/* chardev.c - support for the /dev/openisrctl character device */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (R)
 *         system
 * 
 * Copyright (C) 2006-2007 Carnegie Mellon University
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include "defs.h"

/**
 * chr_config_thread - configure task state for the userspace process
 *
 * Set task flags for the current process to help prevent kernel-user deadlock,
 * etc.  This is an interim hacky solution until we have a real one.
 *
 * The only thing this does right now is set the %PF_LESS_THROTTLE flag, which
 * allows userspace to dirty *more* pages than everyone else can before being
 * throttled.  Without this, if userspace tries to dirty a page when the Nexus
 * block device it's servicing is congested and the dirty ratio exceeds 
 * vm_dirty_ratio, the block device deadlocks.
 *
 * Problems with this approach:
 *
 * 1.  We don't get notified when an existing process/thread gets a copy of an
 * existing chardev fd, so we can't configure the thread.  We work around this
 * by providing an ioctl that a new thread can call to be configured.  Note
 * that newly forked/cloned tasks inherit PF_LESS_THROTTLE.
 *
 * 2.  We're not allowed to write to a task's flags unless we're called from
 * that task's context.  So, in the case of multithreaded processes, only the
 * thread that directly calls close() will be properly deconfigured.
 *
 * 3.  If a thread has more than one chardev fd open, and it unregisters or
 * closes one of them, the thread will be deconfigured.  The thread can work
 * around this by using the configure ioctl afterward.
 **/
static int chr_config_thread(void)
{
	if (current->flags & PF_LESS_THROTTLE)
		return -EEXIST;
	debug(DBG_CHARDEV, "Configuring thread %d", current->pid);
	current->flags |= PF_LESS_THROTTLE;
	return 0;
}

/**
 * chr_unconfig_thread - unconfigure task state for the userspace process
 **/
static void chr_unconfig_thread(void)
{
	if (!(current->flags & PF_LESS_THROTTLE))
		return;
	debug(DBG_CHARDEV, "Unconfiguring thread %d", current->pid);
	current->flags &= ~PF_LESS_THROTTLE;
}

/**
 * chr_flush - clean up after an individual thread closes a chardev fd
 **/
static fops_flush_method(chr_flush, filp)
{
	debug(DBG_CHARDEV, "Running chr_flush");
	chr_unconfig_thread();
	return 0;
}

/**
 * chr_release - clean up after the last user closes a chardev fd
 **/
static int chr_release(struct inode *ino, struct file *filp)
{
	struct nexus_dev *dev=filp->private_data;
	
	if (dev == NULL)
		return 0;
	debug(DBG_CHARDEV, "Running chr_release");
	/* We have no way to fail, so we can't lock interruptibly */
	mutex_lock(&dev->lock);
	/* Redundant if unregister ioctl has already been called */
	shutdown_dev(dev, 1);
	mutex_unlock(&dev->lock);
	nexus_dev_put(dev, 1);
	return 0;
}

/**
 * chr_write - handle reads from the chardev
 *
 * @count must be a multiple of sizeof(&struct nexus_message) bytes.
 **/
static ssize_t chr_read(struct file *filp, char __user *buf,
			size_t count, loff_t *offp)
{
	struct nexus_dev *dev=filp->private_data;
	struct nexus_message msg;
	DEFINE_WAIT(wait);
	int i;
	int ret;
	int err=0;
	int do_end;
	struct chunkdata *cd;
	enum nexus_compress compress;
	
	debug(DBG_CHARDEV, "Entering chr_read");
	if (dev == NULL)
		return -ENXIO;
	if (count % sizeof(msg))
		return -EINVAL;
	count /= sizeof(msg);
	
	if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
	if (dev_is_shutdown(dev)) {
		mutex_unlock(&dev->lock);
		return -ENXIO;
	}
	for (i=0; i<count; i++) {
		memset(&msg, 0, sizeof(msg));
		
		debug(DBG_CHARDEV, "chr_read trying to get chunk");
		while ((cd=next_usermsg(dev, &msg.type)) == NULL) {
			if (i > 0)
				goto out;
			if (filp->f_flags & O_NONBLOCK) {
				ret=-EAGAIN;
				goto out;
			}
			prepare_to_wait(&dev->waiting_users, &wait,
						TASK_INTERRUPTIBLE);
			mutex_unlock(&dev->lock);
			schedule();
			finish_wait(&dev->waiting_users, &wait);
			if (signal_pending(current))
				return -ERESTARTSYS;
			if (mutex_lock_interruptible(&dev->lock))
				return -ERESTARTSYS;
		}
		switch (msg.type) {
		case NEXUS_MSGTYPE_GET_META:
			get_usermsg_get_meta(cd, &msg.chunk);
			do_end=0;
			break;
		case NEXUS_MSGTYPE_UPDATE_META:
			get_usermsg_update_meta(cd, &msg.chunk, &msg.length,
						&compress, msg.key, msg.tag);
			msg.compression=compress;  /* type conversion */
			do_end=1;
			break;
		default:
			do_end=1;  /* make compiler happy */
			BUG();
		}
		ret=copy_to_user(buf + i * sizeof(msg), &msg, sizeof(msg));
		if (ret) {
			err=-EFAULT;
			fail_usermsg(cd);
			goto out;
		} else if (do_end) {
			end_usermsg(cd);
		}
	}
out:
	mutex_unlock(&dev->lock);
	memset(msg.key, 0, sizeof(msg.key));
	if (err && i == 0)
		return err;
	debug(DBG_CHARDEV, "Leaving chr_read: %d", i * (int)sizeof(msg));
	return i * sizeof(msg);
}

/**
 * chr_write - handle writes to the chardev
 *
 * All writes must be a multiple of sizeof(&struct nexus_message) bytes.
 **/
static ssize_t chr_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *offp)
{
	struct nexus_dev *dev=filp->private_data;
	struct nexus_message msg;
	int i;
	int err=0;
	
	debug(DBG_CHARDEV, "Entering chr_write");
	if (dev == NULL)
		return -ENXIO;
	if (count % sizeof(msg))
		return -EINVAL;
	count /= sizeof(msg);
	
	if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
	if (dev_is_shutdown(dev)) {
		mutex_unlock(&dev->lock);
		return -ENXIO;
	}
	for (i=0; i<count; i++) {
		if (copy_from_user(&msg, buf + i * sizeof(msg), sizeof(msg))) {
			err=-EFAULT;
			goto out;
		}
		
		switch (msg.type) {
		case NEXUS_MSGTYPE_SET_META:
			if (msg.chunk >= dev->chunks ||
						msg.length == 0 ||
						msg.length > dev->chunksize) {
				err=-EINVAL;
				goto out;
			}
			if (!compression_type_ok(dev, msg.compression)) {
				err=-EINVAL;
				goto out;
			}
			set_usermsg_set_meta(dev, msg.chunk, msg.length,
						msg.compression, msg.key,
						msg.tag);
			break;
		case NEXUS_MSGTYPE_META_HARDERR:
			if (msg.chunk >= dev->chunks) {
				err=-EINVAL;
				goto out;
			}
			set_usermsg_meta_err(dev, msg.chunk);
			break;
		default:
			err=-EINVAL;
			goto out;
		}
	}
out:
	mutex_unlock(&dev->lock);
	memset(msg.key, 0, sizeof(msg.key));
	if (err && i == 0)
		return err;
	debug(DBG_CHARDEV, "Leaving chr_write: %d", i * (int)sizeof(msg));
	return i * sizeof(msg);
}

/**
 * chr_ioctl - ioctl support for chardev
 * 
 * The only operations we perform via ioctl are registration and
 * unregistration, and even those may be moved in-band at some later date.
 * Certainly we should try to avoid adding new ioctls.
 * 
 * NEXUS_IOC_REGISTER: Create a blockdev associated with this chardev fd.
 * When the chardev is first opened, the fd has no blockdev associated with it.
 * Only one blockdev may ever be associated with a chardev fd over its
 * lifetime.
 * 
 * NEXUS_IOC_UNREGISTER: Request to unbind the blockdev from this chardev
 * fd.  The only difference between calling UNREGISTER and just closing the
 * chardev fd is that UNREGISTER will fail with -EBUSY if the blockdev is in
 * use.  (Closing the fd will succeed even if there are existing users, who
 * will then receive I/O errors on writes and uncached reads until they
 * close the block device.)  After UNREGISTER successfully completes, the
 * sysfs entries for the block device will remain present until the fd is
 * closed.  The fd may not be reused to create another block device.
 **/
static long chr_ioctl(struct file *filp, unsigned cmd, unsigned long arg)
{
	struct nexus_dev *dev=filp->private_data;
	struct nexus_setup setup;
	int ret;
	
	switch (cmd) {
	case NEXUS_IOC_REGISTER:
		if (dev != NULL)
			return -EBUSY;
		if (copy_from_user(&setup, (void __user *)arg, sizeof(setup)))
			return -EFAULT;
		if (strnlen(setup.ident, NEXUS_MAX_DEVICE_LEN)
					== NEXUS_MAX_DEVICE_LEN)
			return -EINVAL;
		if (strnlen(setup.chunk_device, NEXUS_MAX_DEVICE_LEN)
					== NEXUS_MAX_DEVICE_LEN)
			return -EINVAL;
		dev=nexus_dev_ctr(setup.ident, setup.chunk_device,
					setup.chunksize, setup.cachesize,
					(sector_t)setup.offset, setup.crypto,
					setup.compress_default,
					setup.compress_required);
		if (IS_ERR(dev))
			return PTR_ERR(dev);
		setup.chunks=dev->chunks;
		setup.major=blk_major;
		setup.num_minors=MINORS_PER_DEVICE;
		setup.index=dev->devnum;
		setup.hash_len=suite_info(dev->suite)->hash_len;
		if (copy_to_user((void __user *)arg, &setup, sizeof(setup)))
			BUG(); /* XXX */
		filp->private_data=dev;
		chr_config_thread();
		return 0;
	case NEXUS_IOC_UNREGISTER:
		if (dev == NULL)
			return -ENXIO;
		if (mutex_lock_interruptible(&dev->lock))
			return -ERESTARTSYS;
		ret=shutdown_dev(dev, 0);
		mutex_unlock(&dev->lock);
		if (!ret)
			chr_unconfig_thread();
		return ret;
	case NEXUS_IOC_CONFIG_THREAD:
		if (dev == NULL || dev_is_shutdown(dev))
			return -ENXIO;
		return chr_config_thread();
	default:
		return -ENOTTY;
	}
}

/**
 * chr_old_ioctl - wrapper for old-style ioctl call
 * 
 * This is called with the BKL held.  Kernels >= 2.6.11 will never call this.
 **/
static int chr_old_ioctl(struct inode *ino, struct file *filp, unsigned cmd,
			unsigned long arg)
{
	return chr_ioctl(filp, cmd, arg);
}

/**
 * chr_poll - select()/poll() support for chardev
 **/
static unsigned chr_poll(struct file *filp, poll_table *wait)
{
	struct nexus_dev *dev=filp->private_data;
	int mask=POLLOUT | POLLWRNORM;
	
	if (dev == NULL)
		return POLLERR;
	poll_wait(filp, &dev->waiting_users, wait);
	/* There doesn't seem to be a good way to make this interruptible */
	mutex_lock(&dev->lock);
	if (!dev_is_shutdown(dev)) {
		if (have_usermsg(dev))
			mask |= POLLIN | POLLRDNORM;
		if (dev->need_user == 0)
			mask |= POLLPRI;
	} else {
		mask=POLLERR;
	}
	mutex_unlock(&dev->lock);
	return mask;
}

static struct file_operations nexus_char_ops = {
	.owner =		THIS_MODULE,
	.open =			nonseekable_open,
	.read =			chr_read,
	.write =		chr_write,
	.flush =		chr_flush,
	.release =		chr_release,
	.llseek =		no_llseek,
	.poll =			chr_poll,
	.ioctl =		chr_old_ioctl,
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl =	chr_ioctl,
#endif
#ifdef HAVE_COMPAT_IOCTL
	.compat_ioctl =		chr_ioctl,
#endif
	/* XXX AIO? */
};

static struct miscdevice nexus_miscdev = {
	.minor =		MISC_DYNAMIC_MINOR,
	.name =			DEVICE_NAME "ctl",
	.fops =			&nexus_char_ops,
	.list =			LIST_HEAD_INIT(nexus_miscdev.list),
};

/**
 * chardev_start - module initialization for character device
 **/
int __init chardev_start(void)
{
	return misc_register(&nexus_miscdev);
}

/**
 * chardev_shutdown - module de-initialization for character device
 **/
void __exit chardev_shutdown(void)
{
	misc_deregister(&nexus_miscdev);
}
