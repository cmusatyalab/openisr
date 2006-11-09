#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include "convergent.h"

static int shutdown_dev(struct convergent_dev *dev, int force)
{
	if (force) {
		/* We're being called by a release() method, so we must
		   succeed. */
		mutex_lock(&dev->lock);
	} else {
		if (mutex_lock_interruptible(&dev->lock))
			return -ERESTARTSYS;
		if (dev->need_user != 0) {
			mutex_unlock(&dev->lock);
			return -EBUSY;
		}
	}
	debug("Shutting down chardev");
	dev->flags |= DEV_SHUTDOWN;
	shutdown_usermsg(dev);
	mutex_unlock(&dev->lock);
	convergent_dev_put(dev, 1);
	return 0;
}

static int chr_release(struct inode *ino, struct file *filp)
{
	struct convergent_dev *dev=filp->private_data;
	
	if (dev != NULL)
		shutdown_dev(dev, 1);
	return 0;
}

static ssize_t chr_read(struct file *filp, char __user *buf,
			size_t count, loff_t *offp)
{
	struct convergent_dev *dev=filp->private_data;
	struct isr_message msg;
	DEFINE_WAIT(wait);
	int i;
	int ret;
	int err=0;
	int do_end;
	struct chunkdata *cd;
	
	ndebug("Entering chr_read");
	if (dev == NULL)
		return -ENXIO;
	if (count % sizeof(msg))
		return -EINVAL;
	count /= sizeof(msg);
	
	if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
	for (i=0; i<count; i++) {
		memset(&msg, 0, sizeof(msg));
		
		ndebug("Trying to get chunk");
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
		case ISR_MSGTYPE_GET_META:
			get_usermsg_get_meta(cd, &msg.chunk);
			do_end=0;
			break;
		case ISR_MSGTYPE_UPDATE_META:
			get_usermsg_update_meta(cd, &msg.chunk, &msg.length,
						&msg.compression, msg.key,
						msg.tag);
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
	if (err && i == 0)
		return err;
	ndebug("Leaving chr_read: %d", i * sizeof(msg));
	return i * sizeof(msg);
}

static ssize_t chr_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *offp)
{
	struct convergent_dev *dev=filp->private_data;
	struct isr_message msg;
	int i;
	int err=0;
	
	ndebug("Entering chr_write");
	if (dev == NULL)
		return -ENXIO;
	if (count % sizeof(msg))
		return -EINVAL;
	count /= sizeof(msg);
	
	if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;
	for (i=0; i<count; i++) {
		if (copy_from_user(&msg, buf + i * sizeof(msg), sizeof(msg))) {
			err=-EFAULT;
			goto out;
		}
		
		switch (msg.type) {
		case ISR_MSGTYPE_SET_META:
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
		default:
			err=-EINVAL;
			goto out;
		}
	}
out:
	mutex_unlock(&dev->lock);
	if (err && i == 0)
		return err;
	ndebug("Leaving chr_write: %d", i * sizeof(msg));
	return i * sizeof(msg);
}

/* XXX we may want to eliminate this later */
static long chr_ioctl(struct file *filp, unsigned cmd, unsigned long arg)
{
	struct convergent_dev *dev=filp->private_data;
	struct isr_setup setup;
	int ret;
	
	switch (cmd) {
	case ISR_IOC_REGISTER:
		if (dev != NULL)
			return -EBUSY;
		if (copy_from_user(&setup, (void __user *)arg, sizeof(setup)))
			return -EFAULT;
		if (strnlen(setup.chunk_device, ISR_MAX_DEVICE_LEN)
					== ISR_MAX_DEVICE_LEN)
			return -EINVAL;
		dev=convergent_dev_ctr(setup.chunk_device, setup.chunksize,
					setup.cachesize,
					(sector_t)setup.offset, setup.crypto,
					setup.compress_default,
					setup.compress_required);
		if (IS_ERR(dev))
			return PTR_ERR(dev);
		setup.major=blk_major;
		setup.first_minor=dev->devnum * MINORS_PER_DEVICE;
		setup.minors=MINORS_PER_DEVICE;
		setup.chunks=dev->chunks;
		setup.hash_len=dev->hash_len;
		if (copy_to_user((void __user *)arg, &setup, sizeof(setup)))
			BUG();
		filp->private_data=dev;
		break;
	case ISR_IOC_UNREGISTER:
		if (dev == NULL)
			return -ENXIO;
		
		ret=shutdown_dev(dev, 0);
		if (ret)
			return ret;
		filp->private_data=NULL;
		break;
	default:
		return -ENOTTY;
	}
	return 0;
}

static int chr_old_ioctl(struct inode *ino, struct file *filp, unsigned cmd,
			unsigned long arg)
{
	return chr_ioctl(filp, cmd, arg);
}

static unsigned chr_poll(struct file *filp, poll_table *wait)
{
	struct convergent_dev *dev=filp->private_data;
	int mask=POLLOUT | POLLWRNORM;
	
	if (dev == NULL)
		return POLLERR;
	poll_wait(filp, &dev->waiting_users, wait);
	/* There doesn't seem to be a good way to make this interruptible */
	mutex_lock(&dev->lock);
	if (have_usermsg(dev))
		mask |= POLLIN | POLLRDNORM;
	if (dev->need_user == 0)
		mask |= POLLPRI;
	mutex_unlock(&dev->lock);
	return mask;
}

static struct file_operations convergent_char_ops = {
	.owner =		THIS_MODULE,
	.open =			nonseekable_open,
	.read =			chr_read,
	.write =		chr_write,
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

static struct miscdevice convergent_miscdev = {
	.minor =		MISC_DYNAMIC_MINOR,
	.name =			DEVICE_NAME "ctl",
	.fops =			&convergent_char_ops,
	.list =			LIST_HEAD_INIT(convergent_miscdev.list),
};

int __init chardev_start(void)
{
	return misc_register(&convergent_miscdev);
}

void __exit chardev_shutdown(void)
{
	misc_deregister(&convergent_miscdev);
}
