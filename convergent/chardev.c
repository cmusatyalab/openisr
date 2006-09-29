#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>
#include "convergent.h"

static void shutdown_dev(struct convergent_dev *dev)
{
	spin_lock_bh(&dev->lock);
	dev->flags |= DEV_SHUTDOWN;
	shutdown_usermsg(dev);
	blk_start_queue(dev->queue);
	spin_unlock_bh(&dev->lock);
	convergent_dev_put(dev, 1);
}

static int chr_open(struct inode *ino, struct file *filp)
{
	nonseekable_open(ino, filp);
	return 0;
}

static int chr_release(struct inode *ino, struct file *filp)
{
	struct convergent_dev *dev=filp->private_data;
	
	if (dev != NULL)
		shutdown_dev(dev);
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
	int do_end;
	struct chunkdata *cd;
	
	ndebug("Entering chr_read");
	if (dev == NULL)
		return -ENXIO;
	if (count % sizeof(msg))
		return -EINVAL;
	count /= sizeof(msg);
	
	for (i=0; i<count; i++) {
		memset(&msg, 0, sizeof(msg));
		
		spin_lock_bh(&dev->lock);
		ndebug("Trying to get chunk");
		cd=next_usermsg(dev, &msg.type);
		while (cd == NULL) {
			spin_unlock_bh(&dev->lock);
			if (i > 0)
				goto out;
			if (filp->f_flags & O_NONBLOCK)
				return -EAGAIN;
			spin_lock_bh(&dev->lock);
			prepare_to_wait(&dev->waiting_users, &wait,
						TASK_INTERRUPTIBLE);
			cd=next_usermsg(dev, &msg.type);
			spin_unlock_bh(&dev->lock);
			if (cd == NULL)
				schedule();
			finish_wait(&dev->waiting_users, &wait);
			if (cd == NULL && signal_pending(current))
				return -ERESTARTSYS;
			spin_lock_bh(&dev->lock);
		}
		switch (msg.type) {
		case ISR_MSGTYPE_GET_META:
			get_usermsg_get_meta(cd, &msg.chunk);
			do_end=0;
			break;
		case ISR_MSGTYPE_UPDATE_META:
			get_usermsg_update_meta(cd, &msg.chunk, &msg.length,
						&msg.compression, msg.key);
			do_end=1;
			break;
		default:
			do_end=1;  /* make compiler happy */
			BUG();
		}
		spin_unlock_bh(&dev->lock);
		ret=copy_to_user(buf, &msg, sizeof(msg));
		spin_lock_bh(&dev->lock);
		if (ret)
			fail_usermsg(cd);
		else if (do_end)
			end_usermsg(cd);
		spin_unlock_bh(&dev->lock);
	}
out:
	ndebug("Leaving chr_read: %d", i * sizeof(msg));
	return i * sizeof(msg);
}

static ssize_t chr_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *offp)
{
	struct convergent_dev *dev=filp->private_data;
	struct isr_message msg;
	int i;
	
	ndebug("Entering chr_write");
	if (dev == NULL)
		return -ENXIO;
	if (count % sizeof(msg))
		return -EINVAL;
	count /= sizeof(msg);
	
	for (i=0; i<count; i++) {
		if (copy_from_user(&msg, buf, sizeof(msg))) {
			if (i > 0)
				break;
			else
				return -EFAULT;
		}
		
		if (msg.type != ISR_MSGTYPE_SET_META) {
			if (i > 0)
				break;
			else
				return -EINVAL;
		}
		/* XXX validate structure */
		ndebug("Setting key");
		
		spin_lock_bh(&dev->lock);
		set_usermsg_set_meta(dev, msg.chunk, msg.length,
					msg.compression, msg.key);
		spin_unlock_bh(&dev->lock);
	}
	ndebug("Leaving chr_write: %d", i * sizeof(msg));
	return i * sizeof(msg);
}

/* XXX we may want to eliminate this later */
static long chr_ioctl(struct file *filp, unsigned cmd, unsigned long arg)
{
	struct convergent_dev *dev=filp->private_data;
	struct isr_setup setup;
	
	switch (cmd) {
	case ISR_VERSION:
		/* XXX use sysfs instead? */
		break;
	case ISR_REGISTER:
		if (dev != NULL)
			return -EBUSY;
		if (copy_from_user(&setup, (void __user *)arg, sizeof(setup)))
			return -EFAULT;
		if (strnlen(setup.chunk_device, MAX_DEVICE_LEN)
					== MAX_DEVICE_LEN)
			return -EINVAL;
		dev=convergent_dev_ctr(setup.chunk_device, setup.chunksize,
					setup.cachesize,
					(sector_t)setup.offset, setup.cipher,
					setup.hash, setup.compress_default);
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
	case ISR_UNREGISTER:
		/* XXX should error out if there are other users, which means
		   read should return if the device is closed while sleeping,
		   which is strange */
		if (dev == NULL)
			return -ENXIO;
		
		shutdown_dev(dev);
		
		break;
	default:
		return -ENOTTY;
	}
	return 0;
}

static unsigned chr_poll(struct file *filp, poll_table *wait)
{
	struct convergent_dev *dev=filp->private_data;
	int mask=POLLOUT | POLLWRNORM;
	
	if (dev == NULL)
		return POLLERR;
	poll_wait(filp, &dev->waiting_users, wait);
	spin_lock_bh(&dev->lock);
	if (have_usermsg(dev))
		mask |= POLLIN | POLLRDNORM;
	spin_unlock_bh(&dev->lock);
	return mask;
}

static struct file_operations convergent_char_ops = {
	.owner =		THIS_MODULE,
	.open =			chr_open,
	.read =			chr_read,
	.write =		chr_write,
	.release =		chr_release,
	.llseek =		no_llseek,
	.poll =			chr_poll,
	.unlocked_ioctl =	chr_ioctl,
	.compat_ioctl =		NULL,  /* XXX */
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
