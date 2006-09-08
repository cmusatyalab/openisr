#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include "convergent.h"
#include "convergent-user.h"

static dev_t char_major;
static struct cdev chardev;

static void shutdown_dev(struct convergent_dev *dev)
{
	dev->flags |= DEV_SHUTDOWN;
	if (atomic_dec_and_test(&dev->refcount)) {
		convergent_dev_dtr(dev);
	} else {
		spin_lock_bh(&dev->queue_lock);
		blk_start_queue(dev->queue);
		spin_unlock_bh(&dev->queue_lock);
	}
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
	return 0;  /* XXX */
}

static ssize_t chr_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *offp)
{
	return 0;  /* XXX */
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
					(sector_t)setup.offset);
		if (IS_ERR(dev))
			return PTR_ERR(dev);
		setup.major=blk_major;
		setup.first_minor=dev->devnum * MINORS_PER_DEVICE;
		setup.minors=MINORS_PER_DEVICE;
		if (copy_to_user((void __user *)arg, &setup, sizeof(setup)))
			BUG();
		filp->private_data=dev;
		break;
	case ISR_UNREGISTER:
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
	return -EINVAL;  /* XXX */
}

static int chr_check_flags(int flags)
{
	return -EINVAL;  /* XXX */
}

static struct file_operations convergent_char_ops = {
	.owner =		THIS_MODULE,
	.open =			chr_open,
	.read =			chr_read,
	.write =		chr_write,
	.release =		chr_release,
	.llseek =		no_llseek,
	.poll =			chr_poll,
	.check_flags =		chr_check_flags,
	.unlocked_ioctl =	chr_ioctl,
	.compat_ioctl =		NULL,  /* XXX */
	/* XXX AIO? */
};

int chardev_start(void)
{
	int ret;
	
	ret=alloc_chrdev_region(&char_major, 0, 1, MODULE_NAME);
	if (ret)
		return ret;
	
	cdev_init(&chardev, &convergent_char_ops);
	chardev.owner=THIS_MODULE;
	ret=cdev_add(&chardev, char_major, 1);
	if (ret) {
		unregister_chrdev_region(char_major, 1);
		return ret;
	}
	return 0;
}

void chardev_shutdown(void)
{
	cdev_del(&chardev);
	unregister_chrdev_region(char_major, 1);
}
