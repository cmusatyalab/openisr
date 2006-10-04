#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/wait.h>
#include "convergent.h"

static unsigned long devnums[(DEVICES + BITS_PER_LONG - 1)/BITS_PER_LONG];
static struct class class;
int blk_major;

struct convergent_dev *convergent_dev_get(struct convergent_dev *dev)
{
	if (dev == NULL)
		return NULL;
	if (class_device_get(dev->class_dev) == NULL)
		return NULL;
	return dev;
}

/* @unlink is true if we should remove the sysfs entries - that is, if
   the character device is going away or the ctr has errored out.  This
   must be called with @unlink true exactly once per device.  The dev lock
   MUST NOT be held. */
void convergent_dev_put(struct convergent_dev *dev, int unlink)
{
	ndebug("dev_put, refs %d, unlink %d",
			atomic_read(&dev->class_dev->kobj.kref.refcount),
			unlink);
	if (unlink) {
		BUG_ON(in_atomic());
		class_device_unregister(dev->class_dev);
	} else {
		if (in_atomic())
			delayed_put(dev);
		else
			class_device_put(dev->class_dev);
	}
}

void user_get(struct convergent_dev *dev)
{
	BUG_ON(!spin_is_locked(&dev->lock));
	dev->need_user++;
	ndebug("need_user now %u", dev->need_user);
}

void user_put(struct convergent_dev *dev)
{
	BUG_ON(!spin_is_locked(&dev->lock));
	if (!--dev->need_user)
		wake_up_interruptible(&dev->waiting_users);
	ndebug("need_user now %u", dev->need_user);
}

static void class_release_dummy(struct class *class)
{
	/* Dummy function: class is allocated statically because
	   class_create() doesn't allow us to specify class attributes,
	   so we don't need a destructor, but if we don't have one the kernel
	   will sometimes whine to the log */
	return;
}

static ssize_t attr_show_version(struct class *c, char *buf)
{
	if (c != &class)
		return -EINVAL;
	return snprintf(buf, PAGE_SIZE, "%u\n", ISR_INTERFACE_VERSION);
}

static struct class_attribute class_attrs[] = {
	__ATTR(version, S_IRUGO, attr_show_version, NULL),
	__ATTR_NULL
};

static ssize_t attr_show_chunksize(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return snprintf(buf, PAGE_SIZE, "%u\n", dev->chunksize);
}

static ssize_t attr_show_states(struct class_device *class_dev, char *buf)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	return print_states(dev, buf, PAGE_SIZE);
}

static struct class_device_attribute class_dev_attrs[] = {
	__ATTR(chunksize, S_IRUGO, attr_show_chunksize, NULL),
	__ATTR(states, S_IRUGO, attr_show_states, NULL),
	__ATTR_NULL
};

static int convergent_open(struct inode *ino, struct file *filp)
{
	struct convergent_dev *dev;
	
	dev=convergent_dev_get(ino->i_bdev->bd_disk->private_data);
	if (dev == NULL)
		return -ENODEV;
	spin_lock_bh(&dev->lock);
	if (dev->flags & DEV_SHUTDOWN) {
		spin_unlock_bh(&dev->lock);
		convergent_dev_put(dev, 0);
		return -ENODEV;
	} else {
		user_get(dev);
		spin_unlock_bh(&dev->lock);
		return 0;
	}
}

static int convergent_release(struct inode *ino, struct file *filp)
{
	struct convergent_dev *dev=ino->i_bdev->bd_disk->private_data;
	
	spin_lock_bh(&dev->lock);
	user_put(dev);
	spin_unlock_bh(&dev->lock);
	convergent_dev_put(dev, 0);
	return 0;
}

static int alloc_devnum(void)
{
	int num;

	/* This is done unlocked, so we have to be careful */
	for (;;) {
		num=find_first_zero_bit(devnums, DEVICES);
		if (num == DEVICES)
			return -1;
		if (!test_and_set_bit(num, devnums))
			return num;
	}
}

static void free_devnum(int devnum)
{
	clear_bit(devnum, devnums);
}

/* Called by dev->class_dev's release callback */
static void convergent_dev_dtr(struct class_device *class_dev)
{
	struct convergent_dev *dev=class_get_devdata(class_dev);
	
	debug("Dtr called");
	/* XXX racy? */
	if (dev->gendisk) {
		if (dev->gendisk->flags & GENHD_FL_UP) {
			del_gendisk(dev->gendisk);
		} else {
			/* Disk was created but not yet added */
			put_disk(dev->gendisk);
		}
	}
	chunkdata_free_table(dev);
	cleaner_stop(dev);
	transform_free(dev);
	if (dev->queue)
		blk_cleanup_queue(dev->queue);
	if (dev->chunk_bdev)
		close_bdev_excl(dev->chunk_bdev);
	free_devnum(dev->devnum);
	kfree(dev->class_dev);
	kfree(dev);
	module_put(THIS_MODULE);
}

static struct block_device_operations convergent_ops = {
	.owner =	THIS_MODULE,
	.open =		convergent_open,
	.release =	convergent_release,
};

struct convergent_dev *convergent_dev_ctr(char *devnode, unsigned chunksize,
			unsigned cachesize, sector_t offset,
			cipher_t cipher, hash_t hash,
			compress_t default_compress,
			compress_t supported_compress)
{
	struct convergent_dev *dev;
	sector_t capacity;
	int devnum;
	int ret;
	
	debug("Ctr starting");
	
	/* If the userspace process goes away right after the ctr returns, the
	   device will still exist until delayed_add_disk runs but the module
	   could be unloaded.  To get around this, we get an extra reference
	   to the module here and put it in the dtr. */
	if (!try_module_get(THIS_MODULE)) {
		ret=-ENOPKG;
		goto early_fail_module;
	}
	
	devnum=alloc_devnum();
	if (devnum < 0) {
		ret=-EMFILE;
		goto early_fail_devnum;
	}
	
	dev=kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		ret=-ENOMEM;
		goto early_fail_devalloc;
	}
	
	dev->class_dev=class_device_create(&class, NULL, 0, NULL,
					DEVICE_NAME "%c", 'a' + devnum);
	if (IS_ERR(dev->class_dev)) {
		ret=PTR_ERR(dev->class_dev);
		goto early_fail_classdev;
	}
	class_set_devdata(dev->class_dev, dev);
	/* Use class-wide release function */
	dev->class_dev->release=NULL;
	
	/* Now we have refcounting, so all further errors should deallocate
	   through the destructor */
	spin_lock_init(&dev->lock);
	INIT_LIST_HEAD(&dev->freed_ios);
	init_waitqueue_head(&dev->waiting_users);
	cleaner_start(dev);
	dev->devnum=devnum;
	
	if (chunksize < 512 || (chunksize & (chunksize - 1)) != 0) {
		log(KERN_ERR, "chunk size must be >= 512 and a power of 2");
		ret=-EINVAL;
		goto bad;
	}
	if (cachesize < MIN_CONCURRENT_REQS * MAX_CHUNKS_PER_IO) {
		log(KERN_ERR, "cache size may not be smaller than %u",
				MIN_CONCURRENT_REQS * MAX_CHUNKS_PER_IO);
		ret=-EINVAL;
		goto bad;
	}
	if (cachesize > CD_MAX_CHUNKS) {
		log(KERN_ERR, "cache size may not be larger than %u",
					CD_MAX_CHUNKS);
		ret=-EINVAL;
		goto bad;
	}
	dev->chunksize=chunksize;
	dev->cachesize=cachesize;
	dev->offset=offset;
	debug("chunksize %u, cachesize %u, backdev %s, offset " SECTOR_FORMAT,
				chunksize, cachesize, devnode, offset);
	
	debug("Opening %s", devnode);
	dev->chunk_bdev=open_bdev_excl(devnode, 0, dev);
	if (IS_ERR(dev->chunk_bdev)) {
		log(KERN_ERR, "couldn't open %s", devnode);
		ret=PTR_ERR(dev->chunk_bdev);
		dev->chunk_bdev=NULL;
		goto bad;
	}
	/* This is how the BLKGETSIZE64 ioctl is implemented, but
	   bd_inode is labeled "will die" in fs.h */
	capacity=dev->chunk_bdev->bd_inode->i_size / 512;
	if (capacity <= offset) {
		log(KERN_ERR, "specified offset is >= disk capacity");
		ret=-EINVAL;
		goto bad;
	}
	/* Make sure the capacity, after offset adjustment, is a multiple
	   of the chunksize */
	capacity=(capacity - offset) & ~(loff_t)(chunk_sectors(dev) - 1);
	debug("Chunk partition capacity: " SECTOR_FORMAT " MB", capacity >> 11);
	dev->chunks=chunk_of(dev, capacity);
	
	ndebug("Allocating queue");
	dev->queue=blk_init_queue(convergent_request, &dev->lock);
	if (dev->queue == NULL) {
		log(KERN_ERR, "couldn't allocate request queue");
		ret=-ENOMEM;
		goto bad;
	}
	dev->queue->queuedata=dev;
	blk_queue_bounce_limit(dev->queue, BLK_BOUNCE_ANY);
	blk_queue_max_phys_segments(dev->queue, MAX_SEGS_PER_IO);
	/* By default, blk_rq_map_sg() coalesces physically adjacent pages
	   into the same segment, resulting in a segment that spans more
	   than one page but only points directly to the first struct page.
	   This works fine when scatterlist_copy() kmaps low memory but
	   will die if it kmaps high memory.  Instead, we tell blk_rq_map_sg()
	   not to cross page boundaries when coalescing segments. */
	blk_queue_segment_boundary(dev->queue, PAGE_SIZE - 1);
	/* blk_rq_map_sg() enforces a minimum boundary of PAGE_CACHE_SIZE.
	   If that ever becomes larger than PAGE_SIZE, the above call
	   won't do the right thing for us and we'll need to modify
	   scatterlist_copy() to divide each scatterlist entry into its
	   constituent pages. */
	BUILD_BUG_ON(PAGE_SIZE != PAGE_CACHE_SIZE);
	blk_queue_max_sectors(dev->queue,
				chunk_sectors(dev) * (MAX_CHUNKS_PER_IO - 1));
	
	ndebug("Allocating transforms");
	ret=transform_alloc(dev, cipher, hash, default_compress,
				supported_compress);
	if (ret) {
		log(KERN_ERR, "could not configure transforms");
		goto bad;
	}
	
	ndebug("Allocating chunkdata");
	ret=chunkdata_alloc_table(dev);
	if (ret)
		goto bad;
	
	ndebug("Allocating disk");
	dev->gendisk=alloc_disk(MINORS_PER_DEVICE);
	if (dev->gendisk == NULL) {
		log(KERN_ERR, "couldn't allocate gendisk");
		ret=-ENOMEM;
		goto bad_put_chunkdata;
	}
	dev->gendisk->major=blk_major;
	dev->gendisk->first_minor=devnum*MINORS_PER_DEVICE;
	dev->gendisk->minors=MINORS_PER_DEVICE;
	sprintf(dev->gendisk->disk_name, "%s", dev->class_dev->class_id);
	dev->gendisk->fops=&convergent_ops;
	dev->gendisk->queue=dev->queue;
	dev->gendisk->private_data=dev;
	set_capacity(dev->gendisk, capacity);
	ndebug("Adding disk");
	/* add_disk() initiates I/O to read the partition tables, so userspace
	   needs to be able to process key requests while it is running.
	   If we called add_disk() directly here, we would deadlock. */
	ret=delayed_add_disk(dev);
	if (ret) {
		log(KERN_ERR, "couldn't schedule gendisk registration");
		goto bad_put_chunkdata;
	}
	
	return dev;
	
bad_put_chunkdata:
	/* Once chunkdata has been started, there's an extra reference to
	   the dev that needs to be released or it won't be freed. */
	convergent_dev_put(dev, 0);
bad:
	convergent_dev_put(dev, 1);
	return ERR_PTR(ret);
	/* Until we have a refcount, we can't fail through the destructor */
early_fail_classdev:
	kfree(dev);
early_fail_devalloc:
	free_devnum(devnum);
early_fail_devnum:
	module_put(THIS_MODULE);
early_fail_module:
	return ERR_PTR(ret);
}

static int __init convergent_init(void)
{
	int ret;
	
	debug("===================================================");
	log(KERN_INFO, "loading (%s, rev %s)", svn_branch, svn_revision);
	
	ret=request_start();
	if (ret)
		goto bad_request;
	
	class.name=DEVICE_NAME;
	class.owner=THIS_MODULE;
	class.class_release=class_release_dummy;
	class.release=convergent_dev_dtr;
	class.class_attrs=class_attrs;
	class.class_dev_attrs=class_dev_attrs;
	ret=class_register(&class);
	if (ret)
		goto bad_class;
	
	ret=chunkdata_start();
	if (ret) {
		log(KERN_ERR, "couldn't set up chunkdata");
		goto bad_chunkdata;
	}
	
	ret=workqueue_start();
	if (ret) {
		log(KERN_ERR, "couldn't start I/O submission thread");
		goto bad_workqueue;
	}
	
	ret=register_blkdev(0, MODULE_NAME);
	if (ret < 0) {
		log(KERN_ERR, "block driver registration failed");
		goto bad_blkdev;
	}
	blk_major=ret;
	
	ret=chardev_start();
	if (ret) {
		log(KERN_ERR, "couldn't register chardev");
		goto bad_chrdev;
	}
	
	return 0;

bad_chrdev:
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
bad_blkdev:
	workqueue_shutdown();
bad_workqueue:
	chunkdata_shutdown();
bad_chunkdata:
	class_unregister(&class);
bad_class:
	request_shutdown();
bad_request:
	return ret;
}

static void __exit convergent_shutdown(void)
{
	log(KERN_INFO, "unloading");
	
	chardev_shutdown();
	
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
	
	workqueue_shutdown();
	
	chunkdata_shutdown();
	
	class_unregister(&class);
	
	request_shutdown();
}

module_init(convergent_init);
module_exit(convergent_shutdown);

MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION("stacking block device for convergent encryption "
			"and compression");
/* We must use a GPL-compatible license to use the crypto API */
MODULE_LICENSE("GPL");
