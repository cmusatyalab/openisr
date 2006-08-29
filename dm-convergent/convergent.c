#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/workqueue.h>
/* We need this for the definition of struct dm_dev. */
#include "dm.h"

extern char *svn_branch;
extern char *svn_revision;

struct convergent_dev {
	struct dm_target *ti;
	struct dm_dev *dmdev;
	unsigned blocksize;
	sector_t offset;
};

struct convergent_req {
	struct convergent_dev *dev;
	struct bio *bio;
	struct work_struct work;
};

struct workqueue_struct *queue;

#ifdef CONFIG_LBD
#define simple_strtosector simple_strtoull
#else
#define simple_strtosector simple_strtoul
#endif

#define log(prio, msg, args...) printk(prio "dm-convergent: " msg "\n", ## args)
#define debug(msg, args...) log(KERN_DEBUG, msg, args)

/* argument format: blocksize backdev backdevoffset */
static int convergent_target_ctr(struct dm_target *ti,
				unsigned int argc, char **argv)
{
	struct convergent_dev *dev;
	char *endp;
	int ret;
	
	if (argc != 3) {
		ti->error="convergent: invalid arguments: should be " \
				"<blocksize> <backing-device> " \
				"<backing-device-offset>";
		return -EINVAL;
	}
	
	dev=kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		ti->error="convergent: could not allocate memory";
		return -ENOMEM;
	}
	ti->private=dev;
	dev->ti=ti;
	
	dev->blocksize=simple_strtoul(argv[0], &endp, 10);
	/* XXX hardsect_size maximum is 65536! */
	if (*endp != 0 || dev->blocksize % 512 != 0 ||
				dev->blocksize > (unsigned short)-1) {
		ti->error="convergent: block size must be multiple of 512 and <= 65536";
		ret=-EINVAL;
		goto out;
	}
	ti->limits.hardsect_size=dev->blocksize;
	dev->offset=simple_strtosector(argv[2], &endp, 10);
	if (*endp != 0) {
		ti->error="convergent: invalid backing device offset";
		ret=-EINVAL;
		goto out;
	}
	debug("blocksize %u, backdev %s, offset " SECTOR_FORMAT,
				dev->blocksize, argv[1], dev->offset);
	
	/* XXX perhaps ti->table->mode? */
	ret=dm_get_device(ti, argv[1], dev->offset, ti->len,
				FMODE_READ|FMODE_WRITE, &dev->dmdev);
	if (ret) {
		ti->error="convergent: could not get backing device";
		goto out;
	}
	
	return 0;
out:
	kfree(dev);
	return ret;
}

static void convergent_target_dtr(struct dm_target *ti)
{
	struct convergent_dev *dev=ti->private;
	
	dm_put_device(ti, dev->dmdev);
	kfree(dev);
}

static void convergent_callback(void* data)
{
	struct convergent_req *req=data;
	
	req->bio->bi_bdev=req->dev->dmdev->bdev;
	req->bio->bi_sector=(req->bio->bi_sector - req->dev->ti->begin)
				+ req->dev->offset;
	generic_make_request(req->bio);
	/* XXX memory leak - we don't free the convergent_req */
}

static int convergent_map(struct dm_target *ti, struct bio *bio,
				union map_info *map_context)
{
	struct convergent_dev *dev=ti->private;
	struct convergent_req *req;
	
	req=kmalloc(sizeof(*req), GFP_NOIO);
	if (req == NULL)
		return -ENOMEM;
	req->dev=dev;
	req->bio=bio;
	INIT_WORK(&req->work, convergent_callback, req);
	queue_work(queue, &req->work);
	return 0;
}

static struct target_type convergent_target = {
	.name =		"convergent",
	.module =	THIS_MODULE,
	.version =	{0,0,0}, /* XXX */
	.ctr =		convergent_target_ctr,
	.dtr =		convergent_target_dtr,
	.map =		convergent_map
};

static int __init convergent_init(void)
{
	int ret;
	
	log(KERN_INFO, "loading (%s, rev %s)", svn_branch, svn_revision);
	
	/* XXX do we really want a workqueue? */
	queue=create_singlethread_workqueue("dm-convergent");
	if (queue == NULL) {
		log(KERN_ERR, "couldn't create workqueue");
		ret=-ENOMEM;
		goto fail1;
	}
	
	ret=dm_register_target(&convergent_target);
	if (ret) {
		log(KERN_ERR, "convergent registration failed: %d", ret);
		goto fail2;
	}
	
	return 0;
	
fail2:
	destroy_workqueue(queue);
fail1:
	return ret;
}

static void __exit convergent_shutdown(void)
{
	int ret;
	
	log(KERN_INFO, "unloading");
	
	ret=dm_unregister_target(&convergent_target);
	if (ret)
		log(KERN_ERR, "convergent unregistration failed: %d", ret);
	
	destroy_workqueue(queue);
}

module_init(convergent_init);
module_exit(convergent_shutdown);

MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION("device-mapper target for convergent encryption "
			"and compression");
/* We must use a GPL-compatible license to use the crypto API */
MODULE_LICENSE("GPL");
