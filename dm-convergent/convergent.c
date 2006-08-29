#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
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

/* XXX might want to support high memory pages.  on the other hand, those
   might force bounce buffering */
/* XXX mempool or something for allocated pages */
/* XXX use bio_set */
/* non-atomic? */
static struct bio *bio_create(unsigned bytes)
{
	struct bio *bio;
	struct page *page;
	unsigned npages=(bytes+PAGE_SIZE-1)/PAGE_SIZE;
	int seg;
	struct bio_vec *bvec;
	
	BUG_ON(bytes == 0);
	
	bio=bio_alloc(GFP_NOIO, npages);
	if (bio == NULL)
		return NULL;

	bytes -= (npages-1) * PAGE_SIZE;
	while (npages--) {
		page=alloc_page(GFP_NOIO);
		if (page == NULL)
			goto bad;
		if (!bio_add_page(bio, page, npages ? PAGE_SIZE : bytes, 0))
			goto bad;
	}
	return bio;
	
bad:
	bio_for_each_segment(bvec, bio, seg) {
		page=bvec->bv_page;
		__free_page(page);
	}
	bio_put(bio);
	return NULL;
}

static struct scatterlist *bio_to_scatterlist(struct bio *bio, gfp_t gfp_mask)
{
	struct scatterlist *sg;
	struct bio_vec *bvec;
	int seg;
	int i=0;
	
	/* XXX use cache? */
	sg=kmalloc(bio_segments(bio) * sizeof(*sg), gfp_mask);
	if (sg == NULL)
		return NULL;
	bio_for_each_segment(bvec, bio, seg) {
		sg[i].page=bvec->bv_page;
		sg[i].offset=bvec->bv_offset;
		sg[i].length=bvec->bv_len;
	}
	/* XXX do we need to increment a page refcount? */
	return sg;
}

static void free_scatterlist(struct scatterlist *sg)
{
	kfree(sg);
}

/* supports high memory pages */
/* non-atomic */
static void scatterlist_copy(struct scatterlist *src,
			struct scatterlist *dst, unsigned nbytes)
{
	void *sbuf, *dbuf;
	unsigned sleft, dleft;
	unsigned copied=0;
	unsigned bytesThisRound;
	
	sbuf=kmap(src->page)+src->offset;
	sleft=src->length;
	dbuf=kmap(dst->page)+dst->offset;
	dleft=dst->length;
	while (copied < nbytes) {
		if (sleft == 0) {
			kunmap(src->page);
			src++;
			sbuf=kmap(src->page)+src->offset;
			sleft=src->length;
		}
		if (dleft == 0) {
			kunmap(dst->page);
			dst++;
			dbuf=kmap(dst->page)+dst->offset;
			dleft=dst->length;
		}
		bytesThisRound=min(sleft, dleft);
		memcpy(dbuf, sbuf, bytesThisRound);
		copied += bytesThisRound;
	}
	kunmap(src->page);
	kunmap(dst->page);
}

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
		goto bad;
	}
	ti->limits.hardsect_size=dev->blocksize;
	dev->offset=simple_strtosector(argv[2], &endp, 10);
	if (*endp != 0) {
		ti->error="convergent: invalid backing device offset";
		ret=-EINVAL;
		goto bad;
	}
	debug("blocksize %u, backdev %s, offset " SECTOR_FORMAT,
				dev->blocksize, argv[1], dev->offset);
	
	/* XXX perhaps ti->table->mode? */
	ret=dm_get_device(ti, argv[1], dev->offset, ti->len,
				FMODE_READ|FMODE_WRITE, &dev->dmdev);
	if (ret) {
		ti->error="convergent: could not get backing device";
		goto bad;
	}
	
	return 0;
bad:
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

/* XXX need to allocate from separate mempool to avoid deadlock if the pool
       empties */
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
		goto bad1;
	}
	
	ret=dm_register_target(&convergent_target);
	if (ret) {
		log(KERN_ERR, "convergent registration failed: %d", ret);
		goto bad2;
	}
	
	return 0;
	
bad2:
	destroy_workqueue(queue);
bad1:
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
