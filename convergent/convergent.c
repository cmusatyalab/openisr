#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/mempool.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include "convergent.h"

struct bio_set *bio_pool;
static int blk_major;
/* XXX until we get a management interface */
static char *device=NULL;
static unsigned chunksize=0;
static struct convergent_dev *gdev;
module_param(device, charp, S_IRUGO);
module_param(chunksize, uint, S_IRUGO);

static void *mempool_alloc_page(gfp_t gfp_mask, void *unused)
{
	return alloc_page(gfp_mask);
}

static void mempool_free_page(void *page, void *unused)
{
	__free_page(page);
}

static void bio_destructor(struct bio *bio)
{
	bio_free(bio, bio_pool);
}

static void request_cleaner(unsigned long data)
{
	struct convergent_dev *dev=(void*)data;
	struct convergent_req *req;
	struct convergent_req *next;
	
	spin_lock(&dev->freed_lock);
	list_for_each_entry_safe(req, next, &dev->freed_reqs, lh_bucket) {
		list_del(&req->lh_bucket);
		/* Wait for the tasklet to finish if it hasn't already */
		tasklet_disable(&req->callback);
		mempool_free(req, req->dev->req_pool);
	}
	spin_unlock(&dev->freed_lock);
	if (!(dev->flags & DEV_KILLCLEANER))
		mod_timer(&dev->cleaner, jiffies + CLEANER_SWEEP);
}

/* XXX might want to support high memory pages.  on the other hand, those
   might force bounce buffering */
static int alloc_cache_pages(struct convergent_req *req)
{
	int i;
	unsigned npages=chunk_pages(req->dev);
	unsigned residual;
	struct scatterlist *sg=NULL;  /* initialization to avoid warning */
	
	for (i=0; i<npages; i++) {
		sg=&req->chunk_sg[i];
		sg->page=mempool_alloc(req->dev->page_pool, GFP_ATOMIC);
		if (sg->page == NULL)
			goto bad;
		sg->offset=0;
		sg->length=PAGE_SIZE;
	}
	/* Possible partial last page */
	residual=req->dev->chunksize % PAGE_SIZE;
	if (residual)
		sg->length=residual;
	return 0;
	
bad:
	while (--i >= 0)
		mempool_free(req->chunk_sg[i].page, req->dev->page_pool);
	return -ENOMEM;
}

static void free_cache_pages(struct convergent_req *req)
{
	int i;

	for (i=0; i<chunk_pages(req->dev); i++)
		mempool_free(req->chunk_sg[i].page, req->dev->page_pool);
}

static unsigned hash(chunk_t chunk)
{
	return chunk % HASH_BUCKETS;
}

static void orig_bio_to_scatterlist(struct convergent_req *req)
{
	struct bio_vec *bvec;
	int seg;
	int i=0;
	
	bio_for_each_segment(bvec, req->orig_bio, seg) {
		req->orig_sg[i].page=bvec->bv_page;
		req->orig_sg[i].offset=bvec->bv_offset;
		req->orig_sg[i].length=bvec->bv_len;
		i++;
	}
	/* XXX do we need to increment a page refcount? */
}

/* supports high memory pages */
static void scatterlist_copy(struct scatterlist *src, struct scatterlist *dst,
			unsigned soffset, unsigned doffset, unsigned len)
{
	void *sbuf, *dbuf;
	unsigned sleft, dleft;
	unsigned bytesThisRound;
	
	/* Necessary to preserve invariant of comment A */
	if (len == 0)
		return;
	
	/* The choice of kmap slots here is rather arbitrary.  There
	   "shouldn't" be any conflicts, since slots are per-CPU and should
	   only be used atomically. */
	while (soffset >= src->length) {
		soffset -= src->length;
		src++;
	}
	sleft=src->length - soffset;
	sbuf=kmap_atomic(src->page, KM_SOFTIRQ0) + src->offset + soffset;
	
	while (doffset >= dst->length) {
		doffset -= dst->length;
		dst++;
	}
	dleft=dst->length - doffset;
	dbuf=kmap_atomic(dst->page, KM_SOFTIRQ1) + dst->offset + doffset;
	
	/* Comment A: We calculate the address to kunmap_atomic() as buf - 1,
	   since in all cases that we call kunmap_atomic(), we must have
	   copied at least one byte from buf.  If we used buf, we might
	   unmap the wrong page if we copied a full page. */
	while (len) {
		if (sleft == 0) {
			kunmap_atomic(sbuf - 1, KM_SOFTIRQ0);
			src++;
			sbuf=kmap_atomic(src->page, KM_SOFTIRQ0) + src->offset;
			sleft=src->length;
		}
		if (dleft == 0) {
			kunmap_atomic(dbuf - 1, KM_SOFTIRQ1);
			dst++;
			dbuf=kmap_atomic(dst->page, KM_SOFTIRQ1) + dst->offset;
			dleft=dst->length;
		}
		bytesThisRound=min(sleft, dleft);
		memcpy(dbuf, sbuf, bytesThisRound);
		len -= bytesThisRound;
		sleft -= bytesThisRound;
		dleft -= bytesThisRound;
		sbuf += bytesThisRound;
		dbuf += bytesThisRound;
	}
	kunmap_atomic(sbuf - 1, KM_SOFTIRQ0);
	kunmap_atomic(dbuf - 1, KM_SOFTIRQ1);
}

static void chunk_tfm(struct convergent_req *req, int type)
{
	struct convergent_dev *dev=req->dev;
	struct scatterlist *sg=req->chunk_sg;
	unsigned nbytes=dev->chunksize;
	char iv[8]={0};
	
	spin_lock(&dev->tfm_lock);
	/* XXX */
	if (crypto_cipher_setkey(dev->cipher, "asdf", 4))
		BUG();
	crypto_cipher_set_iv(dev->cipher, iv, sizeof(iv));
	if (type == READ) {
		ndebug("Decrypting %u bytes for chunk "SECTOR_FORMAT,
					nbytes, req->chunk);
		if (crypto_cipher_decrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	} else {
		ndebug("Encrypting %u bytes for chunk "SECTOR_FORMAT,
					nbytes, req->chunk);
		if (crypto_cipher_encrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	}
	spin_unlock(&dev->tfm_lock);
}

static int convergent_bio_callback(struct bio *newbio, unsigned nbytes,
			int error);
static struct bio *bio_create(struct convergent_req *req, int dir,
			unsigned offset)
{
	struct bio *bio;

	/* XXX could alloc smaller bios if we're looping */
	bio=bio_alloc_bioset(GFP_ATOMIC, chunk_pages(req->dev), bio_pool);
	if (bio == NULL)
		return NULL;

	bio->bi_bdev=req->dev->chunk_bdev;
	bio->bi_sector=chunk_start(req->dev, req->orig_bio->bi_sector)
				+ req->dev->offset + offset;
	ndebug("Creating bio with sector "SECTOR_FORMAT, bio->bi_sector);
	bio->bi_rw=dir;
	bio_set_prio(bio, bio_prio(req->orig_bio));
	bio->bi_end_io=convergent_bio_callback;
	bio->bi_private=req;
	bio->bi_destructor=bio_destructor;
	return bio;
}

static void issue_chunk_io(struct convergent_req *req, int dir)
{
	struct bio *bio=NULL;
	unsigned nbytes=req->dev->chunksize;
	unsigned offset=0;
	int i=0;
	
	/* XXX test against very small maximum seg count on target, etc. */
	ndebug("Submitting clone bio(s)");
	/* We can't assume that we can fit the entire chunk request in one
	   bio: it depends on the queue restrictions of the underlying
	   device */
	while (offset < nbytes) {
		if (bio == NULL) {
			bio=bio_create(req, dir, offset/512);
			if (bio == NULL)
				goto bad;
		}
		if (bio_add_page(bio, req->chunk_sg[i].page,
					req->chunk_sg[i].length,
					req->chunk_sg[i].offset)) {
			offset += req->chunk_sg[i].length;
			i++;
		} else {
			debug("Submitting multiple bios");
			generic_make_request(bio);
			bio=NULL;
		}
	}
	BUG_ON(bio == NULL);
	generic_make_request(bio);
	return;
	
bad:
	/* XXX make this sane */
	req->error=-ENOMEM;
	if (atomic_add_return(nbytes-offset, &req->completed) == nbytes) {
		ndebug("Queueing postprocessing callback on request %p", req);
		tasklet_schedule(&req->callback);
	}
}

static int request_start(struct convergent_req *req)
{
	struct convergent_dev *dev=req->dev;
	struct convergent_req *parent=NULL;
	struct convergent_req *cur;
	int ret;
	
	/* XXX request chaining can go away once we can simply stop the
	   queue, and should, since we need to be able to stop the queue
	   when we run low on memory */
	spin_lock(&dev->pending_lock);
	/* See if another request for this chunk is in progress */
	list_for_each_entry(cur, &dev->pending_reqs[hash(req->chunk)],
				lh_bucket) {
		if (cur->chunk == req->chunk) {
			parent=cur;
			break;
		}
	}
	if (parent == NULL) {
		ndebug("Starting request for chunk " SECTOR_FORMAT,
					req->chunk);
		list_add_tail(&req->lh_bucket,
				&dev->pending_reqs[hash(req->chunk)]);
		ret=1;
	} else {
		list_add_tail(&req->lh_chained, &parent->lh_chained);
		ret=0;
	}
	spin_unlock(&dev->pending_lock);
	return ret;
}

static void convergent_callback1(struct convergent_req *req);
static void request_end(struct convergent_req *req)
{
	struct convergent_dev *dev=req->dev;
	struct convergent_req *child=NULL;
	int do_callback=0;
	
	ndebug("Ending request for chunk " SECTOR_FORMAT, req->chunk);
	spin_lock(&dev->pending_lock);
	list_del_init(&req->lh_bucket);
	if (!list_empty(&req->lh_chained)) {
		ndebug("Retrieving request for chunk " SECTOR_FORMAT,
					req->chunk);
		child=list_entry(req->lh_chained.next, struct convergent_req,
					lh_chained);
		list_del(&req->lh_chained);
		list_add_tail(&child->lh_bucket,
				&dev->pending_reqs[hash(child->chunk)]);
		do_callback=1;
	}
	spin_unlock(&dev->pending_lock);
	if (do_callback) {
		/* Eww eww eww. */
		convergent_callback1(child);
	}
}

static void convergent_callback2(unsigned long data)
{
	struct convergent_req *req=(void*)data;
	
	if (req->error)
		goto out;
	if (bio_data_dir(req->orig_bio) == READ) {
		chunk_tfm(req, READ);
		scatterlist_copy(req->chunk_sg, req->orig_sg,
			chunk_offset(req->dev, req->orig_bio->bi_sector),
			0, req->orig_bio->bi_size);
	} else if (req->flags & REQ_RMW) {
		req->flags &= ~REQ_RMW;
		atomic_set(&req->completed, 0);
		chunk_tfm(req, READ);
		scatterlist_copy(req->orig_sg, req->chunk_sg, 0,
			chunk_offset(req->dev, req->orig_bio->bi_sector),
			req->orig_bio->bi_size);
		chunk_tfm(req, WRITE);
		issue_chunk_io(req, WRITE);
		/* We're not done yet! */
		return;
	}
out:
	free_cache_pages(req);
	ndebug("Submitting original bio, %u bytes, chunk "SECTOR_FORMAT,
				req->orig_bio->bi_size, req->chunk);
	bio_endio(req->orig_bio, req->orig_bio->bi_size, req->error);
	request_end(req);
	/* Schedule the request to be freed the next time the cleaner runs */
	spin_lock(&req->dev->freed_lock);
	list_add_tail(&req->lh_bucket, &req->dev->freed_reqs);
	spin_unlock(&req->dev->freed_lock);
}

/* May be called from interrupt context */
static int convergent_bio_callback(struct bio *newbio, unsigned nbytes,
			int error)
{
	struct convergent_req *req=newbio->bi_private;
	int completed;
	if (error && !req->error) {
		/* XXX we shouldn't fail the whole I/O */
		req->error=error;
	}
	completed=atomic_add_return(nbytes, &req->completed);
	ndebug("Clone bio completion: %u bytes, total now %u; err %d",
				nbytes, completed, error);
	/* Can't call BUG() in interrupt */
	WARN_ON(completed > req->dev->chunksize);
	if (completed >= req->dev->chunksize) {
		ndebug("Queueing postprocessing callback on request %p", req);
		tasklet_schedule(&req->callback);
	}
	return 0;
}

/* XXX this isn't a callback anymore; it's called directly from softirq
   context */
static void convergent_callback1(struct convergent_req *req)
{
	if (alloc_cache_pages(req))
		goto bad;
	orig_bio_to_scatterlist(req);
	if (bio_data_dir(req->orig_bio) == WRITE) {
		/* XXX make sure bio doesn't cross chunk boundary */
		if (req->orig_bio->bi_size == req->dev->chunksize) {
			/* Whole chunk */
			scatterlist_copy(req->orig_sg, req->chunk_sg,
					0, 0, req->orig_bio->bi_size);
			chunk_tfm(req, WRITE);
			issue_chunk_io(req, WRITE);
		} else {
			/* Partial chunk; need read-modify-write */
			req->flags |= REQ_RMW;
			issue_chunk_io(req, READ);
		}
	} else {
		issue_chunk_io(req, READ);
	}
	return;
bad:
	/* XXX fix */
	BUG();
	bio_endio(req->orig_bio, req->orig_bio->bi_size, -ENOMEM);
}

static int convergent_make_request(request_queue_t *q, struct bio *bio)
{
	struct convergent_dev *dev=q->queuedata;
	struct convergent_req *req;
	
	BUG_ON(bio_segments(bio) > MAX_INPUT_SEGS);
	
	ndebug("make_request called, request: %u bytes at sector "SECTOR_FORMAT,
				bio->bi_size, bio->bi_sector);
	req=mempool_alloc(dev->req_pool, GFP_NOIO);
	if (req == NULL)
		return -ENOMEM;
	req->dev=dev;
	req->orig_bio=bio;
	req->error=0;
	req->flags=0;
	req->chunk=chunk_of(dev, bio->bi_sector);
	atomic_set(&req->completed, 0);
	INIT_LIST_HEAD(&req->lh_bucket);
	INIT_LIST_HEAD(&req->lh_chained);
	tasklet_init(&req->callback, convergent_callback2, (unsigned long)req);
	
	if (request_start(req))
		convergent_callback1(req);
	return 0;
}

/* Return the number of bytes of bvec that can be merged into bio */
static int convergent_mergeable_bvec(request_queue_t *q, struct bio *bio,
			struct bio_vec *bvec)
{
	struct convergent_dev *dev=q->queuedata;
	int allowable;
	
	allowable=dev->chunksize - chunk_offset(dev, bio->bi_sector)
				- bio->bi_size;
	BUG_ON(allowable < 0);
	/* XXX */
	BUG_ON(!bio_segments(bio) && allowable < PAGE_SIZE);
	debug("mergeable called; sec=" SECTOR_FORMAT " size=%u allowable=%d",
				bio->bi_sector, bio->bi_size, allowable);
	return allowable;
}

static void convergent_dev_dtr(struct convergent_dev *dev)
{
	debug("Dtr called");
	/* XXX racy? */
	if (dev->gendisk)
		del_gendisk(dev->gendisk);
	dev->flags |= DEV_KILLCLEANER;
	/* Since the gendisk is gone, the last run of the cleaner should
	   clear out everything */
	del_timer_sync(&dev->cleaner);
	if (dev->req_pool)
		mempool_destroy(dev->req_pool);
	if (dev->req_cache)
		if (kmem_cache_destroy(dev->req_cache))
			log(KERN_ERR, "couldn't destroy request cache");
	if (dev->page_pool)
		mempool_destroy(dev->page_pool);
	if (dev->compress)
		crypto_free_tfm(dev->compress);
	if (dev->hash)
		crypto_free_tfm(dev->hash);
	if (dev->cipher)
		crypto_free_tfm(dev->cipher);
	if (dev->queue)
		blk_cleanup_queue(dev->queue);
	if (dev->chunk_bdev)
		close_bdev_excl(dev->chunk_bdev);
	kfree(dev);
}

static struct block_device_operations convergent_ops = {
	.owner =	THIS_MODULE
};

static struct convergent_dev *convergent_dev_ctr(char *devnode,
			unsigned chunksize, sector_t offset)
{
	struct convergent_dev *dev;
	sector_t capacity;
	int ret;
	int i;
	
	debug("Ctr starting");
	dev=kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL)
		return ERR_PTR(-ENOMEM);
	
	for (i=0; i<HASH_BUCKETS; i++)
		INIT_LIST_HEAD(&dev->pending_reqs[i]);
	spin_lock_init(&dev->pending_lock);
	
	INIT_LIST_HEAD(&dev->freed_reqs);
	spin_lock_init(&dev->freed_lock);
	init_timer(&dev->cleaner);
	dev->cleaner.function=request_cleaner;
	dev->cleaner.data=(unsigned long)dev;
	dev->cleaner.expires=jiffies + CLEANER_SWEEP;
	add_timer(&dev->cleaner);
	
	if (chunksize < 512 || (chunksize & (chunksize - 1)) != 0) {
		log(KERN_ERR, "chunk size must be >= 512 and a power of 2");
		ret=-EINVAL;
		goto bad;
	}
	dev->chunksize=chunksize;
	dev->offset=offset;
	debug("chunksize %u, backdev %s, offset " SECTOR_FORMAT,
				chunksize, devnode, offset);
	
	debug("Opening %s", devnode);
	dev->chunk_bdev=open_bdev_excl(devnode, 0, dev);
	if (IS_ERR(dev->chunk_bdev)) {
		log(KERN_ERR, "couldn't open %s", devnode);
		ret=PTR_ERR(dev->chunk_bdev);
		goto bad;
	}
	ndebug("Allocating queue");
	dev->queue=blk_alloc_queue(GFP_KERNEL);
	if (dev->queue == NULL) {
		log(KERN_ERR, "couldn't allocate request queue");
		ret=-ENOMEM;
		goto bad;
	}
	dev->queue->queuedata=dev;
	blk_queue_make_request(dev->queue, convergent_make_request);
	/* We don't want to change hardsect_size because its value is
	   not just used by the request queue; it's exported to
	   the filesystem code, etc.  Also, the kernel seems not to
	   be able to handle hardsect_size > PAGE_SIZE.  We use a
	   merge function to make sure no bio spans multiple chunks.
	   Requests still might. */
	blk_queue_merge_bvec(dev->queue, convergent_mergeable_bvec);
	/* XXX bounce buffer configuration */
	blk_queue_max_phys_segments(dev->queue, MAX_INPUT_SEGS);
	
	ndebug("Allocating crypto");
	dev->cipher=crypto_alloc_tfm("blowfish", CRYPTO_TFM_MODE_CBC);
	dev->hash=crypto_alloc_tfm("sha1", 0);
	/* XXX compression level hardcoded, etc.  may want to do this
	   ourselves, especially since the compression mutators aren't
	   actually scatterlist-based. */
	dev->compress=crypto_alloc_tfm("deflate", 0);
	if (dev->cipher == NULL || dev->hash == NULL || dev->compress == NULL) {
		log(KERN_ERR, "could not allocate crypto transforms");
		ret=-ENOMEM;  /* XXX? */
		goto bad;
	}
	spin_lock_init(&dev->tfm_lock);
	
	ndebug("Allocating memory pools");
	dev->page_pool=mempool_create(chunk_pages(dev) * MIN_CONCURRENT_REQS,
				mempool_alloc_page, mempool_free_page, NULL);
	if (dev->page_pool == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	/* XXX need different cache name for each device; need kstrdup
	   or somesuch, since cache system doesn't copy the string */
	dev->req_cache=kmem_cache_create(MODULE_NAME "-requests",
				sizeof(struct convergent_req) +
				chunk_pages(dev) * sizeof(struct scatterlist),
				0, 0, NULL, NULL);
	if (dev->req_cache == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	dev->req_pool=mempool_create(MIN_CONCURRENT_REQS, mempool_alloc_slab,
				mempool_free_slab, dev->req_cache);
	if (dev->req_pool == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	
	ndebug("Allocating disk");
	dev->gendisk=alloc_disk(MINORS);
	if (dev->gendisk == NULL) {
		log(KERN_ERR, "couldn't allocate gendisk");
		ret=-ENOMEM;
		goto bad;
	}
	dev->gendisk->major=blk_major;
	dev->gendisk->first_minor=0*MINORS;  /* XXX */
	sprintf(dev->gendisk->disk_name, "openisr");
	dev->gendisk->fops=&convergent_ops;
	dev->gendisk->queue=dev->queue;
	/* Make sure the capacity, after offset adjustment, is a multiple
	   of the chunksize */
	/* This is how the BLKGETSIZE64 ioctl is implemented, but
	   bd_inode is labeled "will die" in fs.h */
	capacity=((dev->chunk_bdev->bd_inode->i_size / 512) - offset)
				& ~(loff_t)(chunk_sectors(dev) - 1);
	debug("Chunk partition capacity: " SECTOR_FORMAT " MB", capacity >> 11);
	set_capacity(dev->gendisk, capacity);
	dev->gendisk->private_data=dev;
	ndebug("Adding disk");
	add_disk(dev->gendisk);
	
	return dev;
bad:
	convergent_dev_dtr(dev);
	return ERR_PTR(ret);
}

static int __init convergent_init(void)
{
	int ret;
	
	debug("===================================================");
	log(KERN_INFO, "loading (%s, rev %s)", svn_branch, svn_revision);
	
	/* The second and third parameters are dependent on the contents
	   of bvec_slabs[] in fs/bio.c, and on the chunk size.  Better too
	   high than too low. */
	/* XXX reduce a bit? */
	/* XXX a global pool means that layering convergent on top of
	   convergent could result in deadlocks.  we may want to prevent
	   this in the registration interface. */
	bio_pool=bioset_create(4 * MIN_CONCURRENT_REQS,
				4 * MIN_CONCURRENT_REQS, 4);
	if (bio_pool == NULL) {
		log(KERN_ERR, "couldn't create bioset");
		ret=-ENOMEM;
		goto bad1;
	}

	ret=register_blkdev(0, MODULE_NAME);
	if (ret < 0) {
		log(KERN_ERR, "block driver registration failed");
		goto bad2;
	}
	blk_major=ret;
	
	if (device == NULL) {
		log(KERN_ERR, "no device node specified");
		ret=-EINVAL;
		goto bad3;
	}
	ndebug("Constructing device");
	gdev=convergent_dev_ctr(device, chunksize, 0);
	if (IS_ERR(gdev)) {
		ret=PTR_ERR(gdev);
		goto bad3;
	}
	
	return 0;

bad3:
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
bad2:
	bioset_free(bio_pool);
bad1:
	return ret;
}

static void __exit convergent_shutdown(void)
{
	log(KERN_INFO, "unloading");
	
	convergent_dev_dtr(gdev);
	
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
	
	bioset_free(bio_pool);
}

module_init(convergent_init);
module_exit(convergent_shutdown);

MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION("stacking block device for convergent encryption "
			"and compression");
/* We must use a GPL-compatible license to use the crypto API */
MODULE_LICENSE("GPL");
