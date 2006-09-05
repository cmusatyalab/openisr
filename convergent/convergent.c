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
#include <linux/workqueue.h>

#define DEBUG

#define MAX_INPUT_SEGS 32
#define MIN_CONCURRENT_REQS 2
#define MINORS 16

extern char *svn_branch;
extern char *svn_revision;

#define chunk_sectors(dev) ((sector_t)(dev)->blocksize/512)
#define chunk_pages(dev) (((dev)->blocksize+PAGE_SIZE-1)/PAGE_SIZE)
#define chunk_start(dev, sect) (sect & ~(chunk_sectors(dev) - 1))
struct convergent_dev {
	struct gendisk *gendisk;
	request_queue_t *queue;
	struct block_device *chunk_bdev;
	
	/* XXX rename to chunksize */
	unsigned blocksize;
	sector_t offset;
	
	struct crypto_tfm *cipher;
	struct crypto_tfm *hash;
	struct crypto_tfm *compress;
	spinlock_t tfm_lock;
	
	mempool_t *page_pool;
	kmem_cache_t *req_cache;
	mempool_t *req_pool;
	
	struct list_head freed_reqs;  /* XXX stupid temporary hack */
};

struct convergent_req {
	struct list_head freed_reqs;
	struct convergent_dev *dev;
	struct work_struct work;
	atomic_t completed;
	int error;
	unsigned isRMW; /* XXX convert to proper flag */
	struct bio *orig_bio;
	struct scatterlist orig_sg[MAX_INPUT_SEGS];
	/* XXX hack that lets us not manage yet another allocation */
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct scatterlist chunk_sg[0];
};

static struct workqueue_struct *workqueue;
static int blk_major;
/* XXX until we get a management interface */
static char *device=NULL;
static unsigned blocksize=0;
static struct convergent_dev *gdev;
module_param(device, charp, S_IRUGO);
module_param(blocksize, uint, S_IRUGO);

#ifdef CONFIG_LBD
#define SECTOR_FORMAT "%llu"
#else
#define SECTOR_FORMAT "%lu"
#endif

#define MODULE_NAME "isr-convergent"
#define log(prio, msg, args...) printk(prio MODULE_NAME ": " msg "\n", ## args)
#ifdef DEBUG
#define debug(msg, args...) log(KERN_DEBUG, msg, ## args)
#else
#define debug(args...) do {} while (0)
#endif
#define ndebug(args...) do {} while (0)

static void *mempool_alloc_page(gfp_t gfp_mask, void *unused)
{
	return alloc_page(gfp_mask);
}

static void mempool_free_page(void *page, void *unused)
{
	__free_page(page);
}

/* XXX might want to support high memory pages.  on the other hand, those
   might force bounce buffering */
/* non-atomic */
static int alloc_cache_pages(struct convergent_req *req)
{
	int i;
	unsigned npages=chunk_pages(req->dev);
	unsigned residual;
	struct scatterlist *sg=NULL;  /* initialization to avoid warning */
	
	for (i=0; i<npages; i++) {
		sg=&req->chunk_sg[i];
		sg->page=mempool_alloc(req->dev->page_pool, GFP_NOIO);
		if (sg->page == NULL)
			goto bad;
		sg->offset=0;
		sg->length=PAGE_SIZE;
	}
	/* Possible partial last page */
	residual=req->dev->blocksize % PAGE_SIZE;
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
/* non-atomic */
static void scatterlist_copy(struct scatterlist *src, struct scatterlist *dst,
			unsigned soffset, unsigned doffset, unsigned len)
{
	void *sbuf, *dbuf;
	unsigned sleft, dleft;
	unsigned bytesThisRound;
	
	while (soffset >= src->length) {
		soffset -= src->length;
		src++;
	}
	sleft=src->length - soffset;
	sbuf=kmap(src->page) + src->offset + soffset;
	
	while (doffset >= dst->length) {
		doffset -= dst->length;
		dst++;
	}
	dleft=dst->length - doffset;
	dbuf=kmap(dst->page) + dst->offset + doffset;
	
	while (len) {
		if (sleft == 0) {
			kunmap(src->page);
			src++;
			sbuf=kmap(src->page) + src->offset;
			sleft=src->length;
		}
		if (dleft == 0) {
			kunmap(dst->page);
			dst++;
			dbuf=kmap(dst->page) + dst->offset;
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
	kunmap(src->page);
	kunmap(dst->page);
}

static void chunk_tfm(struct convergent_req *req, int type)
{
	struct convergent_dev *dev=req->dev;
	struct scatterlist *sg=req->chunk_sg;
	unsigned nbytes=dev->blocksize;
	char iv[8]={0};
	
	spin_lock(&dev->tfm_lock);
	/* XXX */
	if (crypto_cipher_setkey(dev->cipher, "asdf", 4))
		BUG();
	crypto_cipher_set_iv(dev->cipher, iv, sizeof(iv));
	if (type == READ) {
		ndebug("Decrypting %u bytes", nbytes);
		if (crypto_cipher_decrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	} else {
		ndebug("Encrypting %u bytes", nbytes);
		if (crypto_cipher_encrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	}
	spin_unlock(&dev->tfm_lock);
}

/* XXX see if there's a better place to break the prototype cycle */
static void issue_chunk_io(struct convergent_req *req, int dir);
static void convergent_callback2(void* data)
{
	struct convergent_req *req=data;
	
	if (req->error)
		goto out;
	if (bio_data_dir(req->orig_bio) == READ) {
		chunk_tfm(req, READ);
		scatterlist_copy(req->chunk_sg, req->orig_sg, 512 *
			(req->orig_bio->bi_sector % chunk_sectors(req->dev)),
			0, req->orig_bio->bi_size);
	} else if (req->isRMW) {
		req->isRMW=0;
		atomic_set(&req->completed, 0);
		chunk_tfm(req, READ);
		scatterlist_copy(req->orig_sg, req->chunk_sg, 0, 512 *
			(req->orig_bio->bi_sector % chunk_sectors(req->dev)),
			req->orig_bio->bi_size);
		chunk_tfm(req, WRITE);
		issue_chunk_io(req, WRITE);
		/* We're not done yet! */
		return;
	}
out:
	free_cache_pages(req);
	ndebug("Submitting original bio");
	bio_endio(req->orig_bio, req->orig_bio->bi_size, req->error);
	/* XXX temporary hack to free the req before shutting down */
	list_add(&req->freed_reqs, &req->dev->freed_reqs);
}

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
	debug("Clone bio completion: %u bytes, total now %u; err %d",
				nbytes, completed, error);
	/* Can't call BUG() in interrupt */
	WARN_ON(completed > req->dev->blocksize);
	if (completed >= req->dev->blocksize) {
		/* XXX make sure it's not still running? */
		ndebug("Queueing postprocessing callback on request %p", req);
		PREPARE_WORK(&req->work, convergent_callback2, req);
		queue_work(workqueue, &req->work);
	}
	return 0;
}

/* non-atomic */
static struct bio *bio_create(struct convergent_req *req, int dir,
			unsigned offset)
{
	struct bio *bio;

	/* XXX use bio_set */
	/* XXX could alloc smaller bios if we're looping */
	bio=bio_alloc(GFP_NOIO, chunk_pages(req->dev));
	if (bio == NULL)
		return NULL;

	bio->bi_bdev=req->dev->chunk_bdev;
	bio->bi_sector=chunk_start(req->dev, req->orig_bio->bi_sector)
				+ req->dev->offset + offset;
	debug("Creating bio with sector "SECTOR_FORMAT, bio->bi_sector);
	bio->bi_rw=dir;
	bio_set_prio(bio, bio_prio(req->orig_bio));
	bio->bi_end_io=convergent_bio_callback;
	bio->bi_private=req;
	return bio;
}

/* XXX need to allocate from separate mempool to avoid deadlock if the pool
       empties */
/* XXX need read-modify-write for chunk sizes > 4K */
static void issue_chunk_io(struct convergent_req *req, int dir)
{
	struct bio *bio=NULL;
	unsigned nbytes=req->dev->blocksize;
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
		} else {
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
		PREPARE_WORK(&req->work, convergent_callback2, req);
		queue_work(workqueue, &req->work);
	}
}

static void convergent_callback1(void* data)
{
	struct convergent_req *req=data;
	
	/* XXX need to do read-modify-write for large blocks */
	if (alloc_cache_pages(req))
		goto bad;
	orig_bio_to_scatterlist(req);
	if (bio_data_dir(req->orig_bio) == WRITE) {
		/* XXX make sure bio doesn't cross chunk boundary */
		if (req->orig_bio->bi_size == req->dev->blocksize) {
			/* Whole chunk */
			scatterlist_copy(req->orig_sg, req->chunk_sg,
					0, 0, req->orig_bio->bi_size);
			chunk_tfm(req, WRITE);
			issue_chunk_io(req, WRITE);
		} else {
			/* XXX we have WAR problems here */
			/* Partial chunk; need read-modify-write */
			req->isRMW=1;
			issue_chunk_io(req, READ);
		}
	} else {
		issue_chunk_io(req, READ);
	}
	return;
bad:
	bio_endio(req->orig_bio, req->orig_bio->bi_size, -ENOMEM);
}

static int convergent_make_request(request_queue_t *q, struct bio *bio)
{
	struct convergent_dev *dev=q->queuedata;
	struct convergent_req *req;
	
	BUG_ON(bio_segments(bio) > MAX_INPUT_SEGS);
	
	debug("make_request called, request: %u bytes at sector "SECTOR_FORMAT,
				bio->bi_size, bio->bi_sector);
	req=mempool_alloc(dev->req_pool, GFP_NOIO);
	if (req == NULL)
		return -ENOMEM;
	req->dev=dev;
	req->orig_bio=bio;
	req->error=0;
	req->isRMW=0;
	atomic_set(&req->completed, 0);
	INIT_LIST_HEAD(&req->freed_reqs);
	INIT_WORK(&req->work, convergent_callback1, req);
	queue_work(workqueue, &req->work);
	return 0;
}

/* Return the number of bytes of bvec that can be merged into bio */
static int convergent_mergeable_bvec(request_queue_t *q, struct bio *bio,
			struct bio_vec *bvec)
{
	struct convergent_dev *dev=q->queuedata;
	sector_t boundary;
	unsigned allowable;
	
	/* XXX constructs like these should probably be using masks */
	/* XXX chunk_start */
	boundary=(bio->bi_sector + chunk_sectors(dev) - 1)/chunk_sectors(dev);
	allowable=(boundary - bio->bi_sector) * 512;
	/* XXX */
	BUG_ON(!bio_segments(bio) && allowable < PAGE_SIZE);
	debug("mergeable called; sec=" SECTOR_FORMAT " boundary="
				SECTOR_FORMAT " allowable=%u",
				bio->bi_sector, boundary, allowable);
	return allowable;
}

static void convergent_dev_dtr(struct convergent_dev *dev)
{
	debug("Dtr called");
	if (dev->gendisk)
		del_gendisk(dev->gendisk);
	if (dev->req_pool) {
		struct convergent_req *req;
		struct convergent_req *next;
		list_for_each_entry_safe(req, next, &dev->freed_reqs,
					freed_reqs)
			mempool_free(req, dev->req_pool);
		mempool_destroy(dev->req_pool);
	}
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

/* argument format: blocksize backdev backdevoffset */
static struct convergent_dev *convergent_dev_ctr(char *devnode,
			unsigned blocksize, sector_t offset)
{
	struct convergent_dev *dev;
	sector_t capacity;
	int ret;
	
	debug("Ctr starting");
	dev=kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL)
		return ERR_PTR(-ENOMEM);
	
	if (blocksize < 512 || (blocksize & (blocksize - 1)) != 0) {
		log(KERN_ERR, "block size must be >= 512 and a power of 2");
		ret=-EINVAL;
		goto bad;
	}
	dev->blocksize=blocksize;
	dev->offset=offset;
	debug("blocksize %u, backdev %s, offset " SECTOR_FORMAT,
				blocksize, devnode, offset);
	
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
	   merge function to make sure no bio spans multiple blocks.
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
	
	INIT_LIST_HEAD(&dev->freed_reqs);
	
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
	/* This is how the BLKGETSIZE64 ioctl is implemented, but
	   bd_inode is labeled "will die" in fs.h */
	/* Make sure the capacity, after offset adjustment, is a multiple
	   of the blocksize */
	/* XXX use chunk_start */
	capacity=((dev->chunk_bdev->bd_inode->i_size - (512 * offset))
				& ~(loff_t)(blocksize - 1)) / 512;
	debug("Chunk partition capacity: " SECTOR_FORMAT " sectors", capacity);
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
	
	/* XXX do we really want a workqueue? */
	workqueue=create_singlethread_workqueue(MODULE_NAME);
	if (workqueue == NULL) {
		log(KERN_ERR, "couldn't create workqueue");
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
		goto bad2;
	}
	debug("Constructing device");
	gdev=convergent_dev_ctr(device, blocksize, 0);
	if (IS_ERR(gdev)) {
		ret=PTR_ERR(gdev);
		goto bad3;
	}
	
	return 0;

bad3:
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
bad2:
	destroy_workqueue(workqueue);
bad1:
	return ret;
}

static void __exit convergent_shutdown(void)
{
	log(KERN_INFO, "unloading");
	
	convergent_dev_dtr(gdev);
	
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
	
	destroy_workqueue(workqueue);
}

module_init(convergent_init);
module_exit(convergent_shutdown);

MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION("stacking block device for convergent encryption "
			"and compression");
/* We must use a GPL-compatible license to use the crypto API */
MODULE_LICENSE("GPL");
