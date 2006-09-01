#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/device-mapper.h>
#include <linux/crypto.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
/* We need this for the definition of struct dm_dev. */
#include "dm.h"

#define DEBUG

#define MAX_INPUT_SEGS 32
#define MIN_CONCURRENT_REQS 2

extern char *svn_branch;
extern char *svn_revision;

#define chunk_pages(dev) (((dev)->blocksize+PAGE_SIZE-1)/PAGE_SIZE)
struct convergent_dev {
	struct dm_target *ti;
	struct dm_dev *dmdev;
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
	struct bio *orig_bio;
	struct scatterlist orig_sg[MAX_INPUT_SEGS];
	/* XXX hack that lets us not manage yet another allocation */
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct scatterlist chunk_sg[0];
};

struct workqueue_struct *queue;

#ifdef CONFIG_LBD
#define simple_strtosector simple_strtoull
#else
#define simple_strtosector simple_strtoul
#endif

#define log(prio, msg, args...) printk(prio "dm-convergent: " msg "\n", ## args)
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
static void scatterlist_copy(struct scatterlist *src,
			struct scatterlist *dst, unsigned nbytes)
{
	void *sbuf, *dbuf;
	unsigned sleft, dleft;
	unsigned copied=0;
	unsigned bytesThisRound;
	
	ndebug("Copying scatterlist");
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

static void request_tfm(struct convergent_req *req, int type)
{
	struct convergent_dev *dev=req->dev;
	struct scatterlist *src;
	struct scatterlist *dst;
	unsigned nbytes;
	int decrypt;
	char iv[8]={0};
	
	if (type == READ) {
		src=req->chunk_sg;
		dst=req->orig_sg;
		decrypt=1;
	} else {
		src=req->orig_sg;
		dst=req->chunk_sg;
		decrypt=0;
	}
	nbytes=req->orig_bio->bi_size;
	
	debug("Performing %s on %u bytes", decrypt ? "decrypt" : "encrypt",
				nbytes);
	spin_lock(&dev->tfm_lock);
	/* XXX */
	if (crypto_cipher_setkey(dev->cipher, "asdf", 4))
		BUG();
	/* XXX wrong: doesn't reset the IV each block */
	crypto_cipher_set_iv(dev->cipher, iv, sizeof(iv));
	if (decrypt) {
		if (crypto_cipher_decrypt(dev->cipher, dst, src, nbytes))
			BUG();
	}
	else {
		if (crypto_cipher_encrypt(dev->cipher, dst, src, nbytes))
			BUG();
	}
	spin_unlock(&dev->tfm_lock);
}

static void convergent_callback2(void* data)
{
	struct convergent_req *req=data;
	
	/* newbio not valid */
	if (!req->error && bio_data_dir(req->orig_bio) == READ)
		request_tfm(req, READ);
	free_cache_pages(req);
	debug("Submitting original bio");
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
	BUG_ON(completed > req->orig_bio->bi_size);
	if (completed >= req->orig_bio->bi_size) {
		/* XXX make sure it's not still running? */
		ndebug("Queueing postprocessing callback on request %p", req);
		PREPARE_WORK(&req->work, convergent_callback2, req);
		queue_work(queue, &req->work);
	}
	return 0;
}

/* non-atomic */
static struct bio *bio_create(struct convergent_req *req, unsigned offset)
{
	struct bio *bio;

	/* XXX use bio_set */
	/* XXX could alloc smaller bios if we're looping */
	bio=bio_alloc(GFP_NOIO, chunk_pages(req->dev));
	if (bio == NULL)
		return NULL;

	bio->bi_bdev=req->dev->dmdev->bdev;
	bio->bi_sector=(req->orig_bio->bi_sector - req->dev->ti->begin)
				+ req->dev->offset + offset;
	bio->bi_rw=req->orig_bio->bi_rw;  /* XXX */
	bio->bi_end_io=convergent_bio_callback;
	bio->bi_private=req;
	return bio;
}

/* XXX need to allocate from separate mempool to avoid deadlock if the pool
       empties */
/* XXX need read-modify-write for chunk sizes > 4K */
static void issue_chunk_io(struct convergent_req *req)
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
			bio=bio_create(req, offset/512);
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
		queue_work(queue, &req->work);
	}
}

static void convergent_callback1(void* data)
{
	struct convergent_req *req=data;
	
	/* XXX need to do read-modify-write for large blocks */
	if (alloc_cache_pages(req))
		goto bad;
	orig_bio_to_scatterlist(req);
	if (bio_data_dir(req->orig_bio) == WRITE)
		request_tfm(req, WRITE);
	issue_chunk_io(req);
	return;
bad:
	bio_endio(req->orig_bio, req->orig_bio->bi_size, -ENOMEM);
}

static int convergent_map(struct dm_target *ti, struct bio *bio,
				union map_info *map_context)
{
	struct convergent_dev *dev=ti->private;
	struct convergent_req *req;
	
	BUG_ON(bio_segments(bio) > MAX_INPUT_SEGS);
	
	debug("Map function called, request: %u bytes at sector "SECTOR_FORMAT,
				bio->bi_size, bio->bi_sector);
	req=mempool_alloc(dev->req_pool, GFP_NOIO);
	if (req == NULL)
		return -ENOMEM;
	req->dev=dev;
	req->orig_bio=bio;
	req->error=0;
	atomic_set(&req->completed, 0);
	INIT_LIST_HEAD(&req->freed_reqs);
	INIT_WORK(&req->work, convergent_callback1, req);
	queue_work(queue, &req->work);
	return 0;
}

static void convergent_target_dtr(struct dm_target *ti)
{
	struct convergent_dev *dev=ti->private;
	
	if (dev) {
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
		if (dev->dmdev)
			dm_put_device(ti, dev->dmdev);
	}
	kfree(dev);
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
	if (*endp != 0 || dev->blocksize < 512 ||
				(dev->blocksize & (dev->blocksize - 1)) != 0) {
		ti->error="convergent: block size must be >= 512 " \
					"and a power of 2";
		ret=-EINVAL;
		goto bad;
	}
	dev->offset=simple_strtosector(argv[2], &endp, 10);
	if (*endp != 0) {
		ti->error="convergent: invalid backing device offset";
		ret=-EINVAL;
		goto bad;
	}
	debug("blocksize %u, backdev %s, offset " SECTOR_FORMAT,
				dev->blocksize, argv[1], dev->offset);
	
	/* We don't want to change hardsect_size because its value is
	   not just used by the request queue; it's exported to
	   the filesystem code, etc.  Also, the kernel seems not to
	   be able to handle hardsect_size > PAGE_SIZE.  Setting split_io
	   makes sure we don't get one request spanning multiple blocks,
	   but we still may need to do larger I/Os than what we're given */
	/* XXX we get strange request sizes with direct I/O this way */
	ti->split_io=dev->blocksize/512;
	ti->limits.max_phys_segments=MAX_INPUT_SEGS;
	/* XXX perhaps ti->table->mode? */
	ret=dm_get_device(ti, argv[1], dev->offset, ti->len,
				FMODE_READ|FMODE_WRITE, &dev->dmdev);
	if (ret) {
		ti->error="convergent: could not get backing device";
		goto bad;
	}
	
	dev->cipher=crypto_alloc_tfm("blowfish", CRYPTO_TFM_MODE_CBC);
	dev->hash=crypto_alloc_tfm("sha1", 0);
	/* XXX compression level hardcoded, etc.  may want to do this
	   ourselves. */
	dev->compress=crypto_alloc_tfm("deflate", 0);
	if (dev->cipher == NULL || dev->hash == NULL || dev->compress == NULL) {
		ti->error="convergent: could not allocate crypto transforms";
		goto bad;
	}
	spin_lock_init(&dev->tfm_lock);
	
	dev->page_pool=mempool_create(chunk_pages(dev) * MIN_CONCURRENT_REQS,
				mempool_alloc_page, mempool_free_page, NULL);
	if (dev->page_pool == NULL)
		goto bad;
	dev->req_cache=kmem_cache_create("convergent_requests",
				sizeof(struct convergent_req) +
				chunk_pages(dev) * sizeof(struct scatterlist),
				0, 0, NULL, NULL);
	if (dev->req_cache == NULL)
		goto bad;
	dev->req_pool=mempool_create(MIN_CONCURRENT_REQS, mempool_alloc_slab,
				mempool_free_slab, dev->req_cache);
	if (dev->req_pool == NULL)
		goto bad;
	
	INIT_LIST_HEAD(&dev->freed_reqs);
	
	return 0;
bad:
	convergent_target_dtr(ti);
	return ret;
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
