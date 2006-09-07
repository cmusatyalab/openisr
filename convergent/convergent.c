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

static void io_cleaner(unsigned long data)
{
	struct convergent_dev *dev=(void*)data;
	struct convergent_io *io;
	struct convergent_io *next;
	int did_work=0;
	
	spin_lock_bh(&dev->freed_lock);
	list_for_each_entry_safe(io, next, &dev->freed_ios, lh_freed) {
		list_del(&io->lh_freed);
		/* Wait for the tasklet to finish if it hasn't already */
		tasklet_disable(&io->callback);
		mempool_free(io, io->dev->io_pool);
		did_work=1;
	}
	spin_unlock_bh(&dev->freed_lock);
	if (did_work && (dev->flags & DEV_LOWMEM)) {
		spin_lock_bh(&dev->queue_lock);
		dev->flags &= ~DEV_LOWMEM;
		blk_start_queue(dev->queue);
		spin_unlock_bh(&dev->queue_lock);
	}
	if (!(dev->flags & DEV_KILLCLEANER))
		mod_timer(&dev->cleaner, jiffies + CLEANER_SWEEP);
	else
		debug("Timer shutting down");
}

/* XXX might want to support high memory pages.  on the other hand, those
   might force bounce buffering */
static int alloc_cache_pages(struct convergent_io *io)
{
	int i;
	unsigned npages=chunk_pages(io->dev);
	unsigned residual;
	struct scatterlist *sg=NULL;  /* initialization to avoid warning */
	
	for (i=0; i<npages; i++) {
		sg=&io->chunk_sg[i];
		sg->page=mempool_alloc(io->dev->page_pool, GFP_ATOMIC);
		if (sg->page == NULL)
			goto bad;
		sg->offset=0;
		sg->length=PAGE_SIZE;
	}
	/* Possible partial last page */
	residual=io->dev->chunksize % PAGE_SIZE;
	if (residual)
		sg->length=residual;
	return 0;
	
bad:
	while (--i >= 0)
		mempool_free(io->chunk_sg[i].page, io->dev->page_pool);
	return -ENOMEM;
}

static void free_cache_pages(struct convergent_io *io)
{
	int i;

	for (i=0; i<chunk_pages(io->dev); i++)
		mempool_free(io->chunk_sg[i].page, io->dev->page_pool);
}

static void request_to_scatterlist(struct convergent_io *io)
{
	struct bio *bio;
	struct bio_vec *bvec;
	int seg;
	int i=0;
	unsigned nbytes=io->len;
	unsigned bytesThisRound;
	
	rq_for_each_bio(bio, io->orig_req) {
		bio_for_each_segment(bvec, bio, seg) {
			bytesThisRound=min(bvec->bv_len, nbytes);
			io->orig_sg[i].page=bvec->bv_page;
			io->orig_sg[i].offset=bvec->bv_offset;
			io->orig_sg[i].length=bytesThisRound;
			i++;
			nbytes -= bytesThisRound;
			/* Stop when we reach the end of this chunk if this
			   is a multiple-chunk request. */
			if (nbytes == 0)
				return;
		}
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

static void chunk_tfm(struct convergent_io *io, int type)
{
	struct convergent_dev *dev=io->dev;
	struct scatterlist *sg=io->chunk_sg;
	unsigned nbytes=dev->chunksize;
	char iv[8]={0};
	
	spin_lock_bh(&dev->tfm_lock);
	/* XXX */
	if (crypto_cipher_setkey(dev->cipher, "asdf", 4))
		BUG();
	crypto_cipher_set_iv(dev->cipher, iv, sizeof(iv));
	if (type == READ) {
		ndebug("Decrypting %u bytes for chunk "SECTOR_FORMAT,
					nbytes, io->chunk);
		if (crypto_cipher_decrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	} else {
		ndebug("Encrypting %u bytes for chunk "SECTOR_FORMAT,
					nbytes, io->chunk);
		if (crypto_cipher_encrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	}
	spin_unlock_bh(&dev->tfm_lock);
}

static int convergent_endio(struct bio *newbio, unsigned nbytes, int error);
static struct bio *bio_create(struct convergent_io *io, int dir,
			unsigned offset)
{
	struct convergent_dev *dev=io->dev;
	struct bio *bio;

	/* XXX could alloc smaller bios if we're looping */
	bio=bio_alloc_bioset(GFP_ATOMIC, chunk_pages(dev), bio_pool);
	if (bio == NULL)
		return NULL;

	bio->bi_bdev=dev->chunk_bdev;
	bio->bi_sector=chunk_to_sector(dev, io->chunk) + dev->offset + offset;
	ndebug("Creating bio with sector "SECTOR_FORMAT, bio->bi_sector);
	bio->bi_rw=dir;
	bio_set_prio(bio, io->prio);
	bio->bi_end_io=convergent_endio;
	bio->bi_private=io;
	bio->bi_destructor=bio_destructor;
	return bio;
}

static void issue_chunk_io(struct convergent_io *io, int dir)
{
	struct bio *bio=NULL;
	unsigned nbytes=io->dev->chunksize;
	unsigned offset=0;
	int i=0;
	
	/* XXX test against very small maximum seg count on target, etc. */
	ndebug("Submitting clone bio(s)");
	/* We can't assume that we can fit the entire chunk io in one
	   bio: it depends on the queue restrictions of the underlying
	   device */
	while (offset < nbytes) {
		if (bio == NULL) {
			bio=bio_create(io, dir, offset/512);
			if (bio == NULL)
				goto bad;
		}
		if (bio_add_page(bio, io->chunk_sg[i].page,
					io->chunk_sg[i].length,
					io->chunk_sg[i].offset)) {
			offset += io->chunk_sg[i].length;
			i++;
		} else {
			debug("Submitting multiple bios");
			submit(bio);
			bio=NULL;
		}
	}
	BUG_ON(bio == NULL);
	submit(bio);
	return;
	
bad:
	/* XXX make this sane */
	io->error=-ENOMEM;
	if (atomic_add_return(nbytes-offset, &io->completed) == nbytes)
		tasklet_schedule(&io->callback);
}

static int convergent_handle_request(struct convergent_dev *dev,
			struct request *io, int initial);
/* Tasklet - runs in softirq context */
static void convergent_callback(unsigned long data)
{
	struct convergent_io *io=(void*)data;
	struct convergent_dev *dev=io->dev;
	
	if (io->error)
		goto out;
	if (!(io->flags & IO_WRITE)) {
		chunk_tfm(io, READ);
		scatterlist_copy(io->chunk_sg, io->orig_sg, io->offset,
			0, io->len);
	} else if (io->flags & IO_RMW) {
		io->flags &= ~IO_RMW;
		atomic_set(&io->completed, 0);
		chunk_tfm(io, READ);
		scatterlist_copy(io->orig_sg, io->chunk_sg, 0, io->offset,
			io->len);
		chunk_tfm(io, WRITE);
		issue_chunk_io(io, WRITE);
		/* We're not done yet! */
		return;
	}
out:
	free_cache_pages(io);
	ndebug("Submitting original bio, %u bytes, chunk "SECTOR_FORMAT,
				io->len, io->chunk);
	spin_lock_bh(&dev->queue_lock);
	/* XXX error handling */
	if (end_that_request_first(io->orig_req, io->error ? io->error : 1,
				io->len / 512)) {
		/* There's another chunk in this request. */
		/* XXX error handling */
		/* XXX minimum mempool size */
		convergent_handle_request(dev, io->orig_req, 0);
	} else {
		/* XXX add_disk_randomness? */
		end_that_request_last(io->orig_req, io->error ? io->error : 1);
	}
	if (unregister_chunk(dev->pending, io->chunk))
		blk_start_queue(dev->queue);
	spin_unlock_bh(&dev->queue_lock);
	/* Schedule the io to be freed the next time the cleaner runs */
	spin_lock_bh(&dev->freed_lock);
	list_add_tail(&io->lh_freed, &dev->freed_ios);
	spin_unlock_bh(&dev->freed_lock);
}

/* May be called from interrupt context */
static int convergent_endio(struct bio *bio, unsigned nbytes, int error)
{
	struct convergent_io *io=bio->bi_private;
	int completed;
	if (error && !io->error) {
		/* XXX we shouldn't fail the whole I/O */
		io->error=error;
	}
	completed=atomic_add_return(nbytes, &io->completed);
	ndebug("Clone bio completion: %u bytes, total now %u; err %d",
				nbytes, completed, error);
	/* Can't call BUG() in interrupt */
	WARN_ON(completed > io->dev->chunksize);
	if (completed >= io->dev->chunksize)
		tasklet_schedule(&io->callback);
	return 0;
}

/* Must be called with queue lock held */
static int convergent_handle_request(struct convergent_dev *dev,
			struct request *req, int initial)
{
	struct convergent_io *io;
	chunk_t first_chunk, last_chunk;
	int ret;
	
	BUG_ON(req->nr_phys_segments > MAX_INPUT_SEGS);
	first_chunk=chunk_of(dev, req->sector);
	last_chunk=chunk_of(dev, req->sector + req->nr_sectors - 1);
	if (initial && !register_chunks(dev->pending, first_chunk,
				last_chunk)) {
		debug("Waiting for chunk " SECTOR_FORMAT, first_chunk);
		ret=-EAGAIN;
		goto bad1;
	}
	
	io=mempool_alloc(dev->io_pool, GFP_ATOMIC);
	if (io == NULL) {
		ret=-ENOMEM;
		goto bad2;
	}
	
	io->dev=dev;
	io->orig_req=req;
	io->error=0;
	io->flags=0;
	if (rq_data_dir(req))
		io->flags |= IO_WRITE;
	io->chunk=first_chunk;
	io->offset=chunk_offset(dev, req->sector);
	io->len=min((unsigned)req->nr_sectors * 512,
				chunk_space(dev, req->sector));
	io->last_chunk=last_chunk;
	io->prio=req->ioprio;
	atomic_set(&io->completed, 0);
	INIT_LIST_HEAD(&io->lh_freed);
	tasklet_init(&io->callback, convergent_callback, (unsigned long)io);
	
	if (initial)
		debug("handle_request called: %lu sectors over " SECTOR_FORMAT
					" chunks at chunk " SECTOR_FORMAT,
					req->nr_sectors,
					io->last_chunk - io->chunk + 1,
					io->chunk);
	
	if (alloc_cache_pages(io)) {
		ret=-ENOMEM;
		goto bad3;
	}
	request_to_scatterlist(io);
	if (io->flags & IO_WRITE) {
		if (io->len == io->dev->chunksize) {
			/* Whole chunk */
			scatterlist_copy(io->orig_sg, io->chunk_sg,
					0, 0, io->len);
			chunk_tfm(io, WRITE);
			issue_chunk_io(io, WRITE);
		} else {
			/* Partial chunk; need read-modify-write */
			io->flags |= IO_RMW;
			issue_chunk_io(io, READ);
		}
	} else {
		issue_chunk_io(io, READ);
	}
	return 0;
	
bad3:
	mempool_free(io, dev->io_pool);
bad2:
	if (initial)
		unregister_chunks(dev->pending, first_chunk, last_chunk);
bad1:
	return ret;
}

static void convergent_request(request_queue_t *q)
{
	struct convergent_dev *dev=q->queuedata;
	struct request *req;
	unsigned long interrupt_state;
	int ret;
	
	while ((req = elv_next_request(q)) != NULL) {
		if (!blk_fs_request(req)) {
			/* XXX */
			debug("Skipping non-fs request");
			end_request(req, 0);
			continue;
		}
		blkdev_dequeue_request(req);
		ret=convergent_handle_request(dev, req, 1);
		if (ret) {
			if (ret == -ENOMEM)
				dev->flags |= DEV_LOWMEM;
			elv_requeue_request(q, req);
			/* blk_stop_queue() must be called with interrupts
			   disabled */
			local_irq_save(interrupt_state);
			blk_stop_queue(q);
			local_irq_restore(interrupt_state);
			return;
		}
	}
}

static void convergent_dev_dtr(struct convergent_dev *dev)
{
	debug("Dtr called");
	/* XXX racy? */
	if (dev->gendisk)
		del_gendisk(dev->gendisk);
	if (dev->pending)
		registration_free(dev->pending);
	dev->flags |= DEV_KILLCLEANER;
	del_timer_sync(&dev->cleaner);
	/* Run the timer one more time to make sure everything's cleaned out
	   now that the gendisk is gone */
	io_cleaner((unsigned long)dev);
	if (dev->io_pool)
		mempool_destroy(dev->io_pool);
	if (dev->io_cache)
		if (kmem_cache_destroy(dev->io_cache))
			log(KERN_ERR, "couldn't destroy io cache");
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
	
	debug("Ctr starting");
	dev=kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL)
		return ERR_PTR(-ENOMEM);
	
	INIT_LIST_HEAD(&dev->freed_ios);
	spin_lock_init(&dev->freed_lock);
	init_timer(&dev->cleaner);
	dev->cleaner.function=io_cleaner;
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
	spin_lock_init(&dev->queue_lock);
	dev->queue=blk_init_queue(convergent_request, &dev->queue_lock);
	if (dev->queue == NULL) {
		log(KERN_ERR, "couldn't allocate request queue");
		ret=-ENOMEM;
		goto bad;
	}
	dev->queue->queuedata=dev;
	blk_queue_bounce_limit(dev->queue, BLK_BOUNCE_ANY);
	blk_queue_max_phys_segments(dev->queue, MAX_INPUT_SEGS);
	/* XXX max_sectors */
	
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
	dev->io_cache=kmem_cache_create(MODULE_NAME "-io",
				sizeof(struct convergent_io) +
				chunk_pages(dev) * sizeof(struct scatterlist),
				0, 0, NULL, NULL);
	if (dev->io_cache == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	dev->io_pool=mempool_create(MIN_CONCURRENT_REQS, mempool_alloc_slab,
				mempool_free_slab, dev->io_cache);
	if (dev->io_pool == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	dev->pending=registration_alloc();
	if (dev->pending == NULL) {
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
	
	if (submitter_start()) {
		log(KERN_ERR, "couldn't start I/O submission thread");
		ret=-ENOMEM;
		goto bad2;
	}
	
	if (registration_start()) {
		log(KERN_ERR, "couldn't allocate registration cache");
		ret=-ENOMEM;
		goto bad3;
	}

	ret=register_blkdev(0, MODULE_NAME);
	if (ret < 0) {
		log(KERN_ERR, "block driver registration failed");
		goto bad4;
	}
	blk_major=ret;
	
	if (device == NULL) {
		log(KERN_ERR, "no device node specified");
		ret=-EINVAL;
		goto bad5;
	}
	ndebug("Constructing device");
	gdev=convergent_dev_ctr(device, chunksize, 0);
	if (IS_ERR(gdev)) {
		ret=PTR_ERR(gdev);
		goto bad5;
	}
	
	return 0;

bad5:
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
bad4:
	registration_shutdown();
bad3:
	submitter_shutdown();
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
	
	registration_shutdown();
	
	submitter_shutdown();
	
	bioset_free(bio_pool);
}

module_init(convergent_init);
module_exit(convergent_shutdown);

MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION("stacking block device for convergent encryption "
			"and compression");
/* We must use a GPL-compatible license to use the crypto API */
MODULE_LICENSE("GPL");
