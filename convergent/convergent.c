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

static struct bio_set *bio_pool;
static unsigned long devnums[(DEVICES + BITS_PER_LONG - 1)/BITS_PER_LONG];
int blk_major;

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

static void lowmem_recover(struct convergent_dev *dev);
static void io_cleaner(unsigned long data)
{
	struct convergent_dev *dev=(void*)data;
	struct convergent_io *io;
	struct convergent_io *next;
	
	spin_lock_bh(&dev->freed_lock);
	list_for_each_entry_safe(io, next, &dev->freed_ios, lh_freed) {
		list_del(&io->lh_freed);
		/* Wait for the tasklet to finish if it hasn't already */
		tasklet_disable(&io->callback);
		mempool_free(io, io->dev->io_pool);
	}
	spin_unlock_bh(&dev->freed_lock);
	/* XXX perhaps it wouldn't hurt to make the timer more frequent */
	/* XXX check for LOWMEM races */
	if (dev->flags & DEV_LOWMEM)
		lowmem_recover(dev);
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

static int end_that_request(struct request *req, int uptodate, int nr_sectors)
{
	int ret;

	BUG_ON(!spin_is_locked(req->q->queue_lock));
	BUG_ON(!list_empty(&req->queuelist));
	ret=end_that_request_first(req, uptodate, nr_sectors);
	if (!ret)
		end_that_request_last(req, uptodate);
	return ret;
}

static void queue_start(struct convergent_dev *dev)
{
	BUG_ON(!spin_is_locked(&dev->queue_lock));
	if (dev->flags & DEV_LOWMEM)
		return;
	blk_start_queue(dev->queue);
}

static void queue_stop(struct convergent_dev *dev)
{
	unsigned long interrupt_state;
	
	BUG_ON(!spin_is_locked(&dev->queue_lock));
	/* Interrupts must be disabled to stop the queue */
	local_irq_save(interrupt_state);
	blk_stop_queue(dev->queue);
	local_irq_restore(interrupt_state);
}

static int convergent_handle_request(struct convergent_dev *dev,
			struct request *io, int reserved);
/* Run low-memory queue */
static void lowmem_recover(struct convergent_dev *dev)
{
	struct request *req;
	struct request *next;
	int still_low=0;
	
	spin_lock_bh(&dev->queue_lock);
	list_for_each_entry_safe(req, next, &dev->pending_reserved,
				queuelist) {
		if (convergent_handle_request(dev, req, 1) == -ENOMEM) {
			/* Every request on the pending_reserved list
			   is mutually exclusive, since they all have their
			   reservations already.  We can keep trying to see
			   if we can get a different request through. */
			still_low=1;
		}
	}
	
	if (!still_low) {
		dev->flags &= ~DEV_LOWMEM;
		queue_start(dev);
	}
	spin_unlock_bh(&dev->queue_lock);
}

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
	if (end_that_request(io->orig_req, io->error ? io->error : 1,
				io->len / 512)) {
		/* There's another chunk in this request. */
		/* XXX minimum mempool size */
		convergent_handle_request(dev, io->orig_req, 1);
	}
	if (unreserve_chunk(dev->chunkdata, io->chunk)) {
		/* Someone was waiting for this chunk. */
		queue_start(dev);
	}
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

static int convergent_handle_request(struct convergent_dev *dev,
			struct request *req, int reserved)
{
	struct convergent_io *io;
	chunk_t first_chunk, last_chunk;
	
	BUG_ON(!spin_is_locked(&dev->queue_lock));
	BUG_ON(req->nr_phys_segments > MAX_INPUT_SEGS);
	first_chunk=chunk_of(dev, req->sector);
	last_chunk=chunk_of(dev, req->sector + req->nr_sectors - 1);
	
	if (dev->flags & DEV_SHUTDOWN) {
		if (reserved)
			unreserve_chunks(dev->chunkdata, first_chunk,
						last_chunk);
		/* We're failing the entire request, so there's no reason
		   to keep it in a list anymore. */
		list_del_init(&req->queuelist);
		end_that_request(req, 0, req->nr_sectors);
		return -ENXIO;
	}
	
	if (!reserved && !reserve_chunks(dev->chunkdata, first_chunk,
				last_chunk)) {
		debug("Waiting for chunk " SECTOR_FORMAT, first_chunk);
		return -EAGAIN;
	}
	
	io=mempool_alloc(dev->io_pool, GFP_ATOMIC);
	if (io == NULL)
		goto bad1;
	
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
	BUG_ON(req->nr_phys_segments > MAX_INPUT_SEGS);
	blk_rq_map_sg(dev->queue, req, io->orig_sg);
	
	if (alloc_cache_pages(io))
		goto bad2;

	debug("handle_request called: %lu sectors over " SECTOR_FORMAT
				" chunks at chunk " SECTOR_FORMAT ", %s",
				req->nr_sectors, io->last_chunk - io->chunk + 1,
				io->chunk, reserved ?
				"continuation" : "initial");
	
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
	/* This request will only be included in a list if there wasn't
	   enough memory to process it.  By now we know this isn't true, so
	   remove the request from the list. */
	list_del_init(&req->queuelist);
	return 0;
	
bad2:
	mempool_free(io, dev->io_pool);
bad1:
	if (!(dev->flags & DEV_LOWMEM)) {
		dev->flags |= DEV_LOWMEM;
		queue_stop(dev);
	}
	if (!list_empty(&req->queuelist))
		list_add_tail(&req->queuelist, &dev->pending_reserved);
	return -ENOMEM;
}

static void convergent_request(request_queue_t *q)
{
	struct convergent_dev *dev=q->queuedata;
	struct request *req;
	
	while ((req = elv_next_request(q)) != NULL) {
		blkdev_dequeue_request(req);
		if (!blk_fs_request(req)) {
			/* XXX */
			debug("Skipping non-fs request");
			end_that_request(req, 0, req->nr_sectors);
			continue;
		}
		switch (convergent_handle_request(dev, req, 0)) {
		case 0:
		case -ENXIO:
			continue;
		case -EAGAIN:
			elv_requeue_request(q, req);
			queue_stop(dev);
			return;
		case -ENOMEM:
			/* Memory is low, and the queue has already been
			   stopped. */
			return;
		default:
			BUG();
		}
	}
}

static int convergent_open(struct inode *ino, struct file *filp)
{
	struct convergent_dev *dev=ino->i_bdev->bd_disk->private_data;
	
	/* XXX racy? */
	if (dev->flags & DEV_SHUTDOWN)
		return -ENODEV;
	atomic_inc(&dev->refcount);
	return 0;
}

static int convergent_release(struct inode *ino, struct file *filp)
{
	struct convergent_dev *dev=ino->i_bdev->bd_disk->private_data;
	
	if (atomic_dec_and_test(&dev->refcount))
		convergent_dev_dtr(dev);
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

void convergent_dev_dtr(struct convergent_dev *dev)
{
	debug("Dtr called");
	/* XXX racy? */
	if (dev->gendisk)
		del_gendisk(dev->gendisk);
	if (dev->chunkdata)
		registration_free(dev->chunkdata);
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
	if (dev->io_cache_name)
		kfree(dev->io_cache_name);
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
	free_devnum(dev->devnum);
	kfree(dev);
}

static struct block_device_operations convergent_ops = {
	.owner =	THIS_MODULE,
	.open =		convergent_open,
	.release =	convergent_release,
};

struct convergent_dev *convergent_dev_ctr(char *devnode,
			unsigned chunksize, sector_t offset)
{
	struct convergent_dev *dev;
	sector_t capacity;
	char buf[NAME_BUFLEN];
	int devnum;
	int ret;
	
	debug("Ctr starting");
	
	devnum=alloc_devnum();
	if (devnum < 0)
		return ERR_PTR(-EMFILE);
	
	dev=kzalloc(sizeof(*dev), GFP_KERNEL);
	if (dev == NULL) {
		free_devnum(devnum);
		return ERR_PTR(-ENOMEM);
	}
	
	INIT_LIST_HEAD(&dev->pending_reserved);
	INIT_LIST_HEAD(&dev->freed_ios);
	spin_lock_init(&dev->freed_lock);
	init_timer(&dev->cleaner);
	dev->cleaner.function=io_cleaner;
	dev->cleaner.data=(unsigned long)dev;
	dev->cleaner.expires=jiffies + CLEANER_SWEEP;
	add_timer(&dev->cleaner);
	dev->devnum=devnum;
	
	if (chunksize < 512 || (chunksize & (chunksize - 1)) != 0) {
		log(KERN_ERR, "chunk size must be >= 512 and a power of 2");
		ret=-EINVAL;
		goto bad;
	}
	dev->chunksize=chunksize;
	dev->offset=offset;
	atomic_set(&dev->refcount, 1);
	debug("chunksize %u, backdev %s, offset " SECTOR_FORMAT,
				chunksize, devnode, offset);
	
	debug("Opening %s", devnode);
	dev->chunk_bdev=open_bdev_excl(devnode, 0, dev);
	if (IS_ERR(dev->chunk_bdev)) {
		log(KERN_ERR, "couldn't open %s", devnode);
		ret=PTR_ERR(dev->chunk_bdev);
		dev->chunk_bdev=NULL;
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
	snprintf(buf, NAME_BUFLEN, MODULE_NAME "-" DEVICE_NAME "%c",
				'a' + devnum);
	dev->io_cache_name=kstrdup(buf, GFP_KERNEL);
	if (dev->io_cache_name == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	dev->io_cache=kmem_cache_create(dev->io_cache_name,
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
	dev->chunkdata=registration_alloc();
	if (dev->chunkdata == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	
	ndebug("Allocating disk");
	dev->gendisk=alloc_disk(MINORS_PER_DEVICE);
	if (dev->gendisk == NULL) {
		log(KERN_ERR, "couldn't allocate gendisk");
		ret=-ENOMEM;
		goto bad;
	}
	dev->gendisk->major=blk_major;
	dev->gendisk->first_minor=devnum*MINORS_PER_DEVICE;
	dev->gendisk->minors=MINORS_PER_DEVICE;
	sprintf(dev->gendisk->disk_name, DEVICE_NAME "%c", 'a' + devnum);
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
	
	ret=submitter_start();
	if (ret) {
		log(KERN_ERR, "couldn't start I/O submission thread");
		goto bad2;
	}
	
	ret=registration_start();
	if (ret) {
		log(KERN_ERR, "couldn't allocate registration cache");
		goto bad3;
	}

	ret=register_blkdev(0, MODULE_NAME);
	if (ret < 0) {
		log(KERN_ERR, "block driver registration failed");
		goto bad4;
	}
	blk_major=ret;
	
	ret=chardev_start();
	if (ret) {
		log(KERN_ERR, "couldn't register chardev");
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
	
	chardev_shutdown();
	
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
