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

static void bio_destructor(struct bio *bio)
{
	bio_free(bio, bio_pool);
}

/* We don't want convergent_req to be a very large structure, but we want
   to be able to handle a large number of physical segments in a request.
   Why is this important?  add_page_to_bio() is careful to coalesce bvecs
   which point to adjacent areas in the same page, but submit_bh() is not:
   it actually creates a separate bio for each 512-byte bh, and of course
   bios can't be coalesced with each other because they might have different
   completion functions.  So we can get requests containing a ton of
   512-byte bios, each of which is a separate physical segment.  This is
   a problem because it means that the total request size is limited by
   the size of our statically-allocated scatterlist.
   
   Fortunately, blk_rq_map_sg() coalesces adjacent segments when building
   the scatterlist.  However, we're still required to provide it a scatterlist
   with enough space to keep each physical segment as a separate entry, even
   if that turns out not to be necessary.  To get around this, we keep one
   big scatterlist in the convergent_dev and smaller ones in each io.
   If blk_rq_map_sg() produces a scatterlist small enough to fit in the io,
   great.  Otherwise we split the io using the same mechanism we use for
   multiple-chunk requests.  The result is that we should be able to process
   large requests most of the time, while still handling requests that are
   truly dispersed through memory.
   
   This function fills in the scatterlist in @io and returns the number
   of bytes we can operate on right now. */
static unsigned request_to_scatterlist(struct convergent_io *io)
{
	struct convergent_dev *dev=io->dev;
	int nsegs;
	int i;
	unsigned nbytes=0;
	
	BUG_ON(io->orig_req->nr_phys_segments > MAX_INPUT_SEGS);
	spin_lock(&dev->setup_lock);
	nsegs=blk_rq_map_sg(dev->queue, io->orig_req, dev->setup_sg);
	debug("%d phys segs, %d coalesced segs",
				io->orig_req->nr_phys_segments, nsegs);
	if (nsegs > MAX_SEGS_PER_IO) {
		nsegs=MAX_SEGS_PER_IO;
		for (i=0; i<nsegs; i++)
			nbytes += dev->setup_sg[i].length;
	} else {
		nbytes=io->orig_req->nr_sectors * 512;
	}
	memcpy(io->orig_sg, dev->setup_sg,
				nsegs * sizeof(struct scatterlist));
	spin_unlock(&dev->setup_lock);
	return nbytes;
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

static void chunk_tfm(struct convergent_io_chunk *chunk, int type)
{
	struct convergent_dev *dev=chunk->parent->dev;
	struct scatterlist *sg=chunk->sg;
	unsigned nbytes=dev->chunksize;
	char iv[8]={0};
	
	spin_lock(&dev->tfm_lock);
	/* XXX */
	if (crypto_cipher_setkey(dev->cipher, "asdf", 4))
		BUG();
	crypto_cipher_set_iv(dev->cipher, iv, sizeof(iv));
	if (type == READ) {
		ndebug("Decrypting %u bytes for chunk "SECTOR_FORMAT,
					nbytes, chunk->chunk);
		if (crypto_cipher_decrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	} else {
		ndebug("Encrypting %u bytes for chunk "SECTOR_FORMAT,
					nbytes, chunk->chunk);
		if (crypto_cipher_encrypt(dev->cipher, sg, sg, nbytes))
			BUG();
	}
	spin_unlock(&dev->tfm_lock);
}

static int convergent_endio_func(struct bio *newbio, unsigned nbytes, int error);
static struct bio *bio_create(struct convergent_io_chunk *chunk, int dir,
			unsigned offset)
{
	struct convergent_dev *dev=chunk->parent->dev;
	struct bio *bio;

	/* XXX could alloc smaller bios if we're looping */
	bio=bio_alloc_bioset(GFP_ATOMIC, chunk_pages(dev), bio_pool);
	if (bio == NULL)
		return NULL;

	bio->bi_bdev=dev->chunk_bdev;
	bio->bi_sector=chunk_to_sector(dev, chunk->chunk) + dev->offset + offset;
	ndebug("Creating bio with sector "SECTOR_FORMAT, bio->bi_sector);
	bio->bi_rw=dir;
	bio_set_prio(bio, chunk->parent->prio);
	bio->bi_end_io=convergent_endio_func;
	bio->bi_private=chunk;
	bio->bi_destructor=bio_destructor;
	return bio;
}

static void issue_chunk_io(struct convergent_io_chunk *chunk, int dir)
{
	struct bio *bio=NULL;
	unsigned nbytes=chunk->parent->dev->chunksize;
	unsigned offset=0;
	int i=0;
	
	/* XXX test against very small maximum seg count on target, etc. */
	ndebug("Submitting clone bio(s)");
	/* We can't assume that we can fit the entire chunk io in one
	   bio: it depends on the queue restrictions of the underlying
	   device */
	while (offset < nbytes) {
		if (bio == NULL) {
			bio=bio_create(chunk, dir, offset/512);
			if (bio == NULL)
				goto bad;
		}
		if (bio_add_page(bio, chunk->sg[i].page,
					chunk->sg[i].length,
					chunk->sg[i].offset)) {
			offset += chunk->sg[i].length;
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
	chunk->error=-ENOMEM;
	if (atomic_add_return(nbytes-offset, &chunk->completed) == nbytes)
		tasklet_schedule(&chunk->callback);
}

/* Called without queue lock held */
static int end_that_request(struct request *req, int uptodate, int nr_sectors)
{
	int ret;
	spinlock_t *lock=req->q->queue_lock;

	BUG_ON(!list_empty(&req->queuelist));
	spin_lock_bh(lock);
	ret=end_that_request_first(req, uptodate, nr_sectors);
	if (!ret)
		end_that_request_last(req, uptodate);
	spin_unlock_bh(lock);
	return ret;
}

/* Called without queue lock held */
static void queue_start(struct convergent_dev *dev)
{
	if (dev->flags & DEV_LOWMEM)
		return;
	spin_lock_bh(&dev->queue_lock);
	blk_start_queue(dev->queue);
	spin_unlock_bh(&dev->queue_lock);
}

/* Called without queue lock held */
static void queue_stop(struct convergent_dev *dev)
{
	unsigned long interrupt_state;
	
	/* Interrupts must be disabled to stop the queue */
	spin_lock_irqsave(&dev->queue_lock, interrupt_state);
	blk_stop_queue(dev->queue);
	spin_unlock_irqrestore(&dev->queue_lock, interrupt_state);
}

static void io_cleaner(unsigned long data)
{
	struct convergent_dev *dev=(void*)data;
	struct convergent_io *io;
	struct convergent_io *next;
	int i;
	
	spin_lock_bh(&dev->freed_lock);
	list_for_each_entry_safe(io, next, &dev->freed_ios, lh_freed) {
		list_del(&io->lh_freed);
		/* Wait for the tasklets to finish if they haven't already */
		for (i=0; i<io_chunks(io); i++)
			tasklet_disable(&io->chunks[i].callback);
		mempool_free(io, io->dev->io_pool);
	}
	spin_unlock_bh(&dev->freed_lock);
	/* XXX perhaps it wouldn't hurt to make the timer more frequent */
	/* XXX check for LOWMEM races */
	if (dev->flags & DEV_LOWMEM) {
		dev->flags &= ~DEV_LOWMEM;
		queue_start(dev);
	}
	if (!(dev->flags & DEV_KILLCLEANER))
		mod_timer(&dev->cleaner, jiffies + CLEANER_SWEEP);
	else
		debug("Timer shutting down");
}

static void convergent_teardown_io(struct convergent_io *io)
{
	/* Schedule the io to be freed the next time the cleaner runs */
	spin_lock_bh(&io->dev->freed_lock);
	list_add_tail(&io->lh_freed, &io->dev->freed_ios);
	spin_unlock_bh(&io->dev->freed_lock);
}

static void convergent_complete_chunk(struct convergent_io_chunk *chunk)
{
	int i;
	struct convergent_io *io=chunk->parent;
	int have_more=0;
	
	spin_lock_bh(&io->lock);
	chunk->flags |= CHUNK_COMPLETED;
	ndebug("Completing chunk " SECTOR_FORMAT, chunk->chunk);
	
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if (chunk->flags & CHUNK_DEAD)
			continue;
		if (!(chunk->flags & CHUNK_COMPLETED)) {
			have_more=1;
			break;
		}
		ndebug("end_that_request for chunk " SECTOR_FORMAT,
					chunk->chunk);
		end_that_request(io->orig_req,
					chunk->error ? chunk->error : 1,
					chunk->len / 512);
		chunk->flags |= CHUNK_DEAD;
		/* We only unreserve the chunk after endio, to make absolutely
		   sure the user never sees out-of-order completions of the same
		   chunk. */
		/* XXX locking */
		spin_unlock_bh(&io->lock);
		unreserve_chunk(chunk);
		spin_lock_bh(&io->lock);
	}
	spin_unlock_bh(&io->lock);
	if (!have_more) {
		/* All chunks in this io are completed. */
		convergent_teardown_io(io);
	}
}

/* Tasklet - runs in softirq context */
static void convergent_complete_io(unsigned long data)
{
	struct convergent_io_chunk *chunk=(void*)data;
	struct convergent_io *io=chunk->parent;
	
	if (chunk->error)
		goto out;
	if (!(io->flags & IO_WRITE)) {
		chunk_tfm(chunk, READ);
		scatterlist_copy(chunk->sg, io->orig_sg, chunk->offset,
					chunk->orig_offset, chunk->len);
	} else if (chunk->flags & CHUNK_RMW) {
		chunk->flags &= ~CHUNK_RMW;
		atomic_set(&chunk->completed, 0);
		chunk_tfm(chunk, READ);
		scatterlist_copy(io->orig_sg, chunk->sg,
					chunk->orig_offset, chunk->offset,
					chunk->len);
		chunk_tfm(chunk, WRITE);
		issue_chunk_io(chunk, WRITE);
		/* We're not done yet! */
		return;
	}
out:
	convergent_complete_chunk(chunk);
}

/* May be called from hardirq context */
static int convergent_endio_func(struct bio *bio, unsigned nbytes, int error)
{
	struct convergent_io_chunk *chunk=bio->bi_private;
	int completed;
	if (error && !chunk->error)
		chunk->error=error;
	completed=atomic_add_return(nbytes, &chunk->completed);
	ndebug("Clone bio completion: %u bytes, total now %u; err %d",
				nbytes, completed, error);
	/* Can't call BUG() in interrupt */
	WARN_ON(completed > chunk->parent->dev->chunksize);
	if (completed >= chunk->parent->dev->chunksize)
		tasklet_schedule(&chunk->callback);
	return 0;
}

/* Process one chunk from an io.  Called without queue lock held. */
static void convergent_process_chunk(struct convergent_io_chunk *chunk)
{
	struct convergent_io *io=chunk->parent;
	struct convergent_dev *dev=io->dev;
	
	/* The device might have been shut down since the io was first
	   set up */
	if (dev->flags & DEV_SHUTDOWN) {
		chunk->error=-EIO;
		convergent_complete_chunk(chunk);
		return;
	}
	
	debug("process_chunk called: chunk " SECTOR_FORMAT ", offset %u, "
				"length %u", chunk->chunk, chunk->offset,
				chunk->len);
	
	chunk->sg=get_scatterlist(chunk);
	if (io->flags & IO_WRITE) {
		if (chunk->len == dev->chunksize) {
			/* Whole chunk */
			scatterlist_copy(io->orig_sg, chunk->sg,
					chunk->orig_offset, chunk->offset,
					chunk->len);
			chunk_tfm(chunk, WRITE);
			issue_chunk_io(chunk, WRITE);
		} else {
			/* Partial chunk; need read-modify-write */
			chunk->flags |= CHUNK_RMW;
			issue_chunk_io(chunk, READ);
		}
	} else {
		issue_chunk_io(chunk, READ);
	}
}

void convergent_process_io(struct convergent_io *io)
{
	int i;
	
	for (i=0; i<io_chunks(io); i++)
		convergent_process_chunk(&io->chunks[i]);
}

/* Do initial setup, memory allocations, anything that can fail.  Called
   without queue lock held. */
static int convergent_setup_io(struct convergent_dev *dev, struct request *req)
{
	struct convergent_io *io;
	struct convergent_io_chunk *chunk;
	unsigned remaining;
	unsigned bytes;
	unsigned sg_len;
	int i;
	
	BUG_ON(req->nr_phys_segments > MAX_INPUT_SEGS);
	
	if (dev->flags & DEV_SHUTDOWN) {
		end_that_request(req, 0, req->nr_sectors);
		return -ENXIO;
	}
	
	io=mempool_alloc(dev->io_pool, GFP_ATOMIC);
	if (io == NULL) {
		/* XXX restart queue */
		return -ENOMEM;
	}
	
	io->dev=dev;
	io->orig_req=req;
	io->flags=0;
	io->first_chunk=chunk_of(dev, req->sector);
	io->last_chunk=chunk_of(dev, req->sector + req->nr_sectors - 1);
	io->prio=req->ioprio;
	if (rq_data_dir(req))
		io->flags |= IO_WRITE;
	INIT_LIST_HEAD(&io->lh_freed);
	spin_lock_init(&io->lock);
	
	bytes=0;
	remaining=(unsigned)req->nr_sectors * 512;
	sg_len=request_to_scatterlist(io);
	BUG_ON((sg_len & ~(512 - 1)) != sg_len);
	/* XXX */
	BUG_ON(sg_len != remaining);
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		chunk->parent=io;
		chunk->chunk=io->first_chunk + i;
		chunk->orig_offset=bytes;
		if (i == 0)
			chunk->offset=chunk_offset(dev, req->sector);
		else
			chunk->offset=0;
		chunk->len=min(remaining, chunk_remaining(dev, chunk->offset));
		chunk->flags=0;
		chunk->error=0;
		INIT_LIST_HEAD(&chunk->lh_pending);
		atomic_set(&chunk->completed, 0);
		tasklet_init(&chunk->callback, convergent_complete_io,
					(unsigned long)chunk);
		remaining -= chunk->len;
		bytes += chunk->len;
	}
	
	debug("setup_io called: %lu sectors over " SECTOR_FORMAT
				" chunks at chunk " SECTOR_FORMAT,
				req->nr_sectors,
				io->last_chunk - io->first_chunk + 1,
				io->first_chunk);
	
	if (reserve_chunks(io)) {
		/* Couldn't allocate chunkdata for this io, so we have to
		   tear the whole thing down */
		mempool_free(io, dev->io_pool);
		return -ENOMEM;
	}
	return 0;
}

static void convergent_request(request_queue_t *q)
{
	struct convergent_dev *dev=q->queuedata;
	struct request *req;
	
	while ((req = elv_next_request(q)) != NULL) {
		blkdev_dequeue_request(req);
		spin_unlock(&dev->queue_lock);
		if (!blk_fs_request(req)) {
			/* XXX */
			debug("Skipping non-fs request");
			end_that_request(req, 0, req->nr_sectors);
			goto next;
		}
		switch (convergent_setup_io(dev, req)) {
		case 0:
		case -ENXIO:
			break;
		case -ENOMEM:
			dev->flags |= DEV_LOWMEM;
			queue_stop(dev);
			spin_lock(&dev->queue_lock);
			elv_requeue_request(q, req);
			return;
		default:
			BUG();
		}
next:
		spin_lock(&dev->queue_lock);
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
		chunkdata_free_table(dev);
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

struct convergent_dev *convergent_dev_ctr(char *devnode, unsigned chunksize,
			unsigned cachesize, sector_t offset)
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
	
	spin_lock_init(&dev->setup_lock);
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
	/* XXX we need a minimum too */
	if (cachesize > CD_MAX_CHUNKS) {
		log(KERN_ERR, "cache size may not be larger than %u",
					CD_MAX_CHUNKS);
		ret=-EINVAL;
		goto bad;
	}
	dev->chunksize=chunksize;
	dev->cachesize=cachesize;
	dev->offset=offset;
	atomic_set(&dev->refcount, 1);
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
	blk_queue_max_sectors(dev->queue,
				chunk_sectors(dev) * (MAX_CHUNKS_PER_IO - 1));
	
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
	snprintf(buf, NAME_BUFLEN, MODULE_NAME "-" DEVICE_NAME "%c",
				'a' + devnum);
	dev->io_cache_name=kstrdup(buf, GFP_KERNEL);
	if (dev->io_cache_name == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	dev->io_cache=kmem_cache_create(dev->io_cache_name,
				sizeof(struct convergent_io), 0, 0, NULL, NULL);
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
	ret=chunkdata_alloc_table(dev);
	if (ret)
		goto bad;
	
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
	
	ret=register_blkdev(0, MODULE_NAME);
	if (ret < 0) {
		log(KERN_ERR, "block driver registration failed");
		goto bad3;
	}
	blk_major=ret;
	
	ret=chardev_start();
	if (ret) {
		log(KERN_ERR, "couldn't register chardev");
		goto bad4;
	}
	
	return 0;

bad4:
	if (unregister_blkdev(blk_major, MODULE_NAME))
		log(KERN_ERR, "block driver unregistration failed");
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
