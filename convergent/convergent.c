#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/mempool.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include "convergent.h"

static unsigned long devnums[(DEVICES + BITS_PER_LONG - 1)/BITS_PER_LONG];
static kmem_cache_t *io_cache;
static mempool_t *io_pool;
int blk_major;

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
		WARN_ON(sleft > PAGE_SIZE || dleft > PAGE_SIZE);
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
	BUG_ON(!spin_is_locked(&dev->lock));
	if (dev->flags & DEV_LOWMEM)
		return;
	blk_start_queue(dev->queue);
}

static void queue_stop(struct convergent_dev *dev)
{
	unsigned long interrupt_state;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	/* Interrupts must be disabled to stop the queue */
	local_irq_save(interrupt_state);
	blk_stop_queue(dev->queue);
	local_irq_restore(interrupt_state);
}

static void io_cleaner(unsigned long data)
{
	struct convergent_dev *dev=(void*)data;
	struct convergent_io *io;
	struct convergent_io *next;
	int i;
	
	spin_lock_bh(&dev->lock);
	list_for_each_entry_safe(io, next, &dev->freed_ios, lh_freed) {
		list_del(&io->lh_freed);
		/* Wait for the tasklets to finish if they haven't already */
		for (i=0; i<io_chunks(io); i++)
			tasklet_disable(&io->chunks[i].callback);
		mempool_free(io, io_pool);
	}
	/* XXX perhaps it wouldn't hurt to make the timer more frequent */
	if (dev->flags & DEV_LOWMEM) {
		dev->flags &= ~DEV_LOWMEM;
		queue_start(dev);
	}
	spin_unlock_bh(&dev->lock);
	if (!(dev->flags & DEV_KILLCLEANER))
		mod_timer(&dev->cleaner, jiffies + CLEANER_SWEEP);
	else
		debug("Timer shutting down");
}

static void convergent_complete_chunk(struct convergent_io_chunk *chunk)
{
	int i;
	struct convergent_io *io=chunk->parent;
	
	BUG_ON(!spin_is_locked(&io->dev->lock));
	
	chunk->flags |= CHUNK_COMPLETED;
	ndebug("Completing chunk " SECTOR_FORMAT, chunk->chunk);
	
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if (chunk->flags & CHUNK_DEAD)
			continue;
		if (!(chunk->flags & CHUNK_COMPLETED))
			return;
		ndebug("end_that_request for chunk " SECTOR_FORMAT,
					chunk->chunk);
		end_that_request(io->orig_req,
					chunk->error ? chunk->error : 1,
					chunk->len / 512);
		chunk->flags |= CHUNK_DEAD;
		/* We only unreserve the chunk after endio, to make absolutely
		   sure the user never sees out-of-order completions of the same
		   chunk. */
		unreserve_chunk(chunk);
	}
	/* All chunks in this io are completed.  Schedule the io to
	   be freed the next time the cleaner runs */
	list_add_tail(&io->lh_freed, &io->dev->freed_ios);
}

/* Process one chunk from an io.  Tasklet. */
static void convergent_process_chunk(unsigned long data)
{
	struct convergent_io_chunk *chunk=(void*)data;
	struct convergent_io *io=chunk->parent;
	struct convergent_dev *dev=io->dev;
	struct scatterlist *chunk_sg;
	
	spin_lock_bh(&dev->lock);
	
	/* The device might have been shut down since the io was first
	   set up */
	if (dev->flags & DEV_SHUTDOWN) {
		chunk->error=-EIO;
		convergent_complete_chunk(chunk);
		spin_unlock_bh(&dev->lock);
		return;
	}
	
	debug("process_chunk called: chunk " SECTOR_FORMAT ", offset %u, "
				"length %u", chunk->chunk, chunk->offset,
				chunk->len);
	
	/* XXX error handling */
	chunk_sg=get_scatterlist(chunk);
	if (io->flags & IO_WRITE) {
		scatterlist_copy(io->orig_sg, chunk_sg, chunk->orig_offset,
					chunk->offset, chunk->len);
	} else {
		scatterlist_copy(chunk_sg, io->orig_sg, chunk->offset,
					chunk->orig_offset, chunk->len);
	}
	convergent_complete_chunk(chunk);
	spin_unlock_bh(&dev->lock);
}

/* Do initial setup, memory allocations, anything that can fail. */
static int convergent_setup_io(struct convergent_dev *dev, struct request *req)
{
	struct convergent_io *io;
	struct convergent_io_chunk *chunk;
	unsigned remaining;
	unsigned bytes;
	unsigned nsegs;
	int i;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	BUG_ON(req->nr_phys_segments > MAX_SEGS_PER_IO);
	
	if (dev->flags & DEV_SHUTDOWN) {
		end_that_request(req, 0, req->nr_sectors);
		return -ENXIO;
	}
	
	io=mempool_alloc(io_pool, GFP_ATOMIC);
	if (io == NULL)
		return -ENOMEM;
	
	io->dev=dev;
	io->orig_req=req;
	io->flags=0;
	io->first_chunk=chunk_of(dev, req->sector);
	io->last_chunk=chunk_of(dev, req->sector + req->nr_sectors - 1);
	io->prio=req->ioprio;
	if (rq_data_dir(req))
		io->flags |= IO_WRITE;
	INIT_LIST_HEAD(&io->lh_freed);
	nsegs=blk_rq_map_sg(dev->queue, req, io->orig_sg);
	debug("%d phys segs, %d coalesced segs", req->nr_phys_segments, nsegs);
	
	bytes=0;
	remaining=(unsigned)req->nr_sectors * 512;
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
		if (!((io->flags & IO_WRITE) && chunk->len == dev->chunksize))
			chunk->flags |= CHUNK_READ;
		chunk->error=0;
		INIT_LIST_HEAD(&chunk->lh_pending);
		tasklet_init(&chunk->callback, convergent_process_chunk,
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
		mempool_free(io, io_pool);
		return -ENOMEM;
	}
	return 0;
}

/* Called with queue lock held */
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
		switch (convergent_setup_io(dev, req)) {
		case 0:
		case -ENXIO:
			break;
		case -ENOMEM:
			dev->flags |= DEV_LOWMEM;
			queue_stop(dev);
			elv_requeue_request(q, req);
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
	/* XXX doesn't make sure the add_disk job has run */
	if (dev->gendisk)
		del_gendisk(dev->gendisk);
	chunkdata_free_table(dev);
	dev->flags |= DEV_KILLCLEANER;
	del_timer_sync(&dev->cleaner);
	/* Run the timer one more time to make sure everything's cleaned out
	   now that the gendisk is gone */
	io_cleaner((unsigned long)dev);
	transform_free(dev);
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
			unsigned cachesize, sector_t offset,
			cipher_t cipher, hash_t hash, compress_t compress)
{
	struct convergent_dev *dev;
	sector_t capacity;
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
	
	spin_lock_init(&dev->lock);
	INIT_LIST_HEAD(&dev->freed_ios);
	init_waitqueue_head(&dev->waiting_users);
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
	/* XXX must not be smaller than MAX_CHUNKS_PER_IO */
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
	/* XXX this has a minimum of PAGE_CACHE_SIZE - 1, which might be
	   larger than PAGE_SIZE */
	blk_queue_segment_boundary(dev->queue, PAGE_SIZE - 1);
	blk_queue_max_sectors(dev->queue,
				chunk_sectors(dev) * (MAX_CHUNKS_PER_IO - 1));
	
	ndebug("Allocating transforms");
	ret=transform_alloc(dev, cipher, hash, compress);
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
	dev->chunks=chunk_of(dev, capacity);
	dev->gendisk->private_data=dev;
	ndebug("Adding disk");
	/* add_disk() initiates I/O to read the partition tables, so userspace
	   needs to be able to process key requests while it is running.
	   If we called add_disk() directly here, we would deadlock. */
	ret=delayed_add_disk(dev->gendisk);
	if (ret) {
		log(KERN_ERR, "couldn't schedule gendisk registration");
		goto bad;
	}
	
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
	
	io_cache=kmem_cache_create(MODULE_NAME "-io",
				sizeof(struct convergent_io), 0, 0, NULL, NULL);
	if (io_cache == NULL) {
		ret=-ENOMEM;
		goto bad_cache;
	}
	io_pool=mempool_create(MIN_CONCURRENT_REQS, mempool_alloc_slab,
				mempool_free_slab, io_cache);
	if (io_pool == NULL) {
		ret=-ENOMEM;
		goto bad_mempool;
	}
	
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
	mempool_destroy(io_pool);
bad_mempool:
	if (kmem_cache_destroy(io_cache))
		log(KERN_ERR, "couldn't destroy io cache");
bad_cache:
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
	
	mempool_destroy(io_pool);
	if (kmem_cache_destroy(io_cache))
		log(KERN_ERR, "couldn't destroy io cache");
}

module_init(convergent_init);
module_exit(convergent_shutdown);

MODULE_AUTHOR("Benjamin Gilbert <bgilbert@cs.cmu.edu>");
MODULE_DESCRIPTION("stacking block device for convergent encryption "
			"and compression");
/* We must use a GPL-compatible license to use the crypto API */
MODULE_LICENSE("GPL");
