#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/mempool.h>
#include <linux/workqueue.h>
#include "convergent.h"

static kmem_cache_t *io_cache;
static mempool_t *io_pool;

/* supports high memory pages */
/* XXX race between user and softirq kmaps? */
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

/* XXX restructure this */
static void io_cleaner(void* data)
{
	struct convergent_dev *dev=data;
	int need_release_ref=0;
	
	spin_lock_bh(&dev->lock);
	/* XXX perhaps it wouldn't hurt to make the timer more frequent */
	if (dev->flags & DEV_LOWMEM) {
		dev->flags &= ~DEV_LOWMEM;
		queue_start(dev);
	}
	if ((dev->flags & DEV_SHUTDOWN) && !(dev->flags & DEV_CD_SHUTDOWN) &&
				!dev->need_user) {
		dev->flags |= DEV_CD_SHUTDOWN;
		/* Must not release ref with the lock held */
		need_release_ref=1;
	}
	spin_unlock_bh(&dev->lock);
	if (need_release_ref || atomic_add_unless(&dev->pending_puts, -1, 0))
		convergent_dev_put(dev, 0);
	if (!(dev->flags & DEV_KILLCLEANER))
		queue_delayed_work(queue, &dev->cleaner, CLEANER_SWEEP);
	else
		debug("Timer shutting down");
}

static void convergent_complete_chunk(struct convergent_io_chunk *chunk)
{
	int i;
	struct convergent_io *io=chunk->parent;
	
	BUG_ON(!spin_is_locked(&io->dev->lock));
	
	chunk->flags |= CHUNK_COMPLETED;
	ndebug("Completing chunk " SECTOR_FORMAT, chunk->cid);
	
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if (chunk->flags & CHUNK_DEAD)
			continue;
		if (!(chunk->flags & CHUNK_COMPLETED))
			return;
		ndebug("end_that_request for chunk " SECTOR_FORMAT, chunk->cid);
		end_that_request(io->orig_req,
					chunk->error ? chunk->error : 1,
					chunk->len / 512);
		chunk->flags |= CHUNK_DEAD;
		/* We only unreserve the chunk after endio, to make absolutely
		   sure the user never sees out-of-order completions of the same
		   chunk. */
		unreserve_chunk(chunk);
	}
	/* All chunks in this io are completed. */
	mempool_free(io, io_pool);
}

/* Process one chunk from an io.  Called from workqueue. */
static void convergent_process_chunk(void *data)
{
	struct convergent_io_chunk *chunk=data;
	struct convergent_io *io=chunk->parent;
	struct convergent_dev *dev=io->dev;
	struct scatterlist *chunk_sg;
	
	spin_lock_bh(&dev->lock);
	
	/* The underlying chunk I/O might have errored out */
	if (chunk->error) {
		debug("process_chunk I/O error: chunk " SECTOR_FORMAT,
					chunk->cid);
		convergent_complete_chunk(chunk);
		spin_unlock_bh(&dev->lock);
		return;
	}
	
	ndebug("process_chunk called: chunk " SECTOR_FORMAT ", offset %u, "
				"length %u", chunk->cid, chunk->offset,
				chunk->len);
	
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
	io->first_cid=chunk_of(dev, req->sector);
	io->last_cid=chunk_of(dev, req->sector + req->nr_sectors - 1);
	io->prio=req->ioprio;
	if (rq_data_dir(req))
		io->flags |= IO_WRITE;
	nsegs=blk_rq_map_sg(dev->queue, req, io->orig_sg);
	ndebug("%d phys segs, %d coalesced segs", req->nr_phys_segments, nsegs);
	
	bytes=0;
	remaining=(unsigned)req->nr_sectors * 512;
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		chunk->parent=io;
		chunk->cid=io->first_cid + i;
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
		INIT_WORK(&chunk->callback, convergent_process_chunk, chunk);
		remaining -= chunk->len;
		bytes += chunk->len;
	}
	
	ndebug("setup_io called: %lu sectors over " SECTOR_FORMAT
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
void convergent_request(request_queue_t *q)
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

void cleaner_start(struct convergent_dev *dev)
{
	INIT_WORK(&dev->cleaner, io_cleaner, dev);
	queue_delayed_work(queue, &dev->cleaner, CLEANER_SWEEP);
}

void cleaner_stop(struct convergent_dev *dev)
{
	dev->flags |= DEV_KILLCLEANER;
	cancel_delayed_work(&dev->cleaner);
	flush_workqueue(queue);
	/* Run the timer one more time to make sure everything's cleaned out */
	io_cleaner(dev);
}

int __init request_start(void)
{
	int ret;
	
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
	return 0;
	
bad_mempool:
	if (kmem_cache_destroy(io_cache))
		log(KERN_ERR, "couldn't destroy io cache");
bad_cache:
	return ret;
}

void __exit request_shutdown(void)
{
	mempool_destroy(io_pool);
	if (kmem_cache_destroy(io_cache))
		log(KERN_ERR, "couldn't destroy io cache");
}
