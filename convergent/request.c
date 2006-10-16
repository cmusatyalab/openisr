#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/mempool.h>
#include "convergent.h"

static kmem_cache_t *io_cache;
static mempool_t *io_pool;

/* supports high memory pages */
static void scatterlist_copy(struct scatterlist *src, struct scatterlist *dst,
			unsigned soffset, unsigned doffset, unsigned len)
{
	void *sbuf, *dbuf;
	unsigned sleft, dleft;
	unsigned bytesThisRound;
	
	/* We use KM_USER* */
	BUG_ON(in_interrupt());
	
	/* Necessary to preserve invariant of comment A */
	if (len == 0)
		return;
	
	while (soffset >= src->length) {
		soffset -= src->length;
		src++;
	}
	sleft=src->length - soffset;
	sbuf=kmap_atomic(src->page, KM_USER0) + src->offset + soffset;
	
	while (doffset >= dst->length) {
		doffset -= dst->length;
		dst++;
	}
	dleft=dst->length - doffset;
	dbuf=kmap_atomic(dst->page, KM_USER1) + dst->offset + doffset;
	
	/* Comment A: We calculate the address to kunmap_atomic() as buf - 1,
	   since in all cases that we call kunmap_atomic(), we must have
	   copied at least one byte from buf.  If we used buf, we might
	   unmap the wrong page if we copied a full page. */
	while (len) {
		if (sleft == 0) {
			kunmap_atomic(sbuf - 1, KM_USER0);
			src++;
			sbuf=kmap_atomic(src->page, KM_USER0) + src->offset;
			sleft=src->length;
		}
		if (dleft == 0) {
			kunmap_atomic(dbuf - 1, KM_USER1);
			dst++;
			dbuf=kmap_atomic(dst->page, KM_USER1) + dst->offset;
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
	kunmap_atomic(sbuf - 1, KM_USER0);
	kunmap_atomic(dbuf - 1, KM_USER1);
}

static int __end_that_request(struct request *req, int uptodate, int nr_sectors)
{
	int ret;
	
	BUG_ON(!list_empty(&req->queuelist));
	ret=end_that_request_first(req, uptodate, nr_sectors);
	if (!ret)
		end_that_request_last(req, uptodate);
	return ret;
}

static int end_that_request(struct request *req, int uptodate, int nr_sectors)
{
	spinlock_t *lock=req->q->queue_lock;
	int ret;
	
	spin_lock_bh(lock);
	ret=__end_that_request(req, uptodate, nr_sectors);
	spin_unlock_bh(lock);
	return ret;
}

static void convergent_complete_chunk(struct convergent_io_chunk *chunk)
{
	int i;
	struct convergent_io *io=chunk->parent;
	
	BUG_ON(!mutex_is_locked(&io->dev->lock));
	
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

/* Process one chunk from an io. */
void convergent_process_chunk(struct convergent_io_chunk *chunk)
{
	struct convergent_io *io=chunk->parent;
	struct convergent_dev *dev=io->dev;
	struct scatterlist *chunk_sg;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	
	/* The underlying chunk I/O might have errored out */
	if (chunk->error) {
		debug("process_chunk I/O error: chunk " SECTOR_FORMAT,
					chunk->cid);
		convergent_complete_chunk(chunk);
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
		remaining -= chunk->len;
		bytes += chunk->len;
	}
	
	ndebug("setup_io called: %lu sectors over " SECTOR_FORMAT
				" chunks at chunk " SECTOR_FORMAT,
				req->nr_sectors,
				io->last_chunk - io->first_chunk + 1,
				io->first_chunk);
	
	mutex_lock_workqueue(&dev->lock);
	if (reserve_chunks(io)) {
		/* Couldn't allocate chunkdata for this io, so we have to
		   tear the whole thing down */
		mutex_unlock(&dev->lock);
		mempool_free(io, io_pool);
		return -ENOMEM;
	}
	mutex_unlock(&dev->lock);
	return 0;
}

/* Workqueue callback */
void convergent_run_requests(void *data)
{
	struct convergent_dev *dev=data;
	struct request *req;
	int need_put;
	
	if (convergent_dev_get(dev) == NULL)
		return;
	spin_lock(&dev->requests_lock);
	/* We don't use the "safe" iterator because the next pointer might
	   change out from under us between iterations */
	while (!list_empty(&dev->requests)) {
		req=list_entry(dev->requests.next, struct request, queuelist);
		list_del_init(&req->queuelist);
		need_put=list_empty(&dev->requests);
		spin_unlock(&dev->requests_lock);
		if (need_put)
			convergent_dev_put(dev, 0);
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
			spin_lock(&dev->requests_lock);
			if (list_empty(&dev->requests))
				convergent_dev_get(dev);
			list_add(&req->queuelist, &dev->requests);
			/* Come back later when we're happier */
			queue_delayed_work(wkqueue, &dev->cb_run_requests,
						LOWMEM_WAIT_TIME);
			goto out;
		default:
			BUG();
		}
		spin_lock(&dev->requests_lock);
	}
out:
	spin_unlock(&dev->requests_lock);
	convergent_dev_put(dev, 0);
}

/* Called with queue lock held */
void convergent_request(request_queue_t *q)
{
	struct convergent_dev *dev=q->queuedata;
	struct request *req;
	int need_queue=0;
	
	/* We don't spin_lock_bh() the requests lock */
	BUG_ON(in_interrupt());
	while ((req = elv_next_request(q)) != NULL) {
		blkdev_dequeue_request(req);
		if (dev->flags & DEV_SHUTDOWN) {
			__end_that_request(req, 0, req->nr_sectors);
		} else {
			spin_lock(&dev->requests_lock);
			if (list_empty(&dev->requests))
				convergent_dev_get(dev);
			list_add_tail(&req->queuelist, &dev->requests);
			spin_unlock(&dev->requests_lock);
			need_queue=1;
		}
	}
	if (need_queue) {
		/* Duplicate enqueue requests will be ignored */
		queue_work(wkqueue, &dev->cb_run_requests);
	}
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
