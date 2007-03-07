/* request.c - request queue interface code */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (TM)
 *         system
 * 
 * Copyright (C) 2006-2007 Carnegie Mellon University
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/mempool.h>
#include "defs.h"

static kmem_cache *io_cache;
static mempool_t *io_pool;

/**
 * scatterlist_copy - copy bytes between scatterlists
 * @soffset: source offset in bytes
 * @doffset: destination offset in bytes
 * @len    : length in bytes
 *
 * This function supports copying to/from scatterlist pages in both high and
 * low memory.  It must be run from user context, since it uses KM_USER*.
 **/
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

/**
 * __end_that_request - report completion of blockdev I/O to the block layer
 *
 * Call end_that_request_first() and, if this completes the entire request,
 * end_that_request_last().  This must be called with the queue lock held and
 * interrupts disabled.
 **/
static int __end_that_request(struct request *req, int uptodate, int nr_sectors)
{
	int ret;
	request_queue_t *q=req->q;
	
	BUG_ON(!list_empty(&req->queuelist));
	ret=end_that_request_first(req, uptodate, nr_sectors);
	debug(DBG_REQUEST, "Ending %d sectors, done=%d", nr_sectors, !ret);
	if (!ret) {
		end_that_request_last(req, uptodate);
		/* XXX Arrange for our request function to be called again.
		   If this isn't here, we'll wedge in under a minute when
		   using the CFQ I/O scheduler: our request function won't be
		   called when there are outstanding requests.  Other I/O
		   schedulers work fine.  Email from Jens Axboe on 1/23/07
		   seems to imply that we need to do this, but I'm not
		   convinced it makes sense.  -BG */
		blk_start_queue(q);
	}
	return ret;
}

/**
 * end_that_request - report completion of blockdev I/O to the block layer
 *
 * After taking the queue lock, call end_that_request_first() and, if this
 * completes the entire request, end_that_request_last().
 **/
static int end_that_request(struct request *req, int uptodate, int nr_sectors)
{
	spinlock_t *lock=req->q->queue_lock;
	int ret;
	
	/* We don't use irqsave.  We can't BUG_ON because, by definition,
	   interrupts are disabled */
	WARN_ON(irqs_disabled());
	/* This could be _bh except for the blk_start_queue() call in
	   __end_that_request() */
	spin_lock_irq(lock);
	ret=__end_that_request(req, uptodate, nr_sectors);
	spin_unlock_irq(lock);
	return ret;
}

/**
 * nexus_complete_chunk - register completion of @chunk
 *
 * The block layer requires that bytes in a request be completed in order.
 * When we complete one chunk of a &nexus_io, we mark it completed in the
 * &nexus_io_chunk but don't report completion to the block layer until all
 * previous chunks in the io have been marked completed.  If we discover
 * completed chunks which can now be reported to the block layer, but have
 * not been (because they were waiting on other chunks), we do so.  After
 * reporting a completion to the block layer, we unreserve the chunk in
 * chunkdata (even if the whole &nexus_io hasn't finished yet), since there
 * can no longer be ordering issues with that chunk wrt this io.
 *
 * If all chunks in this &nexus_io have been completed, we free the io.
 **/
static void nexus_complete_chunk(struct nexus_io_chunk *chunk)
{
	int i;
	struct nexus_io *io=chunk->parent;
	
	BUG_ON(!mutex_is_locked(&io->dev->lock));
	
	chunk->flags |= CHUNK_COMPLETED;
	debug(DBG_REQUEST, "Completing chunk " SECTOR_FORMAT, chunk->cid);
	
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if (chunk->flags & CHUNK_DEAD)
			continue;
		if (!(chunk->flags & CHUNK_COMPLETED))
			return;
		debug(DBG_REQUEST, "end_that_request for chunk " SECTOR_FORMAT,
					chunk->cid);
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

/**
 * nexus_process_chunk - process one &nexus_io_chunk from a &nexus_io
 * @chunk_sg: the scatterlist with the canonical copy of the chunk data
 *
 * This function is called by chunkdata, in thread context, when @chunk is
 * ready to execute (or has errored out).  This is where we actually do the
 * data copying.
 **/
void nexus_process_chunk(struct nexus_io_chunk *chunk,
			struct scatterlist *chunk_sg)
{
	struct nexus_io *io=chunk->parent;
	struct nexus_dev *dev=io->dev;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	
	/* The underlying chunk I/O might have errored out */
	if (chunk->error) {
		debug(DBG_REQUEST, "process_chunk I/O error: chunk "
					SECTOR_FORMAT, chunk->cid);
		nexus_complete_chunk(chunk);
		return;
	}
	
	debug(DBG_REQUEST, "process_chunk called: chunk " SECTOR_FORMAT
				", offset %u, length %u", chunk->cid,
				chunk->offset, chunk->len);
	
	if (io->flags & IO_WRITE) {
		dev->stats.sectors_written += chunk->len / 512;
		scatterlist_copy(io->orig_sg, chunk_sg, chunk->orig_offset,
					chunk->offset, chunk->len);
	} else {
		dev->stats.sectors_read += chunk->len / 512;
		scatterlist_copy(chunk_sg, io->orig_sg, chunk->offset,
					chunk->orig_offset, chunk->len);
	}
	nexus_complete_chunk(chunk);
}

/**
 * nexus_setup_io - set up Nexus data structures for an incoming request @req
 *
 * Allocate and fill in a &nexus_io data structure (and its associated array of
 * &nexus_io_chunk) corresponding to @req, and request a reservation from
 * chunkdata for each of the chunks in the io.  This function is the gatekeeper
 * between the block layer and the rest of Nexus; if any memory or other
 * resource allocations necessary for completing the request could experience
 * temporary failures (e.g., out-of-memory, chunkdata cache full, etc.),
 * they need to be done from this function.  nexus_setup_io() may return
 * -ENOMEM if it cannot preallocate the resources it needs, in which
 * case the caller must be prepared to back off and try again later.
 * Any errors encountered after nexus_setup_io() completes will turn into
 * I/O errors visible to the rest of the system; there will be no further
 * opportunities for retry.
 *
 * If the device has been shut down, this function will error out the request
 * and return -ENXIO, since this is a hard failure.
 *
 * After this function completes successfully, the request code will not
 * deal with this io again until chunkdata decides to start calling
 * nexus_process_chunk() on its io_chunks.
 *
 * &struct nexus_io and &struct nexus_io_chunk contain several fields that
 * are redundant with &struct request.  The intent is that once &nexus_io
 * and &nexus_io_chunk are filled in by this function, the rest of Nexus
 * can deal only with those structures and remain insulated from the details
 * of the block layer.  This philosophy extends to copying the entire
 * bio/bio_vec hierarchy into a scatterlist for ease of access.
 **/
static int nexus_setup_io(struct nexus_dev *dev, struct request *req)
{
	struct nexus_io *io;
	struct nexus_io_chunk *chunk;
	unsigned remaining;
	unsigned bytes;
	unsigned nsegs;
	int i;
	
	BUG_ON(req->nr_phys_segments > MAX_SEGS_PER_IO);
	
	if (dev_is_shutdown(dev)) {
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
	io->prio=req_get_prio(req);
	if (rq_data_dir(req))
		io->flags |= IO_WRITE;
	nsegs=blk_rq_map_sg(dev->queue, req, io->orig_sg);
	debug(DBG_REQUEST, "%d phys segs, %d coalesced segs",
				req->nr_phys_segments, nsegs);
	
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
	
	debug(DBG_REQUEST, "setup_io called: %lu sectors over " SECTOR_FORMAT
				" chunks at chunk " SECTOR_FORMAT,
				req->nr_sectors,
				io->last_cid - io->first_cid + 1,
				io->first_cid);
	
	mutex_lock_thread(&dev->lock);
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

/**
 * oom_timer_fn - schedule request thread callback when OOM delay expires
 *
 * Called from timer (i.e., softirq) context.  Bound to &nexus_dev
 * requests_oom_timer by ctr.
 **/
void oom_timer_fn(unsigned long data)
{
	struct nexus_dev *dev=(struct nexus_dev *)data;
	debug(DBG_REQUEST, "OOM delay expired");
	schedule_request_callback(&dev->lh_run_requests);
}

/**
 * nexus_run_requests - thread callback to process requests from block layer
 *
 * The block layer runs our request function with the queue lock held and
 * interrupts disabled.  For a number of reasons, it's difficult to get work
 * done in that environment, so the request function just queues requests
 * until we can process them in a thread callback; nexus_run_requests() is
 * the corresponding callback function.  When called, we iterate over all
 * pending requests, calling nexus_setup_io() on each one.
 * 
 * This thread callback is different from all of the others in Nexus in that
 * it processes all pending requests rather than just one at a time, and the
 * thread code ensures that only one CPU/thread can be executing here at a
 * time; this is necessary to ensure that our out-of-memory handling can never
 * reorder pending requests.
 *
 * If nexus_setup_io() reports an out-of-memory condition, we requeue the
 * request at the head of the queue and arrange for a timer to schedule us
 * again later, in the hope that resources will have been freed up by then.
 * While the timer is pending, the request function will not attempt to
 * schedule us again, even if further requests arrive.
 *
 * In order to make sure the &nexus_dev isn't freed while there are pending
 * requests, both this function and the request function always gets a dev
 * reference when adding a request to an empty run_requests queue, and this
 * function always puts the reference when removing the last request from
 * the queue.  In order to make sure the dev isn't freed out from under us
 * while we're running, we get an additional dev reference for the duration
 * of nexus_run_requests().
 **/
void nexus_run_requests(struct list_head *entry)
{
	struct nexus_dev *dev=container_of(entry, struct nexus_dev,
				lh_run_requests);
	struct request *req;
	int need_put;
	
	if (!test_and_clear_bit(__DEV_REQ_PENDING, &dev->flags))
		BUG();
	nexus_dev_get(dev);
	/* We need to use the _bh variant because CFQ has a timer which takes
	   the queue lock.  If we didn't disable softirqs here, the timer
	   could fire after we get the requests_lock and a lock-order inversion
	   would occur between the queue and requests locks. */
	spin_lock_bh(&dev->requests_lock);
	/* We don't use the "safe" iterator because the next pointer might
	   change out from under us between iterations */
	while (!list_empty(&dev->requests)) {
		req=list_entry(dev->requests.next, struct request, queuelist);
		list_del_init(&req->queuelist);
		need_put=list_empty(&dev->requests);
		spin_unlock_bh(&dev->requests_lock);
		if (need_put)
			nexus_dev_put(dev, 0);
		if (blk_fs_request(req)) {
			switch (nexus_setup_io(dev, req)) {
			case 0:
			case -ENXIO:
				break;
			case -ENOMEM:
				spin_lock_bh(&dev->requests_lock);
				if (list_empty(&dev->requests))
					nexus_dev_get(dev);
				list_add(&req->queuelist, &dev->requests);
				/* Come back later when we're happier, if we
				   haven't already been scheduled to run again
				   immediately */
				if (!test_and_set_bit(__DEV_REQ_PENDING,
								&dev->flags)) {
					dev->requests_oom_timer.expires=jiffies
							+ LOWMEM_WAIT_TIME;
					debug(DBG_REQUEST, "OOM delay");
					add_timer(&dev->requests_oom_timer);
				}
				goto out;
			default:
				BUG();
			}
		} else {
			/* XXX */
			debug(DBG_REQUEST, "Skipping non-fs request");
			end_that_request(req, 0, req->nr_sectors);
		}
		cond_resched();
		spin_lock_bh(&dev->requests_lock);
	}
out:
	spin_unlock_bh(&dev->requests_lock);
	nexus_dev_put(dev, 0);
}

/**
 * nexus_request - the block layer request function
 *
 * The block layer calls this when it has requests it wants us to process.
 * We are expected to process every pending request from the queue (or
 * explicitly notify the block layer that we will not, but we don't do that).
 *
 * This function is called with the queue lock held and interrupts disabled.
 * All we do here is enqueue requests for the nexus_run_requests() callback
 * and schedule it if it's not already scheduled.  If the dev is already
 * shut down, we bypass the run_requests callback and error out the requests
 * directly from here.  (Downstream functions still need to check for this
 * case, since the dev may have been shut down with I/O in flight.)
 **/
void nexus_request(request_queue_t *q)
{
	struct nexus_dev *dev=q->queuedata;
	struct request *req;
	int need_queue=0;
	
	while ((req = elv_next_request(q)) != NULL) {
		blkdev_dequeue_request(req);
		if (dev_is_shutdown(dev)) {
			__end_that_request(req, 0, req->nr_sectors);
		} else {
			/* We don't use _bh or _irq variants since irqs are
			   already disabled */
			spin_lock(&dev->requests_lock);
			if (list_empty(&dev->requests))
				nexus_dev_get(dev);
			list_add_tail(&req->queuelist, &dev->requests);
			spin_unlock(&dev->requests_lock);
			need_queue=1;
		}
	}
	if (need_queue) {
		/* Avoid enqueueing if already enqueued */
		if (!test_and_set_bit(__DEV_REQ_PENDING, &dev->flags))
			schedule_request_callback(&dev->lh_run_requests);
	}
}

/**
 * kick_elevator - force the request function to be called
 *
 * For debug use via sysfs only.  Force our request function to be called,
 * in case the elevator has failed to do it for us.  (This shouldn't be
 * necessary, but there are some not-fully-understood issues with CFQ
 * which may require it...)
 **/
void kick_elevator(struct nexus_dev *dev)
{
	log(KERN_NOTICE, "Unwedging elevator");
	blk_run_queue(dev->queue);
}

/**
 * request_start - module initialization for request processing code
 **/
int __init request_start(void)
{
	int ret;
	
	io_cache=kmem_cache_create(MODULE_NAME "-io",
				sizeof(struct nexus_io), 0, 0, NULL, NULL);
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
	kmem_cache_destroy(io_cache);
bad_cache:
	return ret;
}

/**
 * request_shutdown - module de-initialization for request processing code
 **/
void __exit request_shutdown(void)
{
	mempool_destroy(io_pool);
	kmem_cache_destroy(io_cache);
}
