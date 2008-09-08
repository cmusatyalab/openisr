/* chunkdata.c - chunk cache and state machine */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (R)
 *         system
 * 
 * Copyright (C) 2006-2008 Carnegie Mellon University
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

#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/bio.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/scatterlist.h>
#include "defs.h"

enum cd_bits {
	__CD_USER,           /* Was given to userspace; waiting for reply */
	__CD_NR_BITS
};

#define CD_USER         (1 << __CD_USER)

enum cd_state {
	ST_INVALID,          /* No key or data */
	ST_LOAD_META,        /* Loading metadata */
	ST_META,             /* Have metadata but not data */
	ST_LOAD_DATA,        /* Loading data */
	ST_ENCRYPTED,        /* Have metadata and clean, encrypted data */
	ST_DECRYPTING,       /* Decrypting data */
	ST_CLEAN,            /* Have metadata and data */
	ST_DIRTY,            /* Data is dirty */
	ST_ENCRYPTING,       /* Encrypting data */
	ST_DIRTY_ENCRYPTED,  /* Data is dirty and encryption has finished */
	ST_STORE_DATA,       /* Storing data */
	ST_DIRTY_META,       /* Metadata is dirty */
	ST_STORE_META,       /* Storing metadata */
	ST_ERROR_USER,       /* Error; data not valid; must notify userspace */
	ST_ERROR_PENDING,    /* Userspace notification queued */
	ST_ERROR,            /* I/O error occurred; data not valid */
	NR_STATES
};

/**
 * struct chunkdata - one chunk in the chunkdata cache/state machine
 * @lh_bucket            : list head for &chunkdata_table bucket
 * @lh_lru               : list head for LRU list
 * @lh_user              : list head for usermsg queue
 * @lh_need_update       : list head for CB_UPDATE_CHUNK
 * @lh_pending_completion: list head for CB_COMPLETE_IO
 * @lh_need_tfm          : list head for CB_CRYPTO
 * @table                : pointer to parent &chunkdata_table
 * @cid                  : the chunk number for this chunk
 * @size                 : encrypted size including padding, in bytes
 * @compression          : compression type
 * @pending              : queue of pending &nexus_io_chunk for this chunk
 * @remaining            : bytes which have not yet completed chunk store I/O
 * @error                : error code if in ST_ERROR/ST_ERROR_*
 * @errtype              : error type for userspace if in ST_ERROR_*
 * @flags                : CD_ flags
 * @state                : current state in state machine
 * @state_begin          : when we entered @state (usec since epoch)
 * @key                  : key as of last encrypt/decrypt
 * @tag                  : tag as of last encrypt/decrypt
 * @found                : calculated tag/key if mismatch found
 * @sg                   : scatterlist pointing to chunk contents
 *
 * &struct chunkdata is protected by the dev lock, with a few exceptions.
 * The list heads for thread callbacks are updated under the appropriate
 * locks by thread.c.  @remaining is not protected by any lock; it may be
 * updated from hardirq context.
 **/
struct chunkdata {
	struct list_head lh_bucket;
	struct list_head lh_lru;
	struct list_head lh_user;
	struct list_head lh_need_update;
	struct list_head lh_pending_completion;
	struct list_head lh_need_tfm;
	struct chunkdata_table *table;
	chunk_t cid;
	unsigned size;
	enum nexus_compress compression;
	struct list_head pending;
	atomic_t remaining;
	int error;
	nexus_err_t errtype;
	unsigned flags;
	enum cd_state state;
	u64 state_begin;
	char key[NEXUS_MAX_HASH_LEN];
	char tag[NEXUS_MAX_HASH_LEN];
	char found[NEXUS_MAX_HASH_LEN];
	struct scatterlist *sg;
};

/**
 * struct chunkdata_table - chunkdata state for a single &nexus_dev
 * @dev            : the parent &nexus_dev (r/o)
 * @buckets        : the number of buckets in @hash (r/o)
 * @busy_count     : count of &chunkdata in non-idle state
 * @pending_updates: length of CB_UPDATE_CHUNK queue
 * @lru            : LRU list for chunkdata_reclaim()
 * @user           : usermsg queue for chardev
 * @hash           : &chunkdata hash table -- array of @buckets list_heads
 *
 * &chunkdata_table is protected by the dev lock.
 **/
struct chunkdata_table {
	struct nexus_dev *dev;
	unsigned buckets;
	unsigned busy_count;
	unsigned pending_updates;
	struct list_head lru;
	struct list_head user;
	struct list_head *hash;
};

static struct bio_set *bio_pool;


/**
 * current_time_usec - return the number of microseconds since the epoch
 **/
static u64 current_time_usec(void)
{
	struct timeval curtime;
	
	do_gettimeofday(&curtime);
	return curtime.tv_sec * USEC_PER_SEC + curtime.tv_usec;
}

/**
 * hash - return the number of the hash table bucket for the given chunk
 **/
static inline unsigned hash(struct chunkdata_table *table, chunk_t cid)
{
	return (unsigned)cid % table->buckets;
}

/**
 * pending_head - return the first &nexus_io_chunk pending on this @cd
 *
 * Returns NULL if no &nexus_io_chunk is pending.
 **/
static inline struct nexus_io_chunk *pending_head(struct chunkdata *cd)
{
	if (list_empty(&cd->pending))
		return NULL;
	return list_first_entry(&cd->pending, struct nexus_io_chunk,
				lh_pending);
}

/**
 * pending_head_is - return true if @chunk is the first io_chunk pending on @cd
 **/
static inline int pending_head_is(struct chunkdata *cd,
			struct nexus_io_chunk *chunk)
{
	if (list_empty(&cd->pending))
		return 0;
	return (pending_head(cd) == chunk);
}

/**
 * is_idle_state - return true if @state is potentially idle
 *
 * Non-idle states are those which always indicate that processing or I/O
 * is ongoing.  If is_idle_state() returns true, AND no I/O is pending on a
 * chunk in @state (i.e., pending_head(cd) == NULL), that chunk's cache line
 * can safely be recycled for a different chunk.
 **/
static inline int is_idle_state(enum cd_state state)
{
	switch (state) {
	case ST_INVALID:
	case ST_ENCRYPTED:
	case ST_CLEAN:
	case ST_ERROR:
		return 1;
	default:
		return 0;
	}
}

/**
 * __transition - internals of state machine transition code
 *
 * Don't call this; call transition() or transition_error().
 *
 * This is where the actual state transition is done.  For statistics purposes,
 * we keep track of the number of chunkdata lines in each state, as well
 * as (information allowing us to calculate) the amount of time spent in each
 * state.  We also maintain a user reference for every chunk in non-idle state;
 * this prevents the chardev from going away (assuming userspace uses
 * NEXUS_IOC_UNREGISTER) if the block device has been closed but writeback
 * is still in progress.
 **/
static void __transition(struct chunkdata *cd, enum cd_state new_state)
{
	struct nexus_dev *dev=cd->table->dev;
	enum cd_state states[2]={cd->state, new_state};
	u64 curtime=current_time_usec();
	int idle[2];
	int i;
	
	BUILD_BUG_ON(NR_STATES != CD_NR_STATES);
	BUG_ON(!mutex_is_locked(&dev->lock));
	dev->stats.state_time_us[cd->state] += curtime - cd->state_begin;
	dev->stats.state_time_samples[cd->state]++;
	for (i=0; i<2; i++)
		idle[i]=is_idle_state(states[i]);
	if (!idle[0] && idle[1]) {
		user_put(dev);
		cd->table->busy_count--;
	}
	if (idle[0] && !idle[1]) {
		user_get(dev);
		cd->table->busy_count++;
	}
	dev->stats.state_count[cd->state]--;
	dev->stats.state_count[new_state]++;
	cd->state=new_state;
	cd->state_begin=curtime;
}

#ifdef DEBUG
/**
 * format_hash - debug/logging helper to convert a hash to hex representation
 * @out   : buffer in which to store the hex digits
 * @in    : hash bytes
 * @in_len: number of bytes in @in
 *
 * @out must be able to store 2 * @in_len + 1 bytes.
 **/
static void format_hash(char *out, unsigned char *in, unsigned in_len)
{
	int i;
	for (i=0; i<in_len; i++, in++, out += 2)
		sprintf(out, "%.2x", *in);
}

/**
 * log_chunk_err - log a debug message for an ST_ERROR_USER transition
 **/
static void log_chunk_err(struct chunkdata *cd)
{
	unsigned hash_len = suite_info(cd->table->dev->suite)->hash_len;
	char tag[2 * hash_len + 1];
	char found[2 * hash_len + 1];
	enum nexus_chunk_err err;
	const char *rw;
	
	err = cd->errtype & ~NEXUS_ERR_IS_WRITE;
	rw = (cd->errtype & NEXUS_ERR_IS_WRITE) ? "Writing" : "Reading";
	switch (err) {
	case NEXUS_ERR_NOERR:
		BUG();
		break;
	case NEXUS_ERR_IO:
		debug(DBG_ERR, "%s chunk " SECTOR_FORMAT ": I/O error", rw,
					cd->cid);
		break;
	case NEXUS_ERR_TAG:
		format_hash(tag, cd->tag, hash_len);
		format_hash(found, cd->found, hash_len);
		debug(DBG_ERR, "%s chunk " SECTOR_FORMAT ": Expected tag %s, "
					"found %s", rw, cd->cid, tag, found);
		break;
	case NEXUS_ERR_KEY:
		format_hash(tag, cd->tag, hash_len);
		debug(DBG_ERR, "%s chunk " SECTOR_FORMAT ": Key doesn't "
					"match decrypted data for tag %s",
					rw, cd->cid, tag);
		break;
	case NEXUS_ERR_HASH:
		debug(DBG_ERR, "%s chunk " SECTOR_FORMAT ": Hashing failed",
					rw, cd->cid);
		break;
	case NEXUS_ERR_CRYPT:
		debug(DBG_ERR, "%s chunk " SECTOR_FORMAT ": Crypto failed",
					rw, cd->cid);
		break;
	case NEXUS_ERR_COMPRESS:
		format_hash(tag, cd->tag, hash_len);
		debug(DBG_ERR, "%s chunk " SECTOR_FORMAT ": Compression "
					"failed, tag %s", rw, cd->cid, tag);
		break;
	}
}
#else
#define log_chunk_err(cd) do {} while (0)
#endif

/**
 * transition - transition @cd to a new non-error state @new_state
 **/
static void transition(struct chunkdata *cd, enum cd_state new_state)
{
	BUG_ON(new_state == ST_ERROR);
	BUG_ON(new_state == ST_ERROR_USER);
	BUG_ON(new_state == ST_ERROR_PENDING);
	__transition(cd, new_state);
}

/**
 * transition_error - transition @cd into error state
 * @cd     : the chunk
 * @error  : the POSIX error code to associate with the chunk
 * @errtype: the &enum nexus_err_t to return to userspace, or 0 if none
 **/
static void transition_error(struct chunkdata *cd, int error,
			nexus_err_t errtype)
{
	cd->error=error;
	cd->errtype=errtype;
	cd->table->dev->stats.chunk_errors++;
	if (errtype) {
		log_chunk_err(cd);
		__transition(cd, ST_ERROR_USER);
	} else {
		__transition(cd, ST_ERROR);
	}
}

/**
 * transition_error_hash - report tag/key check error to userspace
 **/
static void transition_error_hash(struct chunkdata *cd, int error,
			nexus_err_t errtype, char *found)
{
	unsigned hash_len=suite_info(cd->table->dev->suite)->hash_len;
	
	BUG_ON(errtype != NEXUS_ERR_TAG && errtype != NEXUS_ERR_KEY);
	memcpy(cd->found, found, hash_len);
	transition_error(cd, error, errtype);
}

/**
 * update_chunk - schedule @cd to be processed through the state machine
 *
 * update_chunk() arranges for the current state and pending I/O queue of @cd
 * to be examined in a kernel thread, at some point in the future, at which
 * point any work that needs to be started on @cd will be started.
 * update_chunk() is usually called right after some work on a chunk has
 * completed and transition() has been called to move the chunk to a new state.
 * It is always safe to call update_chunk() on a chunk, whether or not work
 * is pending for it and whether or not it is already queued for processing.
 **/
static void update_chunk(struct chunkdata *cd)
{
	struct chunkdata_table *table=cd->table;
	
	BUG_ON(!mutex_is_locked(&table->dev->lock));
	if (!list_empty(&cd->lh_need_update))
		return;
	table->pending_updates++;
	schedule_callback(CB_UPDATE_CHUNK, &cd->lh_need_update);
}

/**
 * chunkdata_find - find an existing &struct chunkdata for the specified @cid
 *
 * chunkdata_find() will return the existing &struct chunkdata for @cid, or
 * if none exists, it will return NULL.
 **/
static struct chunkdata *chunkdata_find(struct chunkdata_table *table,
			chunk_t cid)
{
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&table->dev->lock));
	list_for_each_entry(cd, &table->hash[hash(table, cid)], lh_bucket) {
		if (cd->cid == cid) {
			list_move_tail(&cd->lh_lru, &table->lru);
			return cd;
		}
	}
	return NULL;
}

/**
 * __chunkdata_invalidate - mark the specified @cd invalid
 *
 * This function marks the specified &struct chunkdata as invalid and ready 
 * for reuse by another chunk.  Returns 1 on success, or 0 if the
 * given &chunkdata cannot be invalidated because it is not idle or has
 * pending work against it.  Does not update the LRU list.
 **/
static int __chunkdata_invalidate(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));

	if (!list_empty(&cd->pending) || !is_idle_state(cd->state))
		return 0;
	if (cd->state == ST_ENCRYPTED)
		cd->table->dev->stats.encrypted_discards++;
	list_del_init(&cd->lh_bucket);
	cd->flags=0;
	transition(cd, ST_INVALID);
	return 1;
}

/**
 * chunkdata_reclaim - get a &struct chunkdata for the specified @cid
 *
 * chunkdata_reclaim() will allocate a new &struct chunkdata for @cid by
 * recycling the LRU &chunkdata which does not have work pending against
 * it. If this is not possible (not an infrequent occurrence!) it
 * returns NULL.
 *
 * Caller has to make sure there is not an existing &struct chunkdata for
 * @cid by first checking with chunkdata_find().
 **/
static struct chunkdata *chunkdata_reclaim(struct chunkdata_table *table,
			chunk_t cid)
{
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&table->dev->lock));

	list_for_each_entry(cd, &table->lru, lh_lru) {
		if (!__chunkdata_invalidate(cd))
			continue;
		list_add(&cd->lh_bucket, &table->hash[hash(table, cid)]);
		list_move_tail(&cd->lh_lru, &table->lru);
		cd->cid=cid;
		return cd;
	}
	
	/* Can't get a chunk */
	debug(DBG_CD, "Can't get cd for " SECTOR_FORMAT, cid);
	table->dev->stats.cache_alloc_failures++;
	return NULL;
}

/**
 * chunkdata_invalidate_all - debug function to invalidate all idle &chunkdata
 *
 * Walk the &struct chunkdata LRU list and invalidate every &chunkdata which
 * is idle and has no work queued against it.  Invalidated chunks are moved
 * to the head of the LRU list.
 **/
void chunkdata_invalidate_all(struct nexus_dev *dev)
{
	struct chunkdata_table *table=dev->chunkdata;
	struct chunkdata *cd;
	struct chunkdata *next;

	BUG_ON(!mutex_is_locked(&dev->lock));

	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		if (__chunkdata_invalidate(cd))
			list_move(&cd->lh_lru, &table->lru);
	}
}

/**
 * alloc_scatterlist - create a scatterlist capable of holding @nbytes bytes
 *
 * alloc_scatterlist() creates and returns a scatterlist capable of holding
 * exactly @nbytes bytes.  Both the &struct scatterlist array and the pages
 * themselves are allocated.  Each page except the last is fully utilized
 * (i.e., offset == 0 and length == PAGE_SIZE), and the last page will have
 * offset == 0; this sort of scatterlist is referred to elsewhere as a
 * "chunkdata scatterlist".  Allocated pages may be in high memory and thus
 * may not have a kernel mapping.
 * 
 * On error, NULL is returned.
 **/
struct scatterlist *alloc_scatterlist(unsigned nbytes)
{
	struct scatterlist *sg;
	struct page *page;
	unsigned npages=(nbytes + PAGE_SIZE - 1) / PAGE_SIZE;
	unsigned residual;
	int i;
	
	sg=kmalloc(npages * sizeof(*sg), GFP_KERNEL);
	if (sg == NULL)
		return NULL;
	sg_init_table(sg, npages);
	for (i=0; i<npages; i++) {
		page=alloc_page(GFP_KERNEL | __GFP_HIGHMEM);
		if (page == NULL)
			goto bad;
		sg_set_page(&sg[i], page, PAGE_SIZE, 0);
	}
	/* Possible partial last page */
	residual=nbytes % PAGE_SIZE;
	if (residual)
		sg[npages-1].length=residual;
	return sg;
	
bad:
	while (--i >= 0)
		__free_page(sg_page(&sg[i]));
	kfree(sg);
	return NULL;
}

/**
 * free_scatterlist - free a scatterlist allocated with alloc_scatterlist()
 * @nbytes: must be the value previously passed to alloc_scatterlist()
 **/
void free_scatterlist(struct scatterlist *sg, unsigned nbytes)
{
	struct scatterlist *cur;
	
	if (sg == NULL)
		return;
	for (cur=sg; nbytes > 0; cur++) {
		__free_page(sg_page(cur));
		nbytes -= cur->length;
	}
	kfree(sg);
}

/**
 * bio_destructor - free a bio into the bio_pool
 * 
 * This is called by the block layer when a &bio's refcount hits zero.
 **/
static void bio_destructor(struct bio *bio)
{
	bio_free(bio, bio_pool);
}

static void nexus_endio(struct bio *bio, unsigned nbytes, int error, int done);

/**
 * nexus_endio_func - register completion of @bio
 *
 * This is a kernel-version-specific wrapper for nexus_endio(), and is called
 * by the block layer upon completion of a single &bio to the chunk store.
 */
NEXUS_ENDIO_FUNC

/**
 * bio_create - create a &bio to do I/O to the chunk store
 * @cd    : the chunk in question
 * @dir   : %READ or %WRITE
 * @offset: the sector offset into the chunk at which we're starting
 *
 * bio_create() creates a &bio with the appropriate parameters to read or
 * write the chunk store for the given chunk.  Due to restrictions imposed
 * by the device driver of the underlying block device, the &bio may not
 * be large enough to cover the entire chunk.  If this occurs, bio_add_page()
 * calls on the &bio will eventually fail, and bio_create() should be called
 * again with an @offset equal to the number of sectors already associated
 * with a previous &bio.
 *
 * bio_create() never fails; if no memory is available to allocate the bio, we
 * sleep in bio_alloc_bioset() until it is.
 **/
static struct bio *bio_create(struct chunkdata *cd, int dir, unsigned offset)
{
	struct nexus_dev *dev=cd->table->dev;
	struct bio *bio;
	struct nexus_io_chunk *chunk;
	unsigned pages;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	/* This assumes that every page has a zero offset and every page
	   except the last one has a PAGE_SIZE length; this is true for
	   chunkdata scatterlists but not necessarily for scatterlists received
	   from the block layer.  We subtract off the number of *complete*
	   pages which have already been stuffed into other bios. */
	pages=chunk_pages(dev) - offset / (PAGE_SIZE / 512);
	bio=bio_alloc_bioset(GFP_NOIO, pages, bio_pool);
	bio->bi_bdev=dev->chunk_bdev;
	bio->bi_sector=chunk_to_sector(dev, cd->cid) + dev->offset + offset;
	debug(DBG_IO, "Creating bio: %u pages, sector " SECTOR_FORMAT, pages,
				bio->bi_sector);
	bio->bi_rw=dir;
	if (dir == READ) {
		chunk=pending_head(cd);
		if (chunk != NULL)
			bio_set_prio(bio, chunk->parent->prio);
	}
	bio->bi_end_io=nexus_endio_func;
	bio->bi_private=cd;
	bio->bi_destructor=bio_destructor;
	return bio;
}

/**
 * issue_chunk_io - read or write the given @cd to the chunk store
 *
 * issue_chunk_io() reads @cd from the chunk store if @cd is in %ST_LOAD_DATA
 * and writes it to the chunk store if @cd is in %ST_STORE_DATA.  We always
 * read or write the whole chunk, even if we don't need all of the sectors
 * due to compression.  This ensures that the I/O elevator can still coalesce
 * our requests, which is more important than minimizing the requested
 * sector count since the excess data will be in the disk's track buffer
 * anyway.
 **/
static void issue_chunk_io(struct chunkdata *cd)
{
	struct nexus_dev *dev=cd->table->dev;
	struct bio *bio=NULL;
	unsigned offset=0;
	int i=0;
	int dir;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	
	if (cd->state == ST_LOAD_DATA) {
		dir=READ;
		dev->stats.chunk_reads++;
	} else if (cd->state == ST_STORE_DATA) {
		dir=WRITE;
		dev->stats.chunk_writes++;
		dev->stats.data_bytes_written += cd->size;
	} else {
		BUG();
		return;
	}
	
	cd->error=0;
	atomic_set(&cd->remaining, dev->chunksize);
	
	/* We can't assume that we can fit the entire chunk io in one
	   bio: it depends on the queue restrictions of the underlying
	   device */
	while (offset < dev->chunksize) {
		if (bio == NULL)
			bio=bio_create(cd, dir, offset/512);
		if (bio_add_page(bio, sg_page(&cd->sg[i]),
					cd->sg[i].length,
					cd->sg[i].offset)) {
			offset += cd->sg[i].length;
			i++;
		} else {
			debug(DBG_IO, "Submitting bio: %u/%u", offset,
						dev->chunksize);
			schedule_io(bio);
			bio=NULL;
		}
	}
	BUG_ON(bio == NULL);
	debug(DBG_IO, "Submitting bio: %u/%u", offset, dev->chunksize);
	schedule_io(bio);
}

/**
 * __chunk_tfm - encode or decode a chunk
 * @ts  : per-CPU transform state buffer
 * @cd  : the chunk in question
 * @hash: output value - found tag/key in case of mismatch
 * 
 * If %ST_DECRYPTING, decrypt/decompress the chunk and check its tag and key.
 * If %ST_ENCRYPTING, compress/encrypt the chunk and generate a new tag, key,
 * and length.  Prints messages to the kernel log on failure.
 **/
static nexus_err_t __chunk_tfm(struct nexus_tfm_state *ts,
			struct chunkdata *cd, char hash[])
{
	struct nexus_dev *dev=cd->table->dev;
	unsigned compressed_size;
	int ret;
	const struct tfm_suite_info *info=suite_info(dev->suite);
	unsigned hash_len=info->hash_len;
	int do_crypt=(info->cipher_block > 0);
	
	if (cd->state == ST_DECRYPTING) {
		debug(DBG_TFM, "Decoding %u bytes for chunk " SECTOR_FORMAT,
					cd->size, cd->cid);
		/* Make sure encrypted data matches tag */
		if (crypto_hash(dev, ts, cd->sg, cd->size, hash))
			return NEXUS_ERR_HASH;
		if (memcmp(cd->tag, hash, hash_len))
			return NEXUS_ERR_TAG;
		if (do_crypt) {
			ret=crypto_cipher(dev, ts, cd->sg, cd->key, cd->size,
						READ, cd->compression !=
						NEXUS_COMPRESS_NONE);
			if (ret < 0)
				return NEXUS_ERR_CRYPT;
			compressed_size=ret;
			/* Make sure decrypted data matches key */
			if (crypto_hash(dev, ts, cd->sg, compressed_size,
						hash))
				return NEXUS_ERR_HASH;
			if (memcmp(cd->key, hash, hash_len))
				return NEXUS_ERR_KEY;
		} else {
			compressed_size=cd->size;
		}
		if (decompress_chunk(dev, ts, cd->sg, cd->compression,
					compressed_size))
			return NEXUS_ERR_COMPRESS;
	} else if (cd->state == ST_ENCRYPTING) {
		/* If compression or encryption errors out, we don't try to
		   recover the data because the cd will go into ST_ERROR state
		   anyway and no one will be allowed to read it. */
		ret=compress_chunk(dev, ts, cd->sg, dev->default_compression);
		if (ret == -EFBIG) {
			compressed_size=dev->chunksize;
			cd->compression=NEXUS_COMPRESS_NONE;
		} else if (ret < 0) {
			return NEXUS_ERR_COMPRESS|NEXUS_ERR_IS_WRITE;
		} else {
			compressed_size=ret;
			cd->compression=dev->default_compression;
		}
		if (do_crypt) {
			debug(DBG_TFM, "Encoding %u bytes for chunk "
						SECTOR_FORMAT, compressed_size,
						cd->cid);
			if (crypto_hash(dev, ts, cd->sg, compressed_size,
						cd->key))
				return NEXUS_ERR_HASH|NEXUS_ERR_IS_WRITE;
			ret=crypto_cipher(dev, ts, cd->sg, cd->key,
						compressed_size, WRITE,
						cd->compression !=
						NEXUS_COMPRESS_NONE);
			if (ret < 0)
				return NEXUS_ERR_CRYPT|NEXUS_ERR_IS_WRITE;
			cd->size=ret;
		} else {
			memset(cd->key, 0, sizeof(cd->key));
			cd->size=compressed_size;
		}
		if (crypto_hash(dev, ts, cd->sg, cd->size, cd->tag))
			return NEXUS_ERR_HASH|NEXUS_ERR_IS_WRITE;
	} else {
		BUG();
	}
	return 0;
}

/**
 * chunk_tfm - thread callback for encoding/decoding a chunk
 * @ts   : per-CPU transform state buffer
 * @entry: the list head passed to the thread code
 *
 * Runs in thread context.  Do the chunk transform using per-CPU buffers, with
 * no locks held, and then acquire the dev lock and transition the chunk to
 * the next state.
 **/
void chunk_tfm(struct nexus_tfm_state *ts, struct list_head *entry)
{
	struct chunkdata *cd=container_of(entry, struct chunkdata, lh_need_tfm);
	struct nexus_dev *dev=cd->table->dev;
	char found[NEXUS_MAX_HASH_LEN];
	nexus_err_t err;
	
	/* The actual crypto is done using per-CPU temporary buffers, without
	   the dev lock held, so that multiple CPUs can do crypto in parallel */
	err=__chunk_tfm(ts, cd, found);
	mutex_lock_thread(&dev->lock);
	if (err == NEXUS_ERR_TAG || err == NEXUS_ERR_KEY)
		transition_error_hash(cd, -EIO, err, found);
	else if (err)
		transition_error(cd, -EIO, err);
	else if (cd->state == ST_ENCRYPTING)
		transition(cd, ST_DIRTY_ENCRYPTED);
	else
		transition(cd, ST_CLEAN);
	update_chunk(cd);
	mutex_unlock(&dev->lock);
}

/**
 * chunkdata_complete_io - thread callback on completion of chunk store I/O
 * @entry: the list head passed to the thread code
 *
 * Runs in thread context.  Called when all bios associated with the given
 * chunk have completed.  Transitions the chunk to the next state and logs
 * I/O errors.
 **/
void chunkdata_complete_io(struct list_head *entry)
{
	struct chunkdata *cd=container_of(entry, struct chunkdata,
				lh_pending_completion);
	struct chunkdata_table *table=cd->table;
	struct nexus_dev *dev=table->dev;
	nexus_err_t err;
	
	mutex_lock_thread(&dev->lock);
	if (cd->error) {
		log_limit(KERN_ERR, "I/O error %s chunk " SECTOR_FORMAT,
					cd->state == ST_LOAD_DATA ?
					"reading" : "writing", cd->cid);
		err=NEXUS_ERR_IO;
		if (cd->state == ST_STORE_DATA)
			err |= NEXUS_ERR_IS_WRITE;
		transition_error(cd, cd->error, err);
	} else if (cd->state == ST_LOAD_DATA) {
		transition(cd, ST_ENCRYPTED);
	} else if (cd->state == ST_STORE_DATA) {
		transition(cd, ST_DIRTY_META);
	} else {
		BUG();
	}
	update_chunk(cd);
	mutex_unlock(&dev->lock);
}

/**
 * nexus_endio - register completion of @bio
 * 
 * The block layer calls nexus_endio_func() upon completion of a single &bio
 * to the chunk store.  nexus_endio_func(), in turn, is a kernel-version-
 * specific wrapper for this function.  Depending on the device driver for
 * the chunk store, this may be called in hardirq context.  Arranges for
 * chunkdata_complete_io() callback to be called once all of the I/O for the
 * chunk has completed.
 **/
static void nexus_endio(struct bio *bio, unsigned nbytes, int error, int done)
{
	struct chunkdata *cd=bio->bi_private;
	
	debug(DBG_IO, "Completed bio: %u bytes, error %d", nbytes, error);
	if (error && !cd->error) {
		/* Racy, but who cares */
		cd->error=error;
	}
	if (atomic_sub_and_test(nbytes, &cd->remaining)) {
		/* Can't call BUG() in interrupt */
		WARN_ON(!list_empty(&cd->lh_pending_completion));
		schedule_callback(CB_COMPLETE_IO, &cd->lh_pending_completion);
	}
	if (done)
		bio_put(bio);
}

/**
 * io_has_reservation - returns true if @io is ready to be processed
 * 
 * Returns true if all chunks in the io are either at the front of their
 * pending queues or have already been unreserved, or false if at least one
 * chunk is not at head-of-queue.
 **/
static int io_has_reservation(struct nexus_io *io)
{
	struct nexus_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!mutex_is_locked(&io->dev->lock));
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		/* CHUNK_STARTED is an optimization: if set, we know it's
		   head-of-queue so we don't need to do the lookup */
		if ((chunk->flags & CHUNK_DEAD) ||
					(chunk->flags & CHUNK_STARTED))
			continue;
		cd=chunkdata_find(io->dev->chunkdata, chunk->cid);
		if (cd == NULL || !pending_head_is(cd, chunk))
			return 0;
	}
	return 1;
}

/**
 * try_start_io - try to make progress on @io
 * 
 * We cannot do anything with @io if another &nexus_io is ahead of us in line
 * for any of the constituent chunks of @io.  (This preserves read- and
 * write-ordering for multiple requests on the same chunk.)  Otherwise, for
 * each &nexus_io_chunk in @io which has not already been processed, if the
 * &chunkdata is in a state such that we can perform the requisite read or
 * write, we mark the &nexus_io_chunk "started" and call into the request-queue
 * interface code to perform the actual copy.  Once all chunks in @io have
 * been completed, we free the io.
 **/
static void try_start_io(struct nexus_io *io)
{
	struct nexus_dev *dev=io->dev;
	struct nexus_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	int dead;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	
	/* See if this io can run yet at all. */
	if (!io_has_reservation(io))
		return;
	
	/* Start any chunks which can run and haven't been started yet. */
	for (i=0, dead=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if (chunk->flags & CHUNK_DEAD)
			dead++;
		if ((chunk->flags & CHUNK_DEAD) ||
					(chunk->flags & CHUNK_STARTED))
			continue;
		cd=chunkdata_find(dev->chunkdata, chunk->cid);
		BUG_ON(cd == NULL);
		
		switch (cd->state) {
		case ST_INVALID:
		case ST_ENCRYPTED:
			if (chunk->flags & CHUNK_READ)
				continue;
			else
				transition(cd, ST_DIRTY);
			break;
		case ST_ERROR:
			if (chunk->flags & CHUNK_READ)
				chunk->error=cd->error;
			else
				transition(cd, ST_DIRTY);
			break;
		case ST_ERROR_USER:
		case ST_ERROR_PENDING:
			if (chunk->flags & CHUNK_READ)
				chunk->error=cd->error;
			else
				continue;
			break;
		case ST_CLEAN:
			if (io->flags & IO_WRITE)
				transition(cd, ST_DIRTY);
			break;
		case ST_DIRTY:
			break;
		default:
			continue;
		}
		if ((io->flags & IO_WRITE) && dev_is_shutdown(dev)) {
			/* Won't be able to do writeback. */
			chunk->error=-EIO;
			/* Subsequent reads to this chunk must not be allowed
			   to return stale data. */
			transition_error(cd, -EIO, 0);
		}
		
		if (!(chunk->flags & CHUNK_READ))
			dev->stats.whole_chunk_updates++;
		chunk->flags |= CHUNK_STARTED;
		nexus_process_chunk(&io->chunks[i], cd->sg);
		if (chunk->flags & CHUNK_DEAD)
			dead++;
	}
	if (io_chunks(io) == dead)
		nexus_free_io(io);
}

/**
 * queue_for_user - arrange for @cd metadata to be passed to/from userspace
 *
 * Returns -EIO if the chardev is already shut down.
 **/
static int queue_for_user(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(!list_empty(&cd->lh_user));
	BUG_ON(cd->state != ST_LOAD_META && cd->state != ST_STORE_META &&
				cd->state != ST_ERROR_PENDING);
	if (dev_is_shutdown(cd->table->dev))
		return -EIO;
	list_add_tail(&cd->lh_user, &cd->table->user);
	wake_up_interruptible(&cd->table->dev->waiting_users);
	return 0;
}

/**
 * have_usermsg - returns false if the usermsg queue has no pending entries
 **/
int have_usermsg(struct nexus_dev *dev)
{
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	list_for_each_entry(cd, &dev->chunkdata->user, lh_user) {
		if (cd->flags & CD_USER)
			continue;
		else
			return 1;
	}
	return 0;
}

/**
 * next_usermsg - retrieve the next pending entry in the usermsg queue
 * 
 * Returns a pointer to the &struct chunkdata corresponding to the selected
 * entry, or NULL if there are no pending entries.  @*type is filled in
 * with the message type of the selected entry.  The &chunkdata pointer is
 * used as an opaque cookie by the chardev code (since &struct chunkdata
 * is static to this file) to retrieve the details of the particular message
 * using the get_usermsg_*() family of functions.
 * 
 * The selected entry is not removed from the usermsg queue, but marked with
 * the %CD_USER flag.  This allows us to reinsert the entry if the chardev code
 * later discovers that the buffer passed to the read() syscall is invalid, and
 * also allows us to validate that replies coming from userspace do in fact
 * correspond to pending usermsgs.
 **/
struct chunkdata *next_usermsg(struct nexus_dev *dev, msgtype_t *type)
{
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	list_for_each_entry(cd, &dev->chunkdata->user, lh_user) {
		if (cd->flags & CD_USER)
			continue;
		cd->flags |= CD_USER;
		if (cd->state == ST_LOAD_META)
			*type=NEXUS_MSGTYPE_GET_META;
		else if (cd->state == ST_STORE_META)
			*type=NEXUS_MSGTYPE_UPDATE_META;
		else if (cd->state == ST_ERROR_PENDING)
			*type=NEXUS_MSGTYPE_CHUNK_ERR;
		else
			BUG();
		return cd;
	}
	return NULL;
}

/**
 * fail_usermsg - revert the @cd usermsg to pending state
 * 
 * This is called by the chardev code when it discovers that the usermsg it
 * has just retrieved to write to userspace, cannot be written to userspace,
 * because userspace gave us an invalid buffer to write into.
 **/
void fail_usermsg(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(!(cd->flags & CD_USER));
	cd->flags &= ~CD_USER;
}

/**
 * __end_usermsg - internal function to remove a usermsg from the queue
 * 
 * This just abstracts out some common code.
 **/
static void __end_usermsg(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(list_empty(&cd->lh_user));
	cd->flags &= ~CD_USER;
	list_del_init(&cd->lh_user);
	update_chunk(cd);
}

/**
 * end_usermsg - report completion on usermsgs that don't require a reply
 *
 * This is called by the chardev code when a usermsg has successfully been
 * copied to userspace, for usermsgs which do NOT require a reply from
 * userspace.  Others should be completed through the per-message functions
 * provided.
 **/
void end_usermsg(struct chunkdata *cd)
{
	BUG_ON(!(cd->flags & CD_USER));
	switch (cd->state) {
	case ST_STORE_META:
		/* We encrypted the data in-place to do write-back, and if
		   we won't need this chunk again there's no point in wasting
		   cycles decrypting it */
		transition(cd, ST_ENCRYPTED);
		__end_usermsg(cd);
		break;
	case ST_ERROR_PENDING:
		__transition(cd, ST_ERROR);
		__end_usermsg(cd);
		break;
	default:
		BUG();
	}
}

/**
 * shutdown_usermsg - error out all usermsgs in the queue (pending or not)
 * 
 * This should be used during the chardev shutdown process, *after* new
 * usermsgs have been prevented from entering the queue, to ensure that
 * messages already in-queue are removed from limbo (since they'd never
 * be processed otherwise).
 **/
void shutdown_usermsg(struct nexus_dev *dev)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	BUG_ON(!dev_is_shutdown(dev));
	list_for_each_entry_safe(cd, next, &dev->chunkdata->user, lh_user) {
		transition_error(cd, -EIO, 0);
		__end_usermsg(cd);
	}
}

/**
 * get_usermsg_get_meta - accessor for GET_META usermsg fields
 **/
void get_usermsg_get_meta(struct chunkdata *cd, unsigned long long *cid)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(cd->state != ST_LOAD_META);
	*cid=cd->cid;
}

/**
 * get_usermsg_update_meta - accessor for UPDATE_META usermsg fields
 **/
void get_usermsg_update_meta(struct chunkdata *cd, unsigned long long *cid,
			unsigned *length, enum nexus_compress *compression,
			char key[], char tag[])
{
	unsigned hash_len=suite_info(cd->table->dev->suite)->hash_len;
	
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(cd->state != ST_STORE_META);
	*cid=cd->cid;
	*length=cd->size;
	*compression=cd->compression;
	memcpy(key, cd->key, hash_len);
	memcpy(tag, cd->tag, hash_len);
}

/**
 * get_usermsg_get_error - accessor for CHUNK_ERR usermsg fields
 **/
void get_usermsg_get_error(struct chunkdata *cd, unsigned long long *cid,
			nexus_err_t *errtype, char expected[], char found[])
{
	unsigned hash_len=suite_info(cd->table->dev->suite)->hash_len;
	
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(cd->state != ST_ERROR_PENDING);
	*cid=cd->cid;
	*errtype=cd->errtype;
	if (cd->errtype == NEXUS_ERR_TAG) {
		memcpy(expected, cd->tag, hash_len);
		memcpy(found, cd->found, hash_len);
	} else if (cd->errtype == NEXUS_ERR_KEY) {
		memcpy(expected, cd->key, hash_len);
		memcpy(found, cd->found, hash_len);
	}
}

/**
 * set_usermsg_set_meta - report completion on GET_META usermsg
 * 
 * GET_META messages sent to userspace produce either a SET_META or META_ERR
 * reply.  The chardev code calls this function when a SET_META message is
 * received from userspace.
 **/
void set_usermsg_set_meta(struct nexus_dev *dev, chunk_t cid, unsigned length,
			enum nexus_compress compression, char key[],
			char tag[])
{
	struct chunkdata *cd;
	unsigned hash_len=suite_info(dev->suite)->hash_len;
	static int warn_count;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_find(dev->chunkdata, cid);
	if (cd == NULL || !(cd->flags & CD_USER) ||
				cd->state != ST_LOAD_META) {
		/* Userspace is messing with us. */
		if (++warn_count < 10)
			log(KERN_WARNING, "Pid %d responded to nonexistent "
					"query for chunk " SECTOR_FORMAT " "
					"metadata", current->pid, cid);
		return;
	}
	cd->size=length;
	cd->compression=compression;
	memcpy(cd->key, key, hash_len);
	memcpy(cd->tag, tag, hash_len);
	transition(cd, ST_META);
	__end_usermsg(cd);
}

/**
 * set_usermsg_meta_err - report error completion on GET_META usermsg
 * 
 * GET_META messages sent to userspace produce either a SET_META or META_ERR
 * reply.  The chardev code calls this function when a META_ERR message is
 * received from userspace, which occurs when userspace can't produce the
 * chunk.  The chunk will go into error state as a result.
 **/
void set_usermsg_meta_err(struct nexus_dev *dev, chunk_t cid)
{
	struct chunkdata *cd;
	static int warn_count;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_find(dev->chunkdata, cid);
	if (cd == NULL || !(cd->flags & CD_USER) ||
				cd->state != ST_LOAD_META) {
		/* Userspace is messing with us. */
		if (++warn_count < 10)
			log(KERN_WARNING, "Pid %d returned error to "
					"nonexistent query for chunk "
					SECTOR_FORMAT "metadata", current->pid,
					cid);
		return;
	}
	transition_error(cd, -EIO, 0);
	__end_usermsg(cd);
}

/**
 * __run_chunk - try to make a transition in the @cd state machine
 *
 * This is the core state machine code.
 * 
 * The state list contains four types of states.  Stable states (which we
 * call "idle" states) are those in which a chunk can rest indefinitely if
 * no I/O is submitted against it.  Unstable states are those in which work
 * such as I/O, crypto, or userspace interaction is scheduled or in progress.
 * The other states are metastable, meaning that they are intermediate states
 * in a series of actions which must be done on a chunk (e.g., in between
 * encrypting a chunk and writing it back to disk, there is a metastable
 * state called %ST_DIRTY_ENCRYPTED).
 *
 * The fourth type is the error state.  All chunks in this state stay there
 * until they have aged out of the chunkdata cache or until their data is
 * overwritten in a single I/O.  (This last limitation is due to the fact that
 * we currently have no infrastructure for tracking which *parts* of a chunk
 * have been updated.)
 *
 * If __run_chunk() is called on a chunk in unstable state, it will do nothing.
 * If the chunk is in metastable state, it will transition it to the
 * appropriate unstable or metastable state and arrange for the corresponding
 * work to be done.  If it is in stable state but I/O is pending to the chunk,
 * then it will likewise transition to the appropriate state and arrange for
 * the work to be done.
 *
 * The various thread callbacks which perform the actual work each end their
 * processing by transitioning to an appropriate state (stable, metastable,
 * or error; never directly to another unstable state) and calling
 * update_chunk(), which arranges for this function to be run from a thread
 * callback.
 **/
static void __run_chunk(struct chunkdata *cd)
{
	struct nexus_io_chunk *chunk;
	
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	chunk=pending_head(cd);
	
again:
	switch (cd->state) {
	case ST_INVALID:
		if (chunk != NULL) {
			/* No key or data */
			if (chunk->flags & CHUNK_READ) {
				debug(DBG_CD, "Requesting key for chunk "
							SECTOR_FORMAT, cd->cid);
				transition(cd, ST_LOAD_META);
				if (queue_for_user(cd)) {
					transition_error(cd, -EIO, 0);
					goto again;
				}
			} else {
				try_start_io(chunk->parent);
			}
		}
		break;
	case ST_LOAD_META:
		break;
	case ST_META:
		/* Have metadata but not data */
		
		/* Right now, this is not a stable state; we should only get
		   here if we're going right to LOAD_DATA.  If this changes,
		   is_idle_state() and refcounting will need to be revisited. */
		BUG_ON(chunk == NULL);
		BUG_ON(!(chunk->flags & CHUNK_READ));
		
		/* The first-in-queue needs the chunk read in. */
		debug(DBG_CD, "Reading in chunk " SECTOR_FORMAT, cd->cid);
		transition(cd, ST_LOAD_DATA);
		issue_chunk_io(cd);
		break;
	case ST_LOAD_DATA:
		break;
	case ST_ENCRYPTED:
		/* Have metadata and encrypted data */
		if (chunk != NULL) {
			if (chunk->flags & CHUNK_READ) {
				/* The first-in-queue needs to be able to
				   read the chunk */
				transition(cd, ST_DECRYPTING);
				schedule_callback(CB_CRYPTO, &cd->lh_need_tfm);
			} else {
				try_start_io(chunk->parent);
			}
		}
		break;
	case ST_DECRYPTING:
		break;
	case ST_CLEAN:
		/* Have metadata and data */
		if (chunk != NULL)
			try_start_io(chunk->parent);
		break;
	case ST_DIRTY:
		/* Have metadata and data */
		if (chunk != NULL) {
			try_start_io(chunk->parent);
		} else {
			transition(cd, ST_ENCRYPTING);
			schedule_callback(CB_CRYPTO, &cd->lh_need_tfm);
		}
	case ST_ENCRYPTING:
		break;
	case ST_DIRTY_ENCRYPTED:
		/* Data is dirty and encryption has finished */
		debug(DBG_CD, "Writing out chunk " SECTOR_FORMAT, cd->cid);
		transition(cd, ST_STORE_DATA);
		issue_chunk_io(cd);
		break;
	case ST_STORE_DATA:
		break;
	case ST_DIRTY_META:
		/* We just wrote out data but haven't written out metadata
		   yet.  We can't do anything else with this chunk until
		   we write out metadata. */
		transition(cd, ST_STORE_META);
		if (queue_for_user(cd)) {
			transition_error(cd, -EIO, 0);
			goto again;
		}
		break;
	case ST_STORE_META:
		break;
	case ST_ERROR_USER:
		/* We have an I/O error that needs to be queued for
		   userspace. */
		__transition(cd, ST_ERROR_PENDING);
		if (queue_for_user(cd))
			__transition(cd, ST_ERROR);
		/* Fall through */
	case ST_ERROR_PENDING:
	case ST_ERROR:
		/* I/O error occurred; data not valid */
		if (chunk != NULL)
			try_start_io(chunk->parent);
		break;
	case NR_STATES:
		BUG();
	}
}

/**
 * run_chunk - thread callback for state machine processing
 * @entry: the list head passed to the thread code
 *
 * This is the thread callback corresponding to __run_chunk().  It processes
 * the given chunk through __run_chunk() and then, if appropriate, releases
 * the chunkdata dev reference.
 **/
void run_chunk(struct list_head *entry)
{
	struct chunkdata *cd=container_of(entry, struct chunkdata,
				lh_need_update);
	struct chunkdata_table *table=cd->table;
	struct nexus_dev *dev=table->dev;
	int need_release=0;
	
	mutex_lock_thread(&dev->lock);
	__run_chunk(cd);
	table->pending_updates--;
	if (table->busy_count == 0 && table->pending_updates == 0) {
		if (test_and_clear_bit(__DEV_HAVE_CD_REF, &dev->flags)) {
			wake_up_interruptible_all(&dev->waiting_idle);
			need_release=1;
		}
	}
	mutex_unlock(&dev->lock);
	if (need_release)
		nexus_dev_put(dev, 0);
}

/**
 * run_all_chunks - debug function to run every chunk through the state machine
 * 
 * Only for debugging via sysfs attribute!  This causes redundant processing
 * of all chunks through __run_chunk().  This should be harmless, but may be
 * useful if the state machine wedges.
 **/
void run_all_chunks(struct nexus_dev *dev)
{
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	log(KERN_NOTICE, "Unwedging chunk cache");
	if (!test_and_set_bit(__DEV_HAVE_CD_REF, &dev->flags))
		nexus_dev_get(dev);
	list_for_each_entry(cd, &dev->chunkdata->lru, lh_lru)
		update_chunk(cd);
}

/**
 * reserve_chunks - enqueue every &nexus_io_chunk in @io for processing
 * 
 * Called by request queue code to inject a new &nexus_io into the chunkdata
 * queues.  reserve_chunks() places each chunk in @io at the end of the queue
 * for its corresponding &chunkdata.  When each io_chunk reaches the
 * head of the line for that chunk, and the chunk is ready to exchange data,
 * the request queue code will receive a nexus_process_chunk() call for that
 * io_chunk.
 *
 * The chunkdata code always maintains a dev reference whenever there are
 * chunks pending for __run_chunk() or chunks in non-idle state.  That
 * reference is acquired here and released in run_chunk().
 *
 * reserve_chunks() may return an error if it is unable to get a &chunkdata
 * structure for each &nexus_io_chunk in @io.  This may happen frequently
 * during heavy I/O load.  The request queue code should perform out-of-memory
 * throttling in that case and try again later.
 **/
int reserve_chunks(struct nexus_io *io)
{
	struct nexus_dev *dev=io->dev;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	/* First pin down any chunkdata entry that's already in the cache */
	for (i=0; i<io_chunks(io); i++) {
		cd=chunkdata_find(dev->chunkdata, io->first_cid + i);
		if (cd == NULL)
			continue;
		list_add_tail(&io->chunks[i].lh_pending, &cd->pending);
		user_get(dev);
	}
	/* Now allocate new entries */
	for (i=0; i<io_chunks(io); i++) {
		if (!list_empty(&io->chunks[i].lh_pending))
			continue;
		cd=chunkdata_reclaim(dev->chunkdata, io->first_cid + i);
		if (cd == NULL)
			goto bad;
		list_add_tail(&io->chunks[i].lh_pending, &cd->pending);
		user_get(dev);
	}
	if (!test_and_set_bit(__DEV_HAVE_CD_REF, &dev->flags))
		nexus_dev_get(dev);
	for (i=0; i<io_chunks(io); i++) {
		cd=chunkdata_find(dev->chunkdata, io->first_cid + i);
		BUG_ON(cd == NULL);
		if (cd->state == ST_INVALID &&
					pending_head(cd) == &io->chunks[i])
			dev->stats.cache_misses++;
		else
			dev->stats.cache_hits++;
		update_chunk(cd);
	}
	return 0;

bad:
	for (i=0; i<io_chunks(io); i++) {
		if (!list_empty(&io->chunks[i].lh_pending)) {
			list_del_init(&io->chunks[i].lh_pending);
			user_put(dev);
		}
	}
	/* XXX this isn't strictly nomem */
	return -ENOMEM;
}

/**
 * unreserve_chunk - release chunk reservation after the @chunk has completed
 **/
void unreserve_chunk(struct nexus_io_chunk *chunk)
{
	struct nexus_dev *dev=chunk->parent->dev;
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_find(dev->chunkdata, chunk->cid);
	BUG_ON(cd == NULL || !pending_head_is(cd, chunk));
	list_del_init(&chunk->lh_pending);
	user_put(dev);
	update_chunk(cd);
}

/**
 * chunkdata_alloc_table - allocate chunkdata state for new device @dev
 *
 * Does not back out allocations on failure, since the @dev dtr will just
 * call chunkdata_free_table() anyway.
 **/
int chunkdata_alloc_table(struct nexus_dev *dev)
{
	struct chunkdata_table *table;
	struct chunkdata *cd;
	unsigned buckets=dev->cachesize;  /* XXX is this reasonable? */
	u64 curtime=current_time_usec();
	int i;
	
	table=kzalloc(sizeof(*table), GFP_KERNEL);
	if (table == NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&table->lru);
	INIT_LIST_HEAD(&table->user);
	table->dev=dev;
	dev->chunkdata=table;
	/* Allocation failures after this point will result in a
	   partially-built structure which will be cleaned up by
	   chunkdata_free_table().  Be careful of initialization order
	   when modifying */
	
	table->hash=kmalloc(buckets * sizeof(table->hash[0]), GFP_KERNEL);
	if (table->hash == NULL)
		return -ENOMEM;
	table->buckets=buckets;
	for (i=0; i<buckets; i++)
		INIT_LIST_HEAD(&table->hash[i]);
	
	for (i=0; i<dev->cachesize; i++) {
		/* We don't use a lookaside cache for struct cachedata because
		   they don't come and go; we pre-allocate and then they sit
		   around. */
		cd=kzalloc(sizeof(*cd), GFP_KERNEL);
		if (cd == NULL)
			return -ENOMEM;
		cd->table=table;
		cd->state=ST_INVALID;
		cd->state_begin=curtime;
		INIT_LIST_HEAD(&cd->lh_bucket);
		INIT_LIST_HEAD(&cd->lh_lru);
		INIT_LIST_HEAD(&cd->lh_user);
		INIT_LIST_HEAD(&cd->lh_need_update);
		INIT_LIST_HEAD(&cd->lh_pending_completion);
		INIT_LIST_HEAD(&cd->lh_need_tfm);
		INIT_LIST_HEAD(&cd->pending);
		list_add(&cd->lh_lru, &table->lru);
		cd->sg=alloc_scatterlist(dev->chunksize);
		if (cd->sg == NULL)
			return -ENOMEM;
	}
	dev->stats.state_count[ST_INVALID]=dev->cachesize;
	return 0;
}

/**
 * chunkdata_free_table - release chunkdata state for @dev
 *
 * This is called unconditionally by the dtr, so it must be able to handle
 * unallocated or partially allocated chunkdata structures.
 **/
void chunkdata_free_table(struct nexus_dev *dev)
{
	struct chunkdata_table *table=dev->chunkdata;
	struct chunkdata *cd;
	struct chunkdata *next;
	
	if (table == NULL)
		return;
	BUG_ON(!list_empty(&table->user));
	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		BUG_ON(!list_empty(&cd->pending));
		BUG_ON(!is_idle_state(cd->state));
		list_del(&cd->lh_bucket);
		list_del(&cd->lh_lru);
		free_scatterlist(cd->sg, dev->chunksize);
		memset(cd->key, 0, sizeof(cd->key));
		kfree(cd);
	}
	kfree(table->hash);
	kfree(table);
}

/**
 * chunkdata_start - module initialization for chunkdata
 **/
int __init chunkdata_start(void)
{
	/* We need to ensure that we can always allocate enough to complete
	   one io, which may require multiple requests to the backing device
	   (depending on its queue limits).  So, these values depend on the
	   queue properties of the backing device and the number of Nexus
	   devices competing for allocations.  We just pick numbers that seem
	   to have enough headroom. */
	/* XXX further io could still block in bio_create(), preventing
	   completed requests from being processed by the worker thread */
	bio_pool=bioset_create(4 * MIN_CONCURRENT_REQS,
				4 * MIN_CONCURRENT_REQS);
	if (bio_pool == NULL)
		return -ENOMEM;
	
	return 0;
}

/**
 * chunkdata_shutdown - module de-initialization for chunkdata
 **/
void chunkdata_shutdown(void)
{
	bioset_free(bio_pool);
}
