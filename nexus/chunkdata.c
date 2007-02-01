#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/bio.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/wait.h>
#include "defs.h"

/* XXX rename all this */

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
	ST_ERROR,            /* I/O error occurred; data not valid */
	NR_STATES
};

struct chunkdata {
	struct list_head lh_bucket;
	struct list_head lh_lru;
	struct list_head lh_user;
	struct list_head lh_need_update;
	struct list_head lh_pending_completion;
	struct list_head lh_need_tfm;
	struct chunkdata_table *table;
	chunk_t cid;
	unsigned size;                   /* encrypted size including padding */
	enum nexus_compress compression; /* compression type */
	struct list_head pending;
	atomic_t remaining;              /* bytes, for I/O */
	int error;
	unsigned flags;
	enum cd_state state;
	u64 state_begin;                 /* usec since epoch */
	char key[NEXUS_MAX_HASH_LEN];
	char tag[NEXUS_MAX_HASH_LEN];
	struct scatterlist *sg;
};

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


static u64 current_time_usec(void)
{
	struct timeval curtime;
	
	do_gettimeofday(&curtime);
	return curtime.tv_sec * USEC_PER_SEC + curtime.tv_usec;
}

static inline unsigned hash(struct chunkdata_table *table, chunk_t cid)
{
	return (unsigned)cid % table->buckets;
}

static inline struct nexus_io_chunk *pending_head(struct chunkdata *cd)
{
	if (list_empty(&cd->pending))
		return NULL;
	return list_entry(cd->pending.next, struct nexus_io_chunk, lh_pending);
}

static inline int pending_head_is(struct chunkdata *cd,
			struct nexus_io_chunk *chunk)
{
	if (list_empty(&cd->pending))
		return 0;
	return (pending_head(cd) == chunk);
}

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

static void chunkdata_hit(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	list_move_tail(&cd->lh_lru, &cd->table->lru);
}

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

static void transition(struct chunkdata *cd, enum cd_state new_state)
{
	BUG_ON(new_state == ST_ERROR);
	__transition(cd, new_state);
}

static void transition_error(struct chunkdata *cd, int error)
{
	cd->error=error;
	cd->table->dev->stats.chunk_errors++;
	__transition(cd, ST_ERROR);
}

static void update_chunk(struct chunkdata *cd)
{
	struct chunkdata_table *table=cd->table;
	
	BUG_ON(!mutex_is_locked(&table->dev->lock));
	if (!list_empty(&cd->lh_need_update))
		return;
	table->pending_updates++;
	schedule_callback(CB_UPDATE_CHUNK, &cd->lh_need_update);
}

static struct chunkdata *chunkdata_get(struct chunkdata_table *table,
			chunk_t cid)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	BUG_ON(!mutex_is_locked(&table->dev->lock));
	
	/* See if the chunk is in the table already */
	list_for_each_entry(cd, &table->hash[hash(table, cid)], lh_bucket) {
		if (cd->cid == cid) {
			chunkdata_hit(cd);
			return cd;
		}
	}
	
	/* Steal the LRU chunk */
	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		if (!list_empty(&cd->pending) || !is_idle_state(cd->state))
			continue;
		
		if (cd->state == ST_ENCRYPTED)
			table->dev->stats.encrypted_discards++;
		list_del_init(&cd->lh_bucket);
		list_add(&cd->lh_bucket, &table->hash[hash(table, cid)]);
		chunkdata_hit(cd);
		cd->cid=cid;
		cd->flags=0;
		transition(cd, ST_INVALID);
		return cd;
	}
	
	/* Can't get a chunk */
	debug(DBG_CD, "Can't get cd for " SECTOR_FORMAT, cid);
	return NULL;
}

/* Allocated buffer pages may be in high memory and thus may not have a
   kernel mapping */
static int alloc_chunk_buffer(struct chunkdata *cd)
{
	struct nexus_dev *dev=cd->table->dev;
	int i;
	unsigned npages=chunk_pages(dev);
	unsigned residual;
	struct scatterlist *sg=NULL;  /* initialization to avoid warning */
	
	BUG_ON(cd->sg != NULL);
	cd->sg=kmalloc(npages * sizeof(cd->sg[0]), GFP_KERNEL);
	if (cd->sg == NULL)
		return -ENOMEM;
	for (i=0; i<npages; i++) {
		sg=&cd->sg[i];
		sg->page=alloc_page(GFP_KERNEL | __GFP_HIGHMEM);
		if (sg->page == NULL)
			goto bad;
		sg->offset=0;
		sg->length=PAGE_SIZE;
	}
	/* Possible partial last page */
	residual=dev->chunksize % PAGE_SIZE;
	if (residual)
		sg->length=residual;
	return 0;
	
bad:
	while (--i >= 0)
		__free_page(cd->sg[i].page);
	kfree(cd->sg);
	return -ENOMEM;
}

static void free_chunk_buffer(struct chunkdata *cd)
{
	struct nexus_dev *dev=cd->table->dev;
	int i;
	
	if (cd->sg == NULL)
		return;
	for (i=0; i<chunk_pages(dev); i++)
		__free_page(cd->sg[i].page);
	kfree(cd->sg);
}

BIO_DESTRUCTOR(bio_destructor, bio_pool)

static int nexus_endio_func(struct bio *bio, unsigned nbytes, int error);
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
	bio=bio_alloc_bioset(GFP_ATOMIC, pages, bio_pool);
	if (bio == NULL)
		return NULL;

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
	bio_set_destructor(bio, bio_destructor);
	return bio;
}

static void chunk_io_make_progress(struct chunkdata *cd, unsigned nbytes);
/* We read or write the whole chunk, even if we don't need all of the sectors
   due to compression.  This ensures that the I/O elevator can still coalesce
   our requests, which is more important than minimizing the requested
   sector count since the excess data will be in the disk's track buffer
   anyway. */
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
	} else {
		BUG();
		return;
	}
	
	cd->error=0;
	atomic_set(&cd->remaining, dev->chunksize);
	
	/* We can't assume that we can fit the entire chunk io in one
	   bio: it depends on the queue restrictions of the underlying
	   device */
	/* XXX is it okay to be failing requests with -ENOMEM?  or should we
	   be doing some sort of retry? */
	while (offset < dev->chunksize) {
		if (bio == NULL) {
			bio=bio_create(cd, dir, offset/512);
			if (bio == NULL)
				goto bad;
		}
		if (bio_add_page(bio, cd->sg[i].page,
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
	return;
	
bad:
	cd->error=-ENOMEM;
	chunk_io_make_progress(cd, dev->chunksize - offset);
}

static void format_hash(char *out, unsigned char *in, unsigned in_len)
{
	int i;
	for (i=0; i<in_len; i++, in++, out += 2)
		sprintf(out, "%.2x", *in);
}

static int __chunk_tfm(struct nexus_tfm_state *ts, struct chunkdata *cd)
{
	struct nexus_dev *dev=cd->table->dev;
	unsigned compressed_size;
	int ret;
	char hash[NEXUS_MAX_HASH_LEN];
	unsigned hash_len=suite_info(dev->suite)->hash_len;
	
	if (cd->state == ST_DECRYPTING) {
		debug(DBG_TFM, "Decrypting %u bytes for chunk " SECTOR_FORMAT,
					cd->size, cd->cid);
		/* Make sure encrypted data matches tag */
		ret=crypto_hash(dev, ts, cd->sg, cd->size, hash);
		if (ret) {
			log_limit(KERN_ERR, "Decrypting chunk " SECTOR_FORMAT
						": Unable to hash encrypted "
						"data", cd->cid);
			return ret;
		}
		if (memcmp(cd->tag, hash, hash_len)) {
			/* Conserve stack space in the common case */
			char expected[2 * hash_len + 1];
			char found[2 * hash_len + 1];
			format_hash(expected, cd->tag, hash_len);
			format_hash(found, hash, hash_len);
			log_limit(KERN_ERR, "Decrypting chunk " SECTOR_FORMAT
						": Expected tag %s, found %s",
						cd->cid, expected, found);
			return -EIO;
		}
		ret=crypto_cipher(dev, ts, cd->sg, cd->key, cd->size, READ,
					cd->compression != NEXUS_COMPRESS_NONE);
		if (ret < 0) {
			/* Conserve stack space in the common case */
			char tag[2 * hash_len + 1];
			format_hash(tag, cd->tag, hash_len);
			log_limit(KERN_ERR, "Decrypting chunk " SECTOR_FORMAT
						": Decryption failed.  Tag: %s",
						cd->cid, tag);
			return ret;
		}
		compressed_size=ret;
		/* Make sure decrypted data matches key */
		ret=crypto_hash(dev, ts, cd->sg, compressed_size, hash);
		if (ret) {
			log_limit(KERN_ERR, "Decrypting chunk " SECTOR_FORMAT
						": Unable to hash decrypted "
						"data", cd->cid);
			return ret;
		}
		if (memcmp(cd->key, hash, hash_len)) {
			/* Conserve stack space in the common case */
			char tag[2 * hash_len + 1];
			format_hash(tag, cd->tag, hash_len);
			log_limit(KERN_ERR, "Decrypting chunk " SECTOR_FORMAT
						": Key doesn't match decrypted "
						"data, tag %s", cd->cid, tag);
			return -EIO;
		}
		ret=decompress_chunk(dev, ts, cd->sg, cd->compression,
					compressed_size);
		if (ret) {
			/* Conserve stack space in the common case */
			char tag[2 * hash_len + 1];
			format_hash(tag, cd->tag, hash_len);
			log_limit(KERN_ERR, "Decrypting chunk " SECTOR_FORMAT
						": Decompression failed.  "
						"Tag: %s", cd->cid, tag);
			return ret;
		}
	} else if (cd->state == ST_ENCRYPTING) {
		/* If compression or encryption errors out, we don't try to
		   recover the data because the cd will go into ST_ERROR state
		   anyway and no one will be allowed to read it. */
		ret=compress_chunk(dev, ts, cd->sg, dev->default_compression);
		if (ret == -EFBIG) {
			compressed_size=dev->chunksize;
			cd->compression=NEXUS_COMPRESS_NONE;
		} else if (ret < 0) {
			log_limit(KERN_ERR, "Encrypting chunk " SECTOR_FORMAT
						": Compression failed",
						cd->cid);
			return ret;
		} else {
			compressed_size=ret;
			cd->compression=dev->default_compression;
		}
		debug(DBG_TFM, "Encrypting %u bytes for chunk "SECTOR_FORMAT,
					compressed_size, cd->cid);
		ret=crypto_hash(dev, ts, cd->sg, compressed_size, cd->key);
		if (ret) {
			log_limit(KERN_ERR, "Encrypting chunk " SECTOR_FORMAT
						": Unable to hash decrypted "
						"data", cd->cid);
			return ret;
		}
		ret=crypto_cipher(dev, ts, cd->sg, cd->key, compressed_size,
					WRITE,
					cd->compression != NEXUS_COMPRESS_NONE);
		if (ret < 0) {
			log_limit(KERN_ERR, "Encrypting chunk " SECTOR_FORMAT
						": Encryption failed", cd->cid);
			return ret;
		}
		cd->size=ret;
		ret=crypto_hash(dev, ts, cd->sg, cd->size, cd->tag);
		if (ret) {
			log_limit(KERN_ERR, "Encrypting chunk " SECTOR_FORMAT
						": Unable to hash encrypted "
						"data", cd->cid);
			return ret;
		}
	} else {
		BUG();
	}
	return 0;
}

/* Runs in thread context */
void chunk_tfm(struct nexus_tfm_state *ts, struct list_head *entry)
{
	struct chunkdata *cd=container_of(entry, struct chunkdata, lh_need_tfm);
	struct nexus_dev *dev=cd->table->dev;
	int err;
	
	/* The actual crypto is done using per-CPU temporary buffers, without
	   the dev lock held, so that multiple CPUs can do crypto in parallel */
	err=__chunk_tfm(ts, cd);
	mutex_lock_thread(&dev->lock);
	if (err)
		transition_error(cd, -EIO);
	else if (cd->state == ST_ENCRYPTING)
		transition(cd, ST_DIRTY_ENCRYPTED);
	else
		transition(cd, ST_CLEAN);
	update_chunk(cd);
	mutex_unlock(&dev->lock);
}

/* Runs in thread context */
void chunkdata_complete_io(struct list_head *entry)
{
	struct chunkdata *cd=container_of(entry, struct chunkdata,
				lh_pending_completion);
	struct chunkdata_table *table=cd->table;
	struct nexus_dev *dev=table->dev;
	
	mutex_lock_thread(&dev->lock);
	if (cd->error) {
		log(KERN_ERR, "I/O error %s chunk " SECTOR_FORMAT,
					cd->state == ST_LOAD_DATA ?
					"reading" : "writing", cd->cid);
		/* XXX arguably we should report write errors to
		   userspace */
		transition_error(cd, cd->error);
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

/* May be called from hardirq context or user context for the same nexus_dev */
static void chunk_io_make_progress(struct chunkdata *cd, unsigned nbytes)
{
	if (atomic_sub_and_test(nbytes, &cd->remaining)) {
		/* Can't call BUG() in interrupt */
		WARN_ON(!list_empty(&cd->lh_pending_completion));
		schedule_callback(CB_COMPLETE_IO, &cd->lh_pending_completion);
	}
}

/* May be called from hardirq context */
static int nexus_endio_func(struct bio *bio, unsigned nbytes, int error)
{
	struct chunkdata *cd=bio->bi_private;
	if (error && !cd->error) {
		/* Racy, but who cares */
		cd->error=error;
	}
	chunk_io_make_progress(cd, nbytes);
	return 0;
}

/* Returns 1 if all chunks in the io are either at the front of their
   pending queues or have already been unreserved */
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
		cd=chunkdata_get(io->dev->chunkdata, chunk->cid);
		if (cd == NULL || !pending_head_is(cd, chunk))
			return 0;
	}
	return 1;
}

static void try_start_io(struct nexus_io *io)
{
	struct nexus_dev *dev=io->dev;
	struct nexus_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	
	/* See if this io can run yet at all. */
	if (!io_has_reservation(io))
		return;
	
	/* Start any chunks which can run and haven't been started yet. */
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if ((chunk->flags & CHUNK_DEAD) ||
					(chunk->flags & CHUNK_STARTED))
			continue;
		cd=chunkdata_get(dev->chunkdata, chunk->cid);
		
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
			transition_error(cd, -EIO);
		}
		
		if (!(chunk->flags & CHUNK_READ))
			dev->stats.whole_chunk_updates++;
		chunk->flags |= CHUNK_STARTED;
		nexus_process_chunk(&io->chunks[i]);
	}
}

/* Returns error if the queue is shut down */
static int queue_for_user(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(!list_empty(&cd->lh_user));
	BUG_ON(cd->state != ST_LOAD_META && cd->state != ST_STORE_META);
	if (dev_is_shutdown(cd->table->dev))
		return -EIO;
	list_add_tail(&cd->lh_user, &cd->table->user);
	wake_up_interruptible(&cd->table->dev->waiting_users);
	return 0;
}

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
		else
			BUG();
		return cd;
	}
	return NULL;
}

void fail_usermsg(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(!(cd->flags & CD_USER));
	cd->flags &= ~CD_USER;
}

static void __end_usermsg(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(list_empty(&cd->lh_user));
	cd->flags &= ~CD_USER;
	list_del_init(&cd->lh_user);
	update_chunk(cd);
}

void end_usermsg(struct chunkdata *cd)
{
	/* chardev.c should only call this on usermsgs which don't require
	   a response from userspace.  Others should be ended through the
	   per-message functions provided. */
	BUG_ON(!(cd->flags & CD_USER));
	switch (cd->state) {
	case ST_STORE_META:
		/* We encrypted the data in-place to do write-back, and if
		   we won't need this chunk again there's no point in wasting
		   cycles decrypting it */
		transition(cd, ST_ENCRYPTED);
		__end_usermsg(cd);
		break;
	default:
		BUG();
	}
}

void shutdown_usermsg(struct nexus_dev *dev)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	BUG_ON(!dev_is_shutdown(dev));
	list_for_each_entry_safe(cd, next, &dev->chunkdata->user, lh_user) {
		transition_error(cd, -EIO);
		__end_usermsg(cd);
	}
}

void get_usermsg_get_meta(struct chunkdata *cd, unsigned long long *cid)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(cd->state != ST_LOAD_META);
	*cid=cd->cid;
}

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

void set_usermsg_set_meta(struct nexus_dev *dev, chunk_t cid, unsigned length,
			enum nexus_compress compression, char key[],
			char tag[])
{
	struct chunkdata *cd;
	unsigned hash_len=suite_info(dev->suite)->hash_len;
	static int warn_count;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, cid);
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

/* Called instead of SET_META when userspace can't produce the chunk */
void set_usermsg_meta_err(struct nexus_dev *dev, chunk_t cid)
{
	struct chunkdata *cd;
	static int warn_count;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, cid);
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
	transition_error(cd, -EIO);
	__end_usermsg(cd);
}

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
					transition_error(cd, -EIO);
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
			transition_error(cd, -EIO);
			goto again;
		}
		break;
	case ST_STORE_META:
		break;
	case ST_ERROR:
		/* I/O error occurred; data not valid */
		if (chunk != NULL)
			try_start_io(chunk->parent);
		break;
	case NR_STATES:
		BUG();
	}
}

/* Thread callback */
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
		if (test_and_clear_bit(__DEV_HAVE_CD_REF, &dev->flags))
			need_release=1;
	}
	mutex_unlock(&dev->lock);
	if (need_release)
		nexus_dev_put(dev, 0);
}

/* Only for debugging via sysfs attribute!  This causes redundant processing
   of all chunks through __run_chunk().  This should be harmless, but may be
   useful if the state machine wedges */
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

int reserve_chunks(struct nexus_io *io)
{
	struct nexus_dev *dev=io->dev;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	for (i=0; i<io_chunks(io); i++) {
		cd=chunkdata_get(dev->chunkdata, io->first_cid + i);
		if (cd == NULL)
			goto bad;
		list_add_tail(&io->chunks[i].lh_pending, &cd->pending);
		user_get(dev);
	}
	if (!test_and_set_bit(__DEV_HAVE_CD_REF, &dev->flags))
		nexus_dev_get(dev);
	for (i=0; i<io_chunks(io); i++) {
		cd=chunkdata_get(dev->chunkdata, io->first_cid + i);
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
	while (--i >= 0) {
		list_del_init(&io->chunks[i].lh_pending);
		user_put(dev);
	}
	/* XXX this isn't strictly nomem */
	return -ENOMEM;
}

void unreserve_chunk(struct nexus_io_chunk *chunk)
{
	struct nexus_dev *dev=chunk->parent->dev;
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, chunk->cid);
	BUG_ON(!pending_head_is(cd, chunk));
	list_del_init(&chunk->lh_pending);
	user_put(dev);
	update_chunk(cd);
}

struct scatterlist *get_scatterlist(struct nexus_io_chunk *chunk)
{
	struct nexus_dev *dev=chunk->parent->dev;
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, chunk->cid);
	BUG_ON(cd == NULL || !pending_head_is(cd, chunk));
	return cd->sg;
}

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
		free_chunk_buffer(cd);
		kfree(cd);
	}
	kfree(table->hash);
	kfree(table);
}

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
		if (alloc_chunk_buffer(cd))
			return -ENOMEM;
	}
	dev->stats.state_count[ST_INVALID]=dev->cachesize;
	return 0;
}

int __init chunkdata_start(void)
{
	/* The second and third parameters are dependent on the contents
	   of bvec_slabs[] in fs/bio.c, and on the chunk size.  Better too
	   high than too low. */
	/* XXX reduce a bit? */
	bio_pool=bioset_create_wrapper(4 * MIN_CONCURRENT_REQS,
				4 * MIN_CONCURRENT_REQS, 4);
	if (IS_ERR(bio_pool))
		return PTR_ERR(bio_pool);
	
	return 0;
}

void __exit chunkdata_shutdown(void)
{
	bioset_free(bio_pool);
}
