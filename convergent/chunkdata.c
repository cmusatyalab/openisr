#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/bio.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include "convergent.h"

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
	ST_CLEAN,            /* Have metadata and data */
	ST_DIRTY,            /* Data is dirty */
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
	struct chunkdata_table *table;
	chunk_t cid;
	unsigned size;         /* compressed size before padding */
	compress_t compression;/* compression type */
	struct list_head pending;
	atomic_t remaining;    /* bytes, for I/O */
	int error;
	unsigned flags;
	enum cd_state state;
	char key[ISR_MAX_HASH_LEN];
	struct scatterlist *sg;
};

struct chunkdata_table {
	struct convergent_dev *dev;
	unsigned buckets;
	unsigned state_count[NR_STATES];
	unsigned busy_count;
	struct list_head lru;
	struct list_head user;
	struct list_head need_update;
	struct list_head pending_completion;
	spinlock_t pending_completion_lock;
	struct list_head *hash;
	struct work_struct cb_run_chunks;
	struct work_struct cb_complete_io;
};

static struct bio_set *bio_pool;


static unsigned hash(struct chunkdata_table *table, chunk_t cid)
{
	return (unsigned)cid % table->buckets;
}

static inline struct convergent_io_chunk *pending_head(struct chunkdata *cd)
{
	if (list_empty(&cd->pending))
		return NULL;
	return list_entry(cd->pending.next, struct convergent_io_chunk,
					lh_pending);
}

static inline int pending_head_is(struct chunkdata *cd,
			struct convergent_io_chunk *chunk)
{
	if (list_empty(&cd->pending))
		return 0;
	return (pending_head(cd) == chunk);
}

static inline int is_idle_state(enum cd_state state)
{
	switch (state) {
	case ST_INVALID:
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
	enum cd_state states[2]={cd->state, new_state};
	int idle[2];
	int i;
	
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	for (i=0; i<2; i++)
		idle[i]=is_idle_state(states[i]);
	if (!idle[0] && idle[1]) {
		user_put(cd->table->dev);
		cd->table->busy_count--;
	}
	if (idle[0] && !idle[1]) {
		user_get(cd->table->dev);
		cd->table->busy_count++;
	}
	cd->table->state_count[cd->state]--;
	cd->table->state_count[new_state]++;
	cd->state=new_state;
}

static void transition(struct chunkdata *cd, enum cd_state new_state)
{
	BUG_ON(new_state == ST_ERROR);
	__transition(cd, new_state);
}

static void transition_error(struct chunkdata *cd, int error)
{
	cd->error=error;
	__transition(cd, ST_ERROR);
}

static void update_chunk(struct chunkdata *cd)
{
	struct chunkdata_table *table=cd->table;
	
	BUG_ON(!mutex_is_locked(&table->dev->lock));
	if (!list_empty(&cd->lh_need_update))
		return;
	list_add_tail(&cd->lh_need_update, &table->need_update);
	/* Ignore return value: if it's already queued, that's fine */
	queue_work(wkqueue, &table->cb_run_chunks);
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
		
		list_del_init(&cd->lh_bucket);
		list_add(&cd->lh_bucket, &table->hash[hash(table, cid)]);
		chunkdata_hit(cd);
		cd->cid=cid;
		cd->flags=0;
		transition(cd, ST_INVALID);
		return cd;
	}
	
	/* Can't get a chunk */
	return NULL;
}

/* Allocated buffer pages may be in high memory and thus may not have a
   kernel mapping */
static int alloc_chunk_buffer(struct chunkdata *cd)
{
	struct convergent_dev *dev=cd->table->dev;
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
	struct convergent_dev *dev=cd->table->dev;
	int i;
	
	if (cd->sg == NULL)
		return;
	for (i=0; i<chunk_pages(dev); i++)
		__free_page(cd->sg[i].page);
	kfree(cd->sg);
}

BIO_DESTRUCTOR(bio_destructor, bio_pool)

static int convergent_endio_func(struct bio *bio, unsigned nbytes, int error);
static struct bio *bio_create(struct chunkdata *cd, int dir, unsigned offset)
{
	struct convergent_dev *dev=cd->table->dev;
	struct bio *bio;
	struct convergent_io_chunk *chunk;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	/* XXX could alloc smaller bios if we're looping */
	bio=bio_alloc_bioset(GFP_ATOMIC, chunk_pages(dev), bio_pool);
	if (bio == NULL)
		return NULL;

	bio->bi_bdev=dev->chunk_bdev;
	bio->bi_sector=chunk_to_sector(dev, cd->cid) + dev->offset + offset;
	ndebug("Creating bio with sector "SECTOR_FORMAT, bio->bi_sector);
	bio->bi_rw=dir;
	if (dir == READ) {
		chunk=pending_head(cd);
		if (chunk != NULL)
			bio_set_prio(bio, chunk->parent->prio);
	}
	bio->bi_end_io=convergent_endio_func;
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
	struct convergent_dev *dev=cd->table->dev;
	struct bio *bio=NULL;
	unsigned offset=0;
	int i=0;
	int dir;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	
	if (cd->state == ST_LOAD_DATA) {
		dir=READ;
	} else if (cd->state == ST_STORE_DATA) {
		dir=WRITE;
	} else {
		BUG();
		return;
	}
	
	cd->error=0;
	atomic_set(&cd->remaining, dev->chunksize);
	
	/* XXX test against very small maximum seg count on target, etc. */
	ndebug("Submitting clone bio(s)");
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
			debug("Submitting multiple bios");
			generic_make_request(bio);
			bio=NULL;
		}
	}
	BUG_ON(bio == NULL);
	generic_make_request(bio);
	return;
	
bad:
	cd->error=-ENOMEM;
	chunk_io_make_progress(cd, dev->chunksize - offset);
}

static int chunk_tfm(struct chunkdata *cd, int type)
{
	struct convergent_dev *dev=cd->table->dev;
	int ret;
	char hash[ISR_MAX_HASH_LEN];
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	if (type == READ) {
		ndebug("Decrypting %u bytes for chunk "SECTOR_FORMAT,
					cd->size, cd->cid);
		ret=crypto_cipher(dev, cd->sg, cd->key, cd->size, READ);
		if (ret)
			return ret;
		/* Make sure decrypted data matches key */
		crypto_hash(dev, cd->sg, cd->size, hash);
		if (memcmp(cd->key, hash, dev->hash_len)) {
			debug("Chunk " SECTOR_FORMAT ": Key doesn't match "
						"decrypted data", cd->cid);
			return -EIO;
		}
		ret=decompress_chunk(dev, cd->sg, cd->compression, cd->size);
		if (ret)
			return ret;
	} else {
		/* If compression or encryption errors out, we don't try to
		   recover the data because the cd will go into ST_ERROR state
		   anyway and no one will be allowed to read it. */
		ret=compress_chunk(dev, cd->sg, dev->default_compression);
		if (ret == -EFBIG) {
			cd->size=dev->chunksize;
			cd->compression=ISR_COMPRESS_NONE;
		} else if (ret < 0) {
			return ret;
		} else {
			cd->size=ret;
			cd->compression=dev->default_compression;
		}
		ndebug("Encrypting %u bytes for chunk "SECTOR_FORMAT,
					cd->size, cd->cid);
		crypto_hash(dev, cd->sg, cd->size, cd->key);
		ret=crypto_cipher(dev, cd->sg, cd->key, cd->size, WRITE);
		if (ret)
			return ret;
	}
	return 0;
}

/* Runs in workqueue (user) context */
static void chunkdata_complete_io(void *data)
{
	struct convergent_dev *dev=data;
	struct chunkdata_table *table=dev->chunkdata;
	struct chunkdata *cd;
	int error;
	unsigned long flags;
	
	mutex_lock_workqueue(&dev->lock);
	spin_lock_irqsave(&table->pending_completion_lock, flags);
	/* Don't use "safe" iterator, because the saved next pointer might
	   have changed out from under us between iterations */
	while (!list_empty(&table->pending_completion)) {
		cd=list_entry(table->pending_completion.next, struct chunkdata,
					lh_pending_completion);
		list_del_init(&cd->lh_pending_completion);
		spin_unlock_irqrestore(&table->pending_completion_lock, flags);
		
		error=cd->error;
		/* XXX we have a bit of a problem: we encrypt in-place.  so if
		   we just did write-back, we need to decrypt again to keep the
		   data clean. */
		if (error)
			log(KERN_ERR, "I/O error %s chunk " SECTOR_FORMAT,
						cd->state == ST_LOAD_DATA ?
						"reading" : "writing", cd->cid);
		else
			if (chunk_tfm(cd, READ))
				error=-EIO;
		
		/* XXX arguably we should report write errors to userspace */
		if (error)
			transition_error(cd, error);
		else if (cd->state == ST_LOAD_DATA)
			transition(cd, ST_CLEAN);
		else if (cd->state == ST_STORE_DATA)
			transition(cd, ST_DIRTY_META);
		else
			BUG();
		
		update_chunk(cd);
		spin_lock_irqsave(&table->pending_completion_lock, flags);
	}
	spin_unlock_irqrestore(&table->pending_completion_lock, flags);
	mutex_unlock(&dev->lock);
}

/* May be called from hardirq context or user context for the same
   convergent_dev */
static void chunk_io_make_progress(struct chunkdata *cd, unsigned nbytes)
{
	unsigned long flags;
	
	if (atomic_sub_and_test(nbytes, &cd->remaining)) {
		/* Can't call BUG() in interrupt */
		WARN_ON(!list_empty(&cd->lh_pending_completion));
		spin_lock_irqsave(&cd->table->pending_completion_lock, flags);
		list_add_tail(&cd->lh_pending_completion,
					&cd->table->pending_completion);
		spin_unlock_irqrestore(&cd->table->pending_completion_lock,
					flags);
		/* Duplicate scheduling is okay, so we ignore the return
		   value */
		queue_work(wkqueue, &cd->table->cb_complete_io);
	}
}

/* May be called from hardirq context */
static int convergent_endio_func(struct bio *bio, unsigned nbytes, int error)
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
static int io_has_reservation(struct convergent_io *io)
{
	struct convergent_io_chunk *chunk;
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

static void try_start_io(struct convergent_io *io)
{
	struct convergent_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!mutex_is_locked(&io->dev->lock));
	
	/* See if this io can run yet at all. */
	if (!io_has_reservation(io))
		return;
	
	/* Start any chunks which can run and haven't been started yet. */
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if ((chunk->flags & CHUNK_DEAD) ||
					(chunk->flags & CHUNK_STARTED))
			continue;
		cd=chunkdata_get(io->dev->chunkdata, chunk->cid);
		
		switch (cd->state) {
		case ST_META:
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
		if ((io->flags & IO_WRITE) &&
					(io->dev->flags & DEV_SHUTDOWN)) {
			/* Won't be able to do writeback. */
			chunk->error=-EIO;
			/* Subsequent reads to this chunk must not be allowed
			   to return stale data. */
			transition_error(cd, -EIO);
		}
		
		chunk->flags |= CHUNK_STARTED;
		convergent_process_chunk(&io->chunks[i]);
	}
}

/* Returns error if the queue is shut down */
static int queue_for_user(struct chunkdata *cd)
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(!list_empty(&cd->lh_user));
	BUG_ON(cd->state != ST_LOAD_META && cd->state != ST_STORE_META);
	if (cd->table->dev->flags & DEV_SHUTDOWN)
		return -EIO;
	list_add_tail(&cd->lh_user, &cd->table->user);
	wake_up_interruptible(&cd->table->dev->waiting_users);
	return 0;
}

int have_usermsg(struct convergent_dev *dev)
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

struct chunkdata *next_usermsg(struct convergent_dev *dev, msgtype_t *type)
{
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	list_for_each_entry(cd, &dev->chunkdata->user, lh_user) {
		if (cd->flags & CD_USER)
			continue;
		cd->flags |= CD_USER;
		if (cd->state == ST_LOAD_META)
			*type=ISR_MSGTYPE_GET_META;
		else if (cd->state == ST_STORE_META)
			*type=ISR_MSGTYPE_UPDATE_META;
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
		transition(cd, ST_CLEAN);
		__end_usermsg(cd);
		break;
	default:
		BUG();
	}
}

void shutdown_usermsg(struct convergent_dev *dev)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	BUG_ON(!(dev->flags & DEV_SHUTDOWN));
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
			unsigned *length, compress_t *compression, char key[])
{
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	BUG_ON(cd->state != ST_STORE_META);
	*cid=cd->cid;
	*length=cd->size;
	*compression=cd->compression;
	memcpy(key, cd->key, cd->table->dev->hash_len);
}

void set_usermsg_set_meta(struct convergent_dev *dev, chunk_t cid,
			unsigned length, compress_t compression, char key[])
{
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, cid);
	if (cd == NULL || !(cd->flags & CD_USER) ||
				cd->state != ST_LOAD_META) {
		/* Userspace is messing with us. */
		debug("Irrelevant metadata passed to usermsg_set_key()");
		return;
	}
	cd->size=length;
	cd->compression=compression;
	memcpy(cd->key, key, dev->hash_len);
	transition(cd, ST_META);
	__end_usermsg(cd);
}

static void run_chunk(struct chunkdata *cd)
{
	struct convergent_io_chunk *chunk;
	
	BUG_ON(!mutex_is_locked(&cd->table->dev->lock));
	chunk=pending_head(cd);
	
again:
	switch (cd->state) {
	case ST_INVALID:
		if (chunk != NULL) {
			/* No key or data */
			debug("Requesting key for chunk " SECTOR_FORMAT,
						cd->cid);
			transition(cd, ST_LOAD_META);
			if (queue_for_user(cd)) {
				transition_error(cd, -EIO);
				goto again;
			}
		}
		break;
	case ST_LOAD_META:
		break;
	case ST_META:
		/* Have metadata but not data */
		if (chunk != NULL) {
			if (chunk->flags & CHUNK_READ) {
				/* The first-in-queue needs the chunk read
				   in. */
				debug("Reading in chunk " SECTOR_FORMAT,
							cd->cid);
				transition(cd, ST_LOAD_DATA);
				issue_chunk_io(cd);
			} else {
				try_start_io(chunk->parent);
			}
		}
		break;
	case ST_LOAD_DATA:
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
			debug("Writing out chunk " SECTOR_FORMAT, cd->cid);
			transition(cd, ST_STORE_DATA);
			if (chunk_tfm(cd, WRITE)) {
				transition_error(cd, -EIO);
				goto again;
			} else {
				issue_chunk_io(cd);
			}
		}
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

/* Workqueue callback */
static void run_chunks(void *data)
{
	struct convergent_dev *dev=data;
	struct chunkdata *cd;
	struct chunkdata *next;
	int need_release=0;
	
	mutex_lock_workqueue(&dev->lock);
	list_for_each_entry_safe(cd, next, &dev->chunkdata->need_update,
				lh_need_update) {
		list_del_init(&cd->lh_need_update);
		run_chunk(cd);
	}
	if ((dev->flags & DEV_HAVE_CD_REF) &&
				dev->chunkdata->busy_count == 0 &&
				list_empty(&dev->chunkdata->need_update)) {
		dev->flags &= ~DEV_HAVE_CD_REF;
		need_release=1;
	}
	mutex_unlock(&dev->lock);
	if (need_release)
		convergent_dev_put(dev, 0);
}

int reserve_chunks(struct convergent_io *io)
{
	struct convergent_dev *dev=io->dev;
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
	if (!(dev->flags & DEV_HAVE_CD_REF)) {
		dev->flags |= DEV_HAVE_CD_REF;
		if (convergent_dev_get(dev) == NULL)
			BUG();
	}
	for (i=0; i<io_chunks(io); i++) {
		cd=chunkdata_get(dev->chunkdata, io->first_cid + i);
		BUG_ON(cd == NULL);
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

void unreserve_chunk(struct convergent_io_chunk *chunk)
{
	struct convergent_dev *dev=chunk->parent->dev;
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, chunk->cid);
	BUG_ON(!pending_head_is(cd, chunk));
	list_del_init(&chunk->lh_pending);
	user_put(dev);
	update_chunk(cd);
}

struct scatterlist *get_scatterlist(struct convergent_io_chunk *chunk)
{
	struct convergent_dev *dev=chunk->parent->dev;
	struct chunkdata *cd;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, chunk->cid);
	BUG_ON(cd == NULL || !pending_head_is(cd, chunk));
	return cd->sg;
}

ssize_t print_states(struct convergent_dev *dev, char *buf, int len)
{
	int i;
	int count=0;
	
	/* XXX if we wanted to be precise about this, we should have the ctr
	   take the dev lock and then have this function lock it before
	   running */
	if (dev->chunkdata == NULL) {
		/* ctr is still running */
		return 0;
	}
	for (i=0; i<NR_STATES; i++) {
		count += snprintf(buf+count, len-count, "%s%u", i ? " " : "",
					dev->chunkdata->state_count[i]);
	}
	count += snprintf(buf+count, PAGE_SIZE, "\n");
	return count;
}

void chunkdata_free_table(struct convergent_dev *dev)
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

int chunkdata_alloc_table(struct convergent_dev *dev)
{
	struct chunkdata_table *table;
	struct chunkdata *cd;
	unsigned buckets=dev->cachesize;  /* XXX is this reasonable? */
	int i;
	
	table=kzalloc(sizeof(*table), GFP_KERNEL);
	if (table == NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&table->lru);
	INIT_LIST_HEAD(&table->user);
	INIT_LIST_HEAD(&table->need_update);
	INIT_LIST_HEAD(&table->pending_completion);
	spin_lock_init(&table->pending_completion_lock);
	INIT_WORK(&table->cb_run_chunks, run_chunks, dev);
	INIT_WORK(&table->cb_complete_io, chunkdata_complete_io, dev);
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
		INIT_LIST_HEAD(&cd->lh_bucket);
		INIT_LIST_HEAD(&cd->lh_lru);
		INIT_LIST_HEAD(&cd->lh_user);
		INIT_LIST_HEAD(&cd->lh_need_update);
		INIT_LIST_HEAD(&cd->lh_pending_completion);
		INIT_LIST_HEAD(&cd->pending);
		list_add(&cd->lh_lru, &table->lru);
		if (alloc_chunk_buffer(cd))
			return -ENOMEM;
	}
	table->state_count[ST_INVALID]=dev->cachesize;
	return 0;
}

int __init chunkdata_start(void)
{
	/* The second and third parameters are dependent on the contents
	   of bvec_slabs[] in fs/bio.c, and on the chunk size.  Better too
	   high than too low. */
	/* XXX reduce a bit? */
	/* XXX a global pool means that layering convergent on top of
	   convergent could result in deadlocks.  we may want to prevent
	   this in the registration interface. */
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
