#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/bio.h>
#include <linux/crypto.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include "convergent.h"

/* XXX rename all this */

enum cd_bits {
	__CD_USER,           /* Pending through userspace */
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
};

struct chunkdata {
	struct list_head lh_bucket;
	struct list_head lh_lru;
	struct list_head lh_user;
	struct chunkdata_table *table;
	chunk_t chunk;
	unsigned size;         /* compressed size before padding */
	compress_t compression;/* compression type */
	struct list_head pending;
	atomic_t completed;    /* bytes, for I/O */
	int error;             /* for I/O */
	struct tasklet_struct callback;
	unsigned flags;
	enum cd_state state;
	char key[MAX_HASH_LEN];
	/* XXX hack that lets us not manage yet another allocation */
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct scatterlist sg[0];
};

struct chunkdata_table {
	struct convergent_dev *dev;
	unsigned buckets;
	struct list_head lru;
	struct list_head user;
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct list_head hash[0];
};

static struct bio_set *bio_pool;


static unsigned hash(struct chunkdata_table *table, chunk_t chunk)
{
	return chunk % table->buckets;
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

static void chunkdata_hit(struct chunkdata *cd)
{
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	list_move_tail(&cd->lh_lru, &cd->table->lru);
}

static struct chunkdata *chunkdata_get(struct chunkdata_table *table,
			chunk_t chunk)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	BUG_ON(!spin_is_locked(&table->dev->lock));
	
	/* See if the chunk is in the table already */
	list_for_each_entry(cd, &table->hash[hash(table, chunk)], lh_bucket) {
		if (cd->chunk == chunk) {
			chunkdata_hit(cd);
			return cd;
		}
	}
	
	/* Steal the LRU chunk */
	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		/* XXX */
		if (list_empty(&cd->pending) &&
					(cd->state == ST_INVALID ||
					cd->state == ST_CLEAN)) {
			list_del_init(&cd->lh_bucket);
			list_add(&cd->lh_bucket,
					&table->hash[hash(table, chunk)]);
			chunkdata_hit(cd);
			cd->chunk=chunk;
			cd->flags=0;
			cd->state=ST_INVALID;
			return cd;
		}
	}
	
	/* Can't get a chunk */
	return NULL;
}

/* XXX might want to support high memory pages.  on the other hand, those
   might force bounce buffering */
static int alloc_chunk_pages(struct chunkdata *cd)
{
	struct convergent_dev *dev=cd->table->dev;
	int i;
	unsigned npages=chunk_pages(dev);
	unsigned residual;
	struct scatterlist *sg=NULL;  /* initialization to avoid warning */
	
	for (i=0; i<npages; i++) {
		sg=&cd->sg[i];
		sg->page=alloc_page(GFP_KERNEL);
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
	return -ENOMEM;
}

static void free_chunk_pages(struct chunkdata *cd)
{
	struct convergent_dev *dev=cd->table->dev;
	int i;

	for (i=0; i<chunk_pages(dev); i++)
		__free_page(cd->sg[i].page);
}

static void bio_destructor(struct bio *bio)
{
	bio_free(bio, bio_pool);
}

static int convergent_endio_func(struct bio *bio, unsigned nbytes, int error);
static struct bio *bio_create(struct chunkdata *cd, int dir, unsigned offset)
{
	struct convergent_dev *dev=cd->table->dev;
	struct bio *bio;
	struct convergent_io_chunk *chunk;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	/* XXX could alloc smaller bios if we're looping */
	bio=bio_alloc_bioset(GFP_ATOMIC, chunk_pages(dev), bio_pool);
	if (bio == NULL)
		return NULL;

	bio->bi_bdev=dev->chunk_bdev;
	bio->bi_sector=chunk_to_sector(dev, cd->chunk) + dev->offset + offset;
	ndebug("Creating bio with sector "SECTOR_FORMAT, bio->bi_sector);
	bio->bi_rw=dir;
	if (dir == READ) {
		chunk=pending_head(cd);
		if (chunk != NULL)
			bio_set_prio(bio, chunk->parent->prio);
	}
	bio->bi_end_io=convergent_endio_func;
	bio->bi_private=cd;
	bio->bi_destructor=bio_destructor;
	return bio;
}

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
	
	BUG_ON(!spin_is_locked(&dev->lock));
	
	if (cd->state == ST_LOAD_DATA) {
		dir=READ;
	} else if (cd->state == ST_STORE_DATA) {
		dir=WRITE;
	} else {
		BUG();
		return;
	}
	
	cd->error=0;
	atomic_set(&cd->completed, 0);
	
	/* XXX test against very small maximum seg count on target, etc. */
	ndebug("Submitting clone bio(s)");
	/* We can't assume that we can fit the entire chunk io in one
	   bio: it depends on the queue restrictions of the underlying
	   device */
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
			submit(bio);
			bio=NULL;
		}
	}
	BUG_ON(bio == NULL);
	submit(bio);
	return;
	
bad:
	/* XXX make this sane */
	cd->error=-ENOMEM;
	if (atomic_add_return(dev->chunksize - offset, &cd->completed)
				== dev->chunksize)
		tasklet_schedule(&cd->callback);
}

static void chunk_tfm(struct chunkdata *cd, int type)
{
	struct convergent_dev *dev=cd->table->dev;
	struct scatterlist *sg=cd->sg;
	unsigned padding;
	char iv[8]={0}; /* XXX */
	int ret;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	if (type == WRITE)
		crypto_digest_digest(dev->hash, sg, chunk_pages(dev), cd->key);
	if (crypto_cipher_setkey(dev->cipher, cd->key, dev->hash_len))
		BUG();
	crypto_cipher_set_iv(dev->cipher, iv, sizeof(iv));
	if (type == READ) {
		padding=crypto_pad(dev, cd->size);
		debug("Decrypting %u bytes for chunk "SECTOR_FORMAT,
					cd->size + padding, cd->chunk);
		if (crypto_cipher_decrypt(dev->cipher, sg, sg,
					cd->size + padding))
			BUG();
		if (decompress_chunk(dev, sg, cd->compression, cd->size))
			BUG(); /* XXX */
	} else {
		cd->compression=dev->compression;
		ret=compress_chunk(dev, sg, cd->compression);
		if (ret == -EFBIG) {
			cd->size=dev->chunksize;
			cd->compression=ISR_COMPRESS_NONE;
		} else if (ret < 0) {
			BUG();  /* XXX */
		} else {
			cd->size=ret;
		}
		padding=crypto_pad(dev, cd->size);
		debug("Encrypting %u bytes for chunk "SECTOR_FORMAT,
					cd->size + padding, cd->chunk);
		if (crypto_cipher_encrypt(dev->cipher, sg, sg,
					cd->size + padding))
			BUG();
	}
}

/* XXX */
static void run_chunk(struct chunkdata *cd);
/* Runs in tasklet (softirq) context */
static void chunkdata_complete_io(unsigned long data)
{
	struct chunkdata *cd=(void*)data;
	
	spin_lock_bh(&cd->table->dev->lock);
	if (cd->error)
		BUG();  /* XXX!!!!!!! */
	
	/* XXX we have a bit of a problem: we encrypt in-place.  so if we
	   just did write-back, we need to decrypt again to keep the data
	   clean. */
	chunk_tfm(cd, READ);
	
	if (cd->state == ST_LOAD_DATA)
		cd->state=ST_CLEAN;
	else if (cd->state == ST_STORE_DATA)
		cd->state=ST_DIRTY_META;
	else
		BUG();
	
	run_chunk(cd);
	spin_unlock_bh(&cd->table->dev->lock);
}

/* May be called from hardirq context */
static int convergent_endio_func(struct bio *bio, unsigned nbytes, int error)
{
	struct chunkdata *cd=bio->bi_private;
	int completed;
	if (error && !cd->error) {
		/* Racy, but who cares */
		cd->error=error;
	}
	completed=atomic_add_return(nbytes, &cd->completed);
	ndebug("Clone bio completion: %u bytes, total now %u; err %d",
				nbytes, completed, error);
	/* Can't call BUG() in interrupt */
	WARN_ON(completed > cd->table->dev->chunksize);
	if (completed >= cd->table->dev->chunksize)
		tasklet_schedule(&cd->callback);
	return 0;
}

/* Returns 1 if all chunks in the io are either at the front of their
   pending queues or have already been unreserved */
static int io_has_reservation(struct convergent_io *io)
{
	struct convergent_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!spin_is_locked(&io->dev->lock));
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		/* CHUNK_STARTED is an optimization: if set, we know it's
		   head-of-queue so we don't need to do the lookup */
		if ((chunk->flags & CHUNK_DEAD) ||
					(chunk->flags & CHUNK_STARTED))
			continue;
		cd=chunkdata_get(io->dev->chunkdata, chunk->chunk);
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
	
	BUG_ON(!spin_is_locked(&io->dev->lock));
	
	/* See if this io can run yet at all. */
	if (!io_has_reservation(io))
		return;
	
	/* Start any chunks which can run and haven't been started yet. */
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		if ((chunk->flags & CHUNK_DEAD) ||
					(chunk->flags & CHUNK_STARTED))
			continue;
		cd=chunkdata_get(io->dev->chunkdata, chunk->chunk);
		
		switch (cd->state) {
		case ST_META:
			if (chunk->flags & CHUNK_READ)
				continue;
		case ST_CLEAN:
		case ST_DIRTY:
			break;
		default:
			continue;
		}
		
		if (io->flags & IO_WRITE)
			cd->state=ST_DIRTY;
		chunk->flags |= CHUNK_STARTED;
		tasklet_schedule(&io->chunks[i].callback);
	}
}

static void queue_for_user(struct chunkdata *cd)
{
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	BUG_ON(!list_empty(&cd->lh_user));
	BUG_ON(cd->state != ST_LOAD_META && cd->state != ST_STORE_META);
	list_add_tail(&cd->lh_user, &cd->table->user);
	wake_up_interruptible(&cd->table->dev->waiting_users);
}

struct chunkdata *next_usermsg(struct convergent_dev *dev, msgtype_t *type)
{
	struct chunkdata *cd;
	
	BUG_ON(!spin_is_locked(&dev->lock));
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
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	BUG_ON(!(cd->flags & CD_USER));
	cd->flags &= ~CD_USER;
}

void end_usermsg(struct chunkdata *cd)
{
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	BUG_ON(!(cd->flags & CD_USER));
	cd->flags &= ~CD_USER;
	list_del_init(&cd->lh_user);
	if (cd->state == ST_STORE_META) {
		cd->state=ST_CLEAN;
		run_chunk(cd);
	}
}

void get_usermsg_get_meta(struct chunkdata *cd, unsigned long long *cid)
{
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	BUG_ON(cd->state != ST_LOAD_META);
	*cid=cd->chunk;
}

void get_usermsg_update_meta(struct chunkdata *cd, unsigned long long *cid,
			unsigned *length, compress_t *compression, char key[])
{
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	BUG_ON(cd->state != ST_STORE_META);
	*cid=cd->chunk;
	*length=cd->size;
	*compression=cd->compression;
	memcpy(key, cd->key, cd->table->dev->hash_len);
}

void set_usermsg_set_meta(struct convergent_dev *dev, chunk_t cid,
			unsigned length, compress_t compression, char key[])
{
	struct chunkdata *cd;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, cid);
	if (cd == NULL || !list_empty(&cd->lh_user) ||
				cd->state != ST_LOAD_META) {
		/* Userspace is messing with us. */
		debug("Irrelevant metadata passed to usermsg_set_key()");
		return;
	}
	cd->size=length;
	cd->compression=compression;
	memcpy(cd->key, key, dev->hash_len);
	cd->state=ST_META;
	run_chunk(cd);
}

/* XXX need to make sure everything is eventually written back */
static void run_chunk(struct chunkdata *cd)
{
	struct convergent_io_chunk *chunk;
	
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	chunk=pending_head(cd);
	
	if (cd->state == ST_DIRTY_META) {
		/* We just wrote out data but haven't written out metadata
		   yet.  We can't do anything else with this chunk until
		   we write out metadata. */
		cd->state=ST_STORE_META;
		queue_for_user(cd);
		return;
	} else if (cd->state == ST_DIRTY && chunk == NULL) {
		debug("Writing out chunk " SECTOR_FORMAT, cd->chunk);
		cd->state=ST_STORE_DATA;
		chunk_tfm(cd, WRITE);
		issue_chunk_io(cd);
	} else if (chunk != NULL) {
		switch (cd->state) {
		case ST_INVALID:
			/* No key or data */
			debug("Requesting key for chunk " SECTOR_FORMAT,
						cd->chunk);
			cd->state=ST_LOAD_META;
			queue_for_user(cd);
			break;
		case ST_META:
			/* Have metadata but not data */
			if (chunk->flags & CHUNK_READ) {
				/* The first-in-queue needs the chunk read
				   in. */
				debug("Reading in chunk " SECTOR_FORMAT,
							cd->chunk);
				cd->state=ST_LOAD_DATA;
				issue_chunk_io(cd);
				break;
			}
			/* else fall through */
		case ST_CLEAN:
		case ST_DIRTY:
			/* Have metadata and data */
			try_start_io(chunk->parent);
		case ST_LOAD_META:
		case ST_LOAD_DATA:
		case ST_STORE_DATA:
		case ST_STORE_META:
			break;
		case ST_DIRTY_META:
			BUG();
		}
	}
}

int reserve_chunks(struct convergent_io *io)
{
	struct convergent_dev *dev=io->dev;
	chunk_t cur;
	struct convergent_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	for (i=0; i<io_chunks(io); i++) {
		cur=io->first_chunk + i;
		chunk=&io->chunks[i];
		cd=chunkdata_get(dev->chunkdata, cur);
		if (cd == NULL)
			goto bad;
		list_add_tail(&chunk->lh_pending, &cd->pending);
	}
	for (i=0; i<io_chunks(io); i++) {
		cur=io->first_chunk + i;
		cd=chunkdata_get(dev->chunkdata, cur);
		BUG_ON(cd == NULL);
		run_chunk(cd);
	}
	return 0;
	
bad:
	while (--i >= 0) {
		chunk=&io->chunks[i];
		list_del_init(&chunk->lh_pending);
	}
	/* XXX this isn't strictly nomem */
	return -ENOMEM;
}

void unreserve_chunk(struct convergent_io_chunk *chunk)
{
	struct convergent_dev *dev=chunk->parent->dev;
	struct chunkdata *cd;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, chunk->chunk);
	BUG_ON(!pending_head_is(cd, chunk));
	list_del_init(&chunk->lh_pending);
	run_chunk(cd);
}

struct scatterlist *get_scatterlist(struct convergent_io_chunk *chunk)
{
	struct convergent_dev *dev=chunk->parent->dev;
	struct chunkdata *cd;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, chunk->chunk);
	BUG_ON(cd == NULL || !pending_head_is(cd, chunk));
	return cd->sg;
}

void chunkdata_free_table(struct convergent_dev *dev)
{
	struct chunkdata_table *table=dev->chunkdata;
	struct chunkdata *cd;
	struct chunkdata *next;
	
	if (table == NULL)
		return;
	/* XXX locking? */
	BUG_ON(!list_empty(&table->user));
	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		/* XXX flags check */
		BUG_ON(!list_empty(&cd->pending));
		/* XXX dirty writeouts */
		/* Wait for the tasklet to finish if it hasn't already */
		/* XXX necessary? */
		tasklet_disable(&cd->callback);
		list_del(&cd->lh_bucket);
		list_del(&cd->lh_lru);
		free_chunk_pages(cd);
		kfree(cd);
	}
	kfree(table);
}

int chunkdata_alloc_table(struct convergent_dev *dev)
{
	struct chunkdata_table *table;
	struct chunkdata *cd;
	unsigned buckets=dev->cachesize;  /* XXX is this reasonable? */
	int i;
	
	table=kmalloc(sizeof(*table) + buckets * sizeof(table->hash[0]),
				GFP_KERNEL);
	if (table == NULL)
		return -ENOMEM;
	table->buckets=buckets;
	INIT_LIST_HEAD(&table->lru);
	INIT_LIST_HEAD(&table->user);
	for (i=0; i<buckets; i++)
		INIT_LIST_HEAD(&table->hash[i]);
	table->dev=dev;
	dev->chunkdata=table;
	
	for (i=0; i<dev->cachesize; i++) {
		/* We don't use a lookaside cache for struct cachedata because
		   they don't come and go; we pre-allocate and then they sit
		   around. */
		cd=kmalloc(sizeof(*cd) + chunk_pages(dev) * sizeof(cd->sg[0]),
					GFP_KERNEL);
		if (cd == NULL)
			return -ENOMEM;
		cd->table=table;
		cd->state=ST_INVALID;
		INIT_LIST_HEAD(&cd->lh_bucket);
		INIT_LIST_HEAD(&cd->lh_lru);
		INIT_LIST_HEAD(&cd->lh_user);
		INIT_LIST_HEAD(&cd->pending);
		if (alloc_chunk_pages(cd)) {
			kfree(cd);
			return -ENOMEM;
		}
		tasklet_init(&cd->callback, chunkdata_complete_io,
					(unsigned long)cd);
		list_add(&cd->lh_lru, &table->lru);
	}
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
	bio_pool=bioset_create(4 * MIN_CONCURRENT_REQS,
				4 * MIN_CONCURRENT_REQS, 4);
	if (bio_pool == NULL)
		return -ENOMEM;
	
	return 0;
}

void __exit chunkdata_shutdown(void)
{
	bioset_free(bio_pool);
}
