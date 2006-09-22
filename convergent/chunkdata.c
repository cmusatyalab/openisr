#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/bio.h>
#include <linux/crypto.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include "convergent.h"
#include "convergent-user.h"

/* XXX rename all this */

enum cd_bits {
	__CD_LOCKED,      /* I/O in progress */
	__CD_WRITE,       /* Pending I/O is a write */
	__CD_DATA_VALID,  /* The chunk's contents are buffered */
	__CD_DATA_DIRTY,  /* The buffered data needs a writeback */
	__CD_KEY_DIRTY,   /* Key needs to be sent to userspace */
	__CD_USER,        /* Metadata I/O with userspace is pending */
	__CD_NR_BITS
};

#define CD_LOCKED      (1 << __CD_LOCKED)
#define CD_WRITE       (1 << __CD_WRITE)
#define CD_DATA_VALID  (1 << __CD_DATA_VALID)
#define CD_DATA_DIRTY  (1 << __CD_DATA_DIRTY)
#define CD_KEY_DIRTY   (1 << __CD_KEY_DIRTY)
#define CD_USER        (1 << __CD_USER)     /* XXX */

struct chunkdata {
	struct list_head lh_bucket;
	struct list_head lh_lru;
	struct list_head lh_user;
	struct chunkdata_table *table;
	chunk_t chunk;
	struct list_head pending;
	atomic_t completed;    /* bytes, for I/O */
	int error;             /* for I/O */
	struct tasklet_struct callback;
	unsigned flags;
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
					!(cd->flags & CD_LOCKED) &&
					!(cd->flags & CD_USER) &&
					!(cd->flags & CD_DATA_DIRTY) &&
					!(cd->flags & CD_KEY_DIRTY)) {
			list_del_init(&cd->lh_bucket);
			list_add(&cd->lh_bucket,
					&table->hash[hash(table, chunk)]);
			chunkdata_hit(cd);
			cd->chunk=chunk;
			cd->flags=0;
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

static void issue_chunk_io(struct chunkdata *cd, int dir)
{
	struct convergent_dev *dev=cd->table->dev;
	struct bio *bio=NULL;
	unsigned offset=0;
	int i=0;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	BUG_ON(cd->flags & CD_LOCKED);
	
	cd->flags |= CD_LOCKED;
	if (dir == WRITE)
		cd->flags |= CD_WRITE;
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

/* XXX */
static void queue_for_user(struct chunkdata *cd);
static void chunk_tfm(struct chunkdata *cd, int type)
{
	struct convergent_dev *dev=cd->table->dev;
	struct scatterlist *sg=cd->sg;
	unsigned nbytes=dev->chunksize;
	char iv[8]={0};
	
	BUG_ON(!spin_is_locked(&dev->lock));
	if (type == WRITE) {
		crypto_digest_digest(dev->hash, sg, chunk_pages(dev), cd->key);
		if (!(cd->flags & CD_KEY_DIRTY)) {
			cd->flags |= CD_KEY_DIRTY;
			queue_for_user(cd);
		}
	}
	if (crypto_cipher_setkey(dev->cipher, cd->key, HASH_LEN))
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
}

/* XXX */
static void try_start_io(struct convergent_io *io);
/* Runs in tasklet (softirq) context */
static void chunkdata_complete_io(unsigned long data)
{
	struct chunkdata *cd=(void*)data;
	struct convergent_io_chunk *pending;
	
	spin_lock_bh(&cd->table->dev->lock);
	if (cd->error)
		BUG();  /* XXX!!!!!!! */
	BUG_ON(!(cd->flags & CD_LOCKED));
	if (!(cd->flags & CD_WRITE))
		cd->flags |= CD_DATA_VALID;
	cd->flags &= ~(CD_LOCKED | CD_DATA_DIRTY | CD_WRITE);
	
	/* XXX we have a bit of a problem: we encrypt in-place.  so if we
	   just did write-back, we need to decrypt again to keep the data
	   clean. */
	chunk_tfm(cd, READ);
	
	pending=pending_head(cd);
	if (pending != NULL)
		try_start_io(pending->parent);
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
		if ((cd->flags & CD_LOCKED) || (cd->flags & CD_USER))
			continue;
		if (!(cd->flags & CD_DATA_VALID) && (chunk->flags & CHUNK_READ))
			continue;
		/* Update state flags based on what the I/O will accomplish. */
		cd->flags |= CD_DATA_VALID;
		if (io->flags & IO_WRITE)
			cd->flags |= CD_DATA_DIRTY;
		chunk->flags |= CHUNK_STARTED;
		tasklet_schedule(&io->chunks[i].callback);
	}
}

static int try_writeback(struct chunkdata *cd)
{
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	
	if ((cd->flags & CD_LOCKED) || (cd->flags & CD_USER))
		return 0;
	if (!(cd->flags & CD_DATA_VALID) || !(cd->flags & CD_DATA_DIRTY))
		return 0;
	/* We can only lock-and-writeback a chunk when it is not reserved. */
	if (!list_empty(&cd->pending))
		return 0;
	debug("Writing out chunk " SECTOR_FORMAT, cd->chunk);
	/* XXX if locking breaks, this will kill things */
	chunk_tfm(cd, WRITE);
	issue_chunk_io(cd, WRITE);
	return 1;
}

static void queue_for_user(struct chunkdata *cd)
{
	BUG_ON(!spin_is_locked(&cd->table->dev->lock));
	if (cd->flags & CD_USER) {
		/* Don't queue the cd again if it's already queued */
		return;
	}
	ndebug("queue_for_user %x", cd->flags);
	cd->flags |= CD_USER;
	list_add_tail(&cd->lh_user, &cd->table->user);
	wake_up_interruptible(&cd->table->dev->waiting_users);
}

void configure_chunk(struct convergent_dev *dev, chunk_t cid, char key[])
{
	struct chunkdata *cd;
	struct convergent_io_chunk *chunk;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, cid);
	if (cd == NULL || !(cd->flags & CD_USER)) {
		/* Userspace is messing with us. */
		debug("Irrelevant metadata passed to configure_chunk()");
		return;
	}
	BUG_ON(cd->flags & CD_DATA_VALID);
	memcpy(cd->key, key, HASH_LEN);
	cd->flags &= ~CD_USER;
	chunk=pending_head(cd);
	if (chunk != NULL) {
		if (chunk->flags & CHUNK_READ) {
			/* The first-in-queue needs the chunk read in. */
			debug("Reading in chunk " SECTOR_FORMAT, cd->chunk);
			issue_chunk_io(cd, READ);
		} else {
			try_start_io(chunk->parent);
		}
	}
}

int have_user_message(struct convergent_dev *dev)
{
	BUG_ON(!spin_is_locked(&dev->lock));
	return (!list_empty(&dev->chunkdata->user));
}

/* XXX make chunkdata globally accessible */
int next_user_message(struct convergent_dev *dev, chunk_t *cid,
			char key[], int *havekey)
{
	struct chunkdata *cd;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	if (list_empty(&dev->chunkdata->user))
		return -ENODATA;
	cd=container_of(dev->chunkdata->user.next, struct chunkdata,
				lh_user);
	list_del_init(&cd->lh_user);
	*cid=cd->chunk;
	if (cd->flags & CD_KEY_DIRTY) {
		*havekey=1;
		cd->flags &= ~(CD_KEY_DIRTY | CD_USER);
		memcpy(key, cd->key, HASH_LEN);
	} else
		*havekey=0;
	return 0;
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
		if (list_empty(&cd->pending) && !(cd->flags & CD_DATA_VALID)) {
			debug("Requesting key for chunk " SECTOR_FORMAT,
						cd->chunk);
			queue_for_user(cd);
		}
		list_add_tail(&chunk->lh_pending, &cd->pending);
	}
	try_start_io(io);
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
	struct convergent_io_chunk *pending;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	cd=chunkdata_get(dev->chunkdata, chunk->chunk);
	BUG_ON(!pending_head_is(cd, chunk));
	list_del_init(&chunk->lh_pending);
	/* XXX this might cause the io to be started twice due to lock races */
	pending=pending_head(cd);
	if (pending != NULL)
		try_start_io(pending->parent);
	else
		try_writeback(cd);  /* XXX perhaps delay this a bit */
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
			goto bad1;
		cd->table=table;
		cd->flags=0;
		INIT_LIST_HEAD(&cd->lh_bucket);
		INIT_LIST_HEAD(&cd->lh_lru);
		INIT_LIST_HEAD(&cd->lh_user);
		INIT_LIST_HEAD(&cd->pending);
		if (alloc_chunk_pages(cd))
			goto bad2;
		tasklet_init(&cd->callback, chunkdata_complete_io,
					(unsigned long)cd);
		list_add(&cd->lh_lru, &table->lru);
	}
	return 0;
	
bad2:
	kfree(cd);
bad1:
	chunkdata_free_table(dev);
	return -ENOMEM;
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
