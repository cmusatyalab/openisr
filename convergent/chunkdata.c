#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

/* XXX LRU removal except for inuse chunks (waiting for userspace,
   or in flight) */
/* XXX rename all this */

enum cd_bits {
	__CD_DATA_VALID,  /* The chunk's contents are buffered */
	__CD_DATA_DIRTY,  /* The buffered data needs a writeback */
	__CD_NR_BITS
};

#define CD_DATA_VALID  (1 << __CD_DATA_VALID) /* XXX */
#define CD_DATA_DIRTY  (1 << __CD_DATA_DIRTY) /* XXX */

struct chunkdata {
	struct list_head lh_bucket;
	struct list_head lh_lru;
	chunk_t chunk;
	struct list_head pending;
	unsigned flags;
	/* XXX hack that lets us not manage yet another allocation */
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct scatterlist sg[0];
};

struct chunkdata_table {
	spinlock_t lock;
	unsigned buckets;
	struct list_head lru;
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct list_head hash[0];
};

static inline struct convergent_io_chunk *pending_head(struct chunkdata *cd)
{
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

/* XXX might want to support high memory pages.  on the other hand, those
   might force bounce buffering */
static int alloc_chunk_pages(struct convergent_dev *dev, struct chunkdata *cd)
{
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

static void free_chunk_pages(struct convergent_dev *dev, struct chunkdata *cd)
{
	int i;

	for (i=0; i<chunk_pages(dev); i++)
		__free_page(cd->sg[i].page);
}

static unsigned hash(struct chunkdata_table *table, chunk_t chunk)
{
	return chunk % table->buckets;
}

void chunkdata_free_table(struct convergent_dev *dev)
{
	struct chunkdata_table *table=dev->chunkdata;
	struct chunkdata *cd;
	struct chunkdata *next;
	
	spin_lock_bh(&table->lock);
	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		/* XXX flags check */
		if (!list_empty(&cd->pending))
			BUG();
		list_del(&cd->lh_bucket);
		list_del(&cd->lh_lru);
		free_chunk_pages(dev, cd);
		kfree(cd);
	}
	spin_unlock_bh(&table->lock);
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
	spin_lock_init(&table->lock);
	for (i=0; i<buckets; i++)
		INIT_LIST_HEAD(&table->hash[i]);
	dev->chunkdata=table;
	
	for (i=0; i<dev->cachesize; i++) {
		/* We don't use a lookaside cache for struct cachedata because
		   they don't come and go; we pre-allocate and then they sit
		   around. */
		cd=kmalloc(sizeof(*cd) + chunk_pages(dev) * sizeof(cd->sg[0]),
					GFP_KERNEL);
		if (cd == NULL)
			goto bad1;
		if (alloc_chunk_pages(dev, cd))
			goto bad2;
		INIT_LIST_HEAD(&cd->lh_bucket);
		INIT_LIST_HEAD(&cd->lh_lru);
		INIT_LIST_HEAD(&cd->pending);
		list_add(&cd->lh_lru, &table->lru);
		cd->flags=0;
	}
	return 0;
	
bad2:
	kfree(cd);
bad1:
	chunkdata_free_table(dev);
	return -ENOMEM;
}

static void chunkdata_hit(struct chunkdata_table *table, struct chunkdata *cd)
{
	BUG_ON(!spin_is_locked(&table->lock));
	list_move_tail(&cd->lh_lru, &table->lru);
}

static struct chunkdata *chunkdata_get(struct chunkdata_table *table,
			chunk_t chunk)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	BUG_ON(!spin_is_locked(&table->lock));
	
	/* See if the chunk is in the table already */
	list_for_each_entry(cd, &table->hash[hash(table, chunk)], lh_bucket) {
		if (cd->chunk == chunk) {
			chunkdata_hit(table, cd);
			return cd;
		}
	}
	
	/* Steal the LRU chunk */
	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		/* XXX */
		if (list_empty(&cd->pending)) {
			list_del_init(&cd->lh_bucket);
			list_add(&cd->lh_bucket,
					&table->hash[hash(table, chunk)]);
			chunkdata_hit(table, cd);
			cd->chunk=chunk;
			cd->flags=0;
			return cd;
		}
	}
	
	/* Can't get a chunk */
	return NULL;
}

static void try_start_io(struct chunkdata_table *table,
			struct convergent_io *io)
{
	struct convergent_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	
	BUG_ON(!spin_is_locked(&table->lock));
	
	for (i=0; i<io_chunks(io); i++) {
		chunk=&io->chunks[i];
		cd=chunkdata_get(table, chunk->chunk);
		BUG_ON(cd == NULL);  /* XXX */
		if (!pending_head_is(cd, chunk))
			return;
		/* XXX make sure we have userspace keys */
	}
	/* XXX */
	spin_unlock(&table->lock);
	convergent_process_io(io);
	spin_lock(&table->lock);
}

int reserve_chunks(struct convergent_io *io)
{
	struct chunkdata_table *table=io->dev->chunkdata;
	chunk_t cur;
	struct convergent_io_chunk *chunk;
	struct chunkdata *cd;
	int i;
	
	spin_lock(&table->lock);
	for (i=0; i<io_chunks(io); i++) {
		cur=io->first_chunk + i;
		chunk=&io->chunks[i];
		cd=chunkdata_get(table, cur);
		if (cd == NULL)
			goto bad;
		list_add_tail(&chunk->lh_pending, &cd->pending);
	}
	try_start_io(table, io);
	spin_unlock(&table->lock);
	return 0;
	
bad:
	while (--i >= 0) {
		chunk=&io->chunks[i];
		list_del_init(&chunk->lh_pending);
	}
	spin_unlock(&table->lock);
	/* XXX this isn't strictly nomem */
	return -ENOMEM;
}

/* XXX locking is probably wrong - needs to be checked with lock validator */
void unreserve_chunk(struct convergent_io_chunk *chunk)
{
	struct chunkdata_table *table=chunk->parent->dev->chunkdata;
	struct chunkdata *cd;
	
	spin_lock(&table->lock);
	cd=chunkdata_get(table, chunk->chunk);
	BUG_ON(!pending_head_is(cd, chunk));
	list_del_init(&chunk->lh_pending);
	/* XXX this might cause the io to be started twice due to lock races */
	if (!list_empty(&cd->pending))
		try_start_io(table, pending_head(cd)->parent);
	spin_unlock(&table->lock);
}

struct scatterlist *get_scatterlist(struct convergent_io_chunk *chunk)
{
	struct chunkdata_table *table=chunk->parent->dev->chunkdata;
	struct chunkdata *cd;
	
	spin_lock(&table->lock);
	cd=chunkdata_get(table, chunk->chunk);
	spin_unlock(&table->lock);
	BUG_ON(cd == NULL || !pending_head_is(cd, chunk));
	return cd->sg;
}
