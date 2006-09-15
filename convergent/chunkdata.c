#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

/* XXX LRU removal except for inuse chunks (waiting for userspace,
   or in flight) */
/* XXX rename all this */

enum cd_bits {
	__CD_RESERVED,  /* A request has reserved this chunk */
	__CD_WAITER,    /* Another request is waiting for this chunk */
	__CD_NR_BITS
};

#define CD_RESERVED    (1 << __CD_RESERVED)
#define CD_WAITER      (1 << __CD_WAITER)

struct chunkdata {
	struct list_head lh_bucket;
	struct list_head lh_lru;
	chunk_t chunk;
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
		if (cd->flags & CD_RESERVED)
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
	list_del_init(&cd->lh_lru);
	list_add_tail(&cd->lh_lru, &table->lru);
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
		if (!(cd->flags & CD_RESERVED)) {
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

int reserve_chunks(struct convergent_dev *dev, chunk_t start, chunk_t end)
{
	struct chunkdata_table *table=dev->chunkdata;
	chunk_t cur;
	struct chunkdata *cd;
	int conflict=0;
	int ret;
	
	spin_lock(&table->lock);
	for (cur=start; cur <= end; cur++) {
		cd=chunkdata_get(table, cur);
		if (cd == NULL) {
			ret=0;
			goto out;
		}
		if (cd->flags & CD_RESERVED) {
			cd->flags |= CD_WAITER;
			conflict=1;
		}
	}
	if (conflict) {
		ret=0;
		goto out;
	}
	for (cur=start; cur <= end; cur++) {
		cd=chunkdata_get(table, cur);
		if (cd == NULL)
			/* XXX eek!  back out */
			BUG();
		cd->flags |= CD_RESERVED;
	}
	ret=1;
out:
	spin_unlock(&table->lock);
	return ret;
}

/* XXX locking is probably wrong - needs to be checked with lock validator */
static int __unreserve_chunk(struct chunkdata_table *table, chunk_t chunk)
{
	struct chunkdata *cd;
	int waiter;
	
	BUG_ON(!spin_is_locked(&table->lock));
	cd=chunkdata_get(table, chunk);
	BUG_ON(!(cd->flags & CD_RESERVED));
	waiter=cd->flags & CD_WAITER;
	cd->flags &= ~(CD_RESERVED | CD_WAITER);
	return waiter ? 1 : 0;
}

int unreserve_chunk(struct convergent_dev *dev, chunk_t chunk)
{
	struct chunkdata_table *table=dev->chunkdata;
	int ret;
	
	spin_lock(&table->lock);
	ret=__unreserve_chunk(table, chunk);
	spin_unlock(&table->lock);
	return ret;
}

int unreserve_chunks(struct convergent_dev *dev, chunk_t start, chunk_t end)
{
	struct chunkdata_table *table=dev->chunkdata;
	chunk_t cur;
	int waiter=0;
	
	spin_lock(&table->lock);
	for (cur=start; cur <= end; cur++)
		if (__unreserve_chunk(table, cur))
			waiter=1;
	spin_unlock(&table->lock);
	
	return waiter;
}

struct scatterlist *get_scatterlist(struct convergent_dev *dev, chunk_t chunk)
{
	struct chunkdata_table *table=dev->chunkdata;
	struct chunkdata *cd;
	
	spin_lock(&table->lock);
	cd=chunkdata_get(table, chunk);
	spin_unlock(&table->lock);
	BUG_ON(cd == NULL);
	BUG_ON(!(cd->flags & CD_RESERVED));
	return cd->sg;
}
