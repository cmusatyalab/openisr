#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

static kmem_cache_t *cd_cache;

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
};

struct chunkdata_table {
	spinlock_t lock;
	unsigned buckets;
	struct list_head lru;
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct list_head hash[0];
};

static unsigned hash(struct chunkdata_table *table, chunk_t chunk)
{
	return chunk % table->buckets;
}

void chunkdata_shutdown(void)
{
	if (cd_cache)
		kmem_cache_destroy(cd_cache);
}

int __init chunkdata_start(void)
{
	cd_cache=kmem_cache_create(MODULE_NAME "-chunkdata",
				sizeof(struct chunkdata), 0, 0, NULL, NULL);
	if (cd_cache == NULL) {
		chunkdata_shutdown();
		return -ENOMEM;
	}
	return 0;
}

void chunkdata_free_table(struct chunkdata_table *table)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	spin_lock_bh(&table->lock);
	list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
		/* XXX flags check */
		if (cd->flags & CD_RESERVED)
			BUG();
		list_del(&cd->lh_bucket);
		list_del(&cd->lh_lru);
		kmem_cache_free(cd_cache, cd);
	}
	spin_unlock_bh(&table->lock);
	kfree(table);
}

struct chunkdata_table *chunkdata_alloc_table(unsigned count)
{
	struct chunkdata_table *table;
	struct chunkdata *cd;
	unsigned buckets=count;  /* XXX is this reasonable? */
	int i;
	
	table=kmalloc(sizeof(*table) + buckets * sizeof(table->hash[0]),
				GFP_KERNEL);
	if (table == NULL)
		return NULL;
	table->buckets=buckets;
	INIT_LIST_HEAD(&table->lru);
	spin_lock_init(&table->lock);
	for (i=0; i<buckets; i++)
		INIT_LIST_HEAD(&table->hash[i]);
	
	for (i=0; i<count; i++) {
		cd=kmem_cache_alloc(cd_cache, GFP_KERNEL);
		if (cd == NULL) {
			chunkdata_free_table(table);
			return NULL;
		}
		INIT_LIST_HEAD(&cd->lh_bucket);
		INIT_LIST_HEAD(&cd->lh_lru);
		list_add(&cd->lh_lru, &table->lru);
		cd->flags=0;
	}
	return table;
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

int reserve_chunks(struct chunkdata_table *table, chunk_t start,
			chunk_t end)
{
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

int unreserve_chunk(struct chunkdata_table *table, chunk_t chunk)
{
	int ret;
	
	spin_lock(&table->lock);
	ret=__unreserve_chunk(table, chunk);
	spin_unlock(&table->lock);
	return ret;
}

int unreserve_chunks(struct chunkdata_table *table, chunk_t start,
			chunk_t end)
{
	chunk_t cur;
	int waiter=0;
	
	spin_lock(&table->lock);
	for (cur=start; cur <= end; cur++)
		if (__unreserve_chunk(table, cur))
			waiter=1;
	spin_unlock(&table->lock);
	
	return waiter;
}
