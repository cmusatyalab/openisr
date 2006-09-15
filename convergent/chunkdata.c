#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

static kmem_cache_t *cd_cache;
static mempool_t *cd_pool;

/* XXX LRU removal except for inuse chunks (waiting for userspace,
   or in flight) */

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
	struct list_head hash[CD_HASH_BUCKETS];
	struct list_head lru;
	unsigned count;
	spinlock_t lock;
};

static unsigned hash(chunk_t chunk)
{
	return chunk % CD_HASH_BUCKETS;
}

void chunkdata_shutdown(void)
{
	if (cd_pool)
		mempool_destroy(cd_pool);
	if (cd_cache)
		kmem_cache_destroy(cd_cache);
}

int __init chunkdata_start(void)
{
	cd_cache=kmem_cache_create(MODULE_NAME "-chunkdata",
				sizeof(struct chunkdata), 0, 0, NULL, NULL);
	/* XXX arbitrary factor.  should be based on maximum request size
	   vs. chunk size */
	/* XXX still use mempool, or preallocate regs? */
	cd_pool=mempool_create(8 * MIN_CONCURRENT_REQS,
				mempool_alloc_slab, mempool_free_slab,
				cd_cache);
	if (cd_cache == NULL || cd_pool == NULL) {
		chunkdata_shutdown();
		return -ENOMEM;
	}
	return 0;
}

struct chunkdata_table *chunkdata_alloc_table(void)
{
	struct chunkdata_table *table;
	int i;
	
	table=kmalloc(sizeof(*table), GFP_KERNEL);
	if (table == NULL)
		return NULL;
	for (i=0; i<CD_HASH_BUCKETS; i++)
		INIT_LIST_HEAD(&table->hash[i]);
	INIT_LIST_HEAD(&table->lru);
	spin_lock_init(&table->lock);
	table->count=0;
	return table;
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
		mempool_free(cd, cd_pool);
	}
	spin_unlock_bh(&table->lock);
	kfree(table);
}

static void chunkdata_hit(struct chunkdata_table *table, struct chunkdata *cd)
{
	BUG_ON(!spin_is_locked(&table->lock));
	list_del_init(&cd->lh_lru);
	list_add_tail(&cd->lh_lru, &table->lru);
}

static struct chunkdata *__chunkdata_alloc(struct chunkdata_table *table,
			chunk_t chunk)
{
	struct chunkdata *cd;
	struct chunkdata *next;
	
	BUG_ON(!spin_is_locked(&table->lock));
	if (table->count < CD_MAX_CHUNKS) {
		cd=mempool_alloc(cd_pool, GFP_ATOMIC);
		if (cd == NULL)
			BUG();  /* XXX */
		INIT_LIST_HEAD(&cd->lh_bucket);
		INIT_LIST_HEAD(&cd->lh_lru);
		list_add(&cd->lh_bucket, &table->hash[hash(chunk)]);
		list_add_tail(&cd->lh_lru, &table->lru);
		cd->chunk=chunk;
		cd->flags=0;
		table->count++;
		return cd;
	} else {
		list_for_each_entry_safe(cd, next, &table->lru, lh_lru) {
			/* XXX */
			if (!(cd->flags & CD_RESERVED)) {
				list_del_init(&cd->lh_bucket);
				list_add(&cd->lh_bucket,
						&table->hash[hash(chunk)]);
				chunkdata_hit(table, cd);
				cd->chunk=chunk;
				cd->flags=0;
				return cd;
			}
		}
		/* XXX */
		BUG();
		return NULL;
	}
}

static struct chunkdata *chunkdata_get(struct chunkdata_table *table,
			chunk_t chunk)
{
	struct chunkdata *cd;
	
	BUG_ON(!spin_is_locked(&table->lock));
	list_for_each_entry(cd, &table->hash[hash(chunk)], lh_bucket) {
		if (cd->chunk == chunk) {
			chunkdata_hit(table, cd);
			return cd;
		}
	}
	return __chunkdata_alloc(table, chunk);
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
