#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

static kmem_cache_t *reg_cache;
static mempool_t *reg_pool;

struct registration {
	struct list_head lh;
	chunk_t chunk;
	int waiter;
};

struct registration_table {
	struct list_head hash[HASH_BUCKETS];
};

static unsigned hash(chunk_t chunk)
{
	return chunk % HASH_BUCKETS;
}

void registration_shutdown(void)
{
	if (reg_pool)
		mempool_destroy(reg_pool);
	if (reg_cache)
		kmem_cache_destroy(reg_cache);
}

int registration_start(void)
{
	reg_cache=kmem_cache_create(MODULE_NAME "-registration",
				sizeof(struct registration), 0, 0, NULL, NULL);
	/* XXX arbitrary factor.  should be based on maximum request size
	   vs. chunk size */
	reg_pool=mempool_create(8 * MIN_CONCURRENT_REQS,
				mempool_alloc_slab, mempool_free_slab,
				reg_cache);
	if (reg_cache == NULL || reg_pool == NULL) {
		registration_shutdown();
		return -ENOMEM;
	}
	return 0;
}

struct registration_table *registration_alloc(void)
{
	struct registration_table *table;
	int i;
	
	table=kmalloc(sizeof(*table), GFP_KERNEL);
	if (table == NULL)
		return NULL;
	for (i=0; i<HASH_BUCKETS; i++)
		INIT_LIST_HEAD(&table->hash[i]);
	return table;
}

void registration_free(struct registration_table *table)
{
	int i;
	
	for (i=0; i<HASH_BUCKETS; i++) {
		if (!list_empty(&table->hash[i])) {
			BUG();
			break;
		}
	}
	kfree(table);
}

/* Must be synchronized by caller */
int register_chunks(struct registration_table *table, chunk_t start,
			chunk_t end)
{
	chunk_t cur;
	struct registration *reg;
	int conflict=0;
	
	for (cur=start; cur <= end; cur++) {
		list_for_each_entry(reg, &table->hash[hash(cur)], lh) {
			if (reg->chunk == cur) {
				reg->waiter=1;
				conflict=1;
			}
		}
	}
	if (conflict)
		return 0;
	for (cur=start; cur <= end; cur++) {
		reg=mempool_alloc(reg_pool, GFP_ATOMIC);
		if (reg == NULL)
			BUG();  /* XXX */
		INIT_LIST_HEAD(&reg->lh);
		reg->chunk=cur;
		reg->waiter=0;
		list_add_tail(&reg->lh, &table->hash[hash(cur)]);
	}
	return 1;
}

/* Must be synchronized by caller */
int unregister_chunk(struct registration_table *table, chunk_t chunk)
{
	struct registration *reg;
	int waiter;
	
	list_for_each_entry(reg, &table->hash[hash(chunk)], lh) {
		if (reg->chunk == chunk) {
			waiter=reg->waiter;
			list_del(&reg->lh);
			mempool_free(reg, reg_pool);
			return waiter;
		}
	}
	/* Not found */
	BUG();
	return 0;
}

/* Must be synchronized by caller */
int unregister_chunks(struct registration_table *table, chunk_t start,
			chunk_t end)
{
	chunk_t cur;
	int waiter=0;
	
	for (cur=start; cur <= end; cur++)
		if (unregister_chunk(table, cur))
			waiter=1;
	
	return waiter;
}
