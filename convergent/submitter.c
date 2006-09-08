#include <linux/blkdev.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

struct submission {
	struct work_struct work;
	struct bio *bio;
};

static struct workqueue_struct *queue;
static kmem_cache_t *submission_cache;
static mempool_t *submission_pool;

static void submitter_handle(void *data)
{
	struct submission *sub=data;
	
	generic_make_request(sub->bio);
	mempool_free(sub, submission_pool);
}

void submitter_shutdown(void)
{
	if (submission_pool)
		mempool_destroy(submission_pool);
	if (submission_cache)
		kmem_cache_destroy(submission_cache);
	if (queue)
		destroy_workqueue(queue);
}

int __init submitter_start(void)
{
	queue=create_workqueue(SUBMIT_QUEUE);
	submission_cache=kmem_cache_create(MODULE_NAME "-submit",
				sizeof(struct submission), 0, 0, NULL, NULL);
	/* XXX arbitrary factor */
	submission_pool=mempool_create(4 * MIN_CONCURRENT_REQS,
				mempool_alloc_slab, mempool_free_slab,
				submission_cache);
	if (queue == NULL || submission_cache == NULL
				|| submission_pool == NULL) {
		submitter_shutdown();
		return -ENOMEM;
	}
	return 0;
}

/* Intended to be called from atomic context */
void submit(struct bio *bio)
{
	struct submission *sub=mempool_alloc(submission_pool, GFP_ATOMIC);
	if (sub == NULL)
		BUG();  /* XXX */
	INIT_WORK(&sub->work, submitter_handle, sub);
	sub->bio=bio;
	queue_work(queue, &sub->work);
}
