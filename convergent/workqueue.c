#include <linux/blkdev.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

struct job {
	struct work_struct work;
	struct bio *bio;
};

static struct workqueue_struct *queue;
static kmem_cache_t *job_cache;
static mempool_t *job_pool;

static void job_handle(void *data)
{
	struct job *job=data;
	
	generic_make_request(job->bio);
	mempool_free(job, job_pool);
}

void workqueue_shutdown(void)
{
	if (job_pool)
		mempool_destroy(job_pool);
	if (job_cache)
		kmem_cache_destroy(job_cache);
	if (queue)
		destroy_workqueue(queue);
}

int __init workqueue_start(void)
{
	queue=create_workqueue(SUBMIT_QUEUE);
	job_cache=kmem_cache_create(MODULE_NAME "-jobs",
				sizeof(struct job), 0, 0, NULL, NULL);
	/* XXX arbitrary factor */
	job_pool=mempool_create(4 * MIN_CONCURRENT_REQS,
				mempool_alloc_slab, mempool_free_slab,
				job_cache);
	if (queue == NULL || job_cache == NULL || job_pool == NULL) {
		workqueue_shutdown();
		return -ENOMEM;
	}
	return 0;
}

/* Intended to be called from atomic context */
void submit(struct bio *bio)
{
	struct job *job=mempool_alloc(job_pool, GFP_ATOMIC);
	if (job == NULL)
		BUG();  /* XXX */
	INIT_WORK(&job->work, job_handle, job);
	job->bio=bio;
	queue_work(queue, &job->work);
}
