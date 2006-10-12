#include <linux/blkdev.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include "convergent.h"

struct job {
	struct work_struct work;
	void *data;
};

struct workqueue_struct *queue;
static kmem_cache_t *job_cache;
static mempool_t *job_pool;

static void job_handle_bio(void *data)
{
	struct job *job=data;
	
	generic_make_request(job->data);
	mempool_free(job, job_pool);
}

static void job_handle_gendisk(void *data)
{
	struct job *job=data;
	struct convergent_dev *dev=job->data;
	
	add_disk(dev->gendisk);
	convergent_dev_put(dev, 0);
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
int submit(struct bio *bio)
{
	struct job *job=mempool_alloc(job_pool, GFP_ATOMIC);
	if (job == NULL)
		return -ENOMEM;
	INIT_WORK(&job->work, job_handle_bio, job);
	job->data=bio;
	if (!queue_work(queue, &job->work))
		BUG();
	return 0;
}

int delayed_add_disk(struct convergent_dev *dev)
{
	struct job *job;
	
	might_sleep();
	/* Make sure the dev isn't freed until add_disk() completes */
	if (convergent_dev_get(dev) == NULL)
		return -EFAULT;
	job=mempool_alloc(job_pool, GFP_KERNEL);
	if (job == NULL) {
		convergent_dev_put(dev, 0);
		return -ENOMEM;
	}
	INIT_WORK(&job->work, job_handle_gendisk, job);
	job->data=dev;
	/* We use the shared queue in order to prevent deadlock: if we
	   used our own queue, add_disk() would block its own I/O to the
	   partition table. */
	if (!schedule_work(&job->work))
		BUG();
	return 0;
}

void queue_for_thread(struct work_struct *work)
{
	if (!queue_work(queue, work))
		BUG();
}
