#include <linux/kthread.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/notifier.h>
#include "defs.h"

/* XXX percpu vars */
static struct {
	MUTEX lock;
	struct task_struct *task[NR_CPUS];
	int count;
	struct nexus_tfm_state ts[NR_CPUS];
	unsigned suite_users[NEXUS_NR_CRYPTO];
	unsigned compress_users[NEXUS_NR_COMPRESS];
} threads;

static struct {
	spinlock_t lock;       /* may be taken in interrupt context */
	struct list_head list[NR_CALLBACKS];
	wait_queue_head_t wq;
} queues;


/* This will always run on the processor to which it is bound, *except* during
   hot-unplug of that CPU, when it will run on an arbitrary processor. */
static int nexus_thread(void *data)
{
	struct nexus_tfm_state *ts=data;
	unsigned long flags;
	enum callback type;
	struct list_head *entry;
	DEFINE_WAIT(wait);
	int did_work;
	
	for (did_work=0; !kthread_should_stop(); did_work=0) {
		spin_lock_irqsave(&queues.lock, flags);
		for (type=0; type<NR_CALLBACKS; type++) {
			if (!list_empty(&queues.list[type])) {
				entry=queues.list[type].next;
				list_del_init(entry);
				spin_unlock_irqrestore(&queues.lock, flags);
				switch (type) {
				case CB_COMPLETE_IO:
					chunkdata_complete_io(entry);
					break;
				case CB_UPDATE_CHUNK:
					run_chunk(entry);
					break;
				case CB_CRYPTO:
					chunk_tfm(ts, entry);
					break;
				case NR_CALLBACKS:
					BUG();
				}
				did_work=1;
				break;
			}
		}
		
		if (!did_work) {
			/* No pending callbacks */
			prepare_to_wait_exclusive(&queues.wq, &wait,
						TASK_INTERRUPTIBLE);
			spin_unlock_irqrestore(&queues.lock, flags);
			if (!kthread_should_stop())
				schedule();
			finish_wait(&queues.wq, &wait);
		}
	}
	return 0;
}

#define nexus_suite nexus_crypto

#define DEFINE_ALLOC_ON_ALL(TYPE)					\
static int alloc_##TYPE##_on_all(enum nexus_##TYPE arg)			\
{									\
	int cpu;							\
	int count;							\
	int err;							\
									\
	BUG_ON(!mutex_is_locked(&threads.lock));			\
	debug("Allocating " #TYPE " %s...",				\
				TYPE##_info(arg)->user_name);		\
	for (cpu=0, count=0; cpu<NR_CPUS; cpu++) {			\
		/* We care about which threads are running, not which	\
		   CPUs are online */					\
		if (threads.task[cpu] == NULL)				\
			continue;					\
		err=TYPE##_add(&threads.ts[cpu], arg);			\
		if (err)						\
			goto bad;					\
		count++;						\
	}								\
	debug("...allocated on %d cpus", count);			\
	return 0;							\
									\
bad:									\
	while (--cpu >= 0) {						\
		if (threads.task[cpu] != NULL)				\
			TYPE##_remove(&threads.ts[cpu], arg);		\
	}								\
	return err;							\
}

#define DEFINE_FREE_ON_ALL(TYPE)					\
static void free_##TYPE##_on_all(enum nexus_##TYPE arg)			\
{									\
	int cpu;							\
	int count;							\
									\
	BUG_ON(!mutex_is_locked(&threads.lock));			\
	debug("Freeing " #TYPE " %s...", TYPE##_info(arg)->user_name);	\
	for (cpu=0, count=0; cpu<NR_CPUS; cpu++) {			\
		if (threads.task[cpu] == NULL)				\
			continue;					\
		TYPE##_remove(&threads.ts[cpu], arg);			\
		count++;						\
	}								\
	debug("...freed on %d cpus", count);				\
}

DEFINE_ALLOC_ON_ALL(suite)
DEFINE_FREE_ON_ALL(suite)
DEFINE_ALLOC_ON_ALL(compress)
DEFINE_FREE_ON_ALL(compress)
#undef nexus_suite

static int alloc_all_on_cpu(int cpu)
{
	enum nexus_crypto suite=0;
	enum nexus_compress alg=0;
	int suite_count;
	int alg_count;
	int err;
	
	BUG_ON(!mutex_is_locked(&threads.lock));
	
	for (suite_count=0; suite<NEXUS_NR_CRYPTO; suite++) {
		if (threads.suite_users[suite]) {
			err=suite_add(&threads.ts[cpu], suite);
			if (err)
				goto bad;
			suite_count++;
		}
	}
	for (alg_count=0; alg<NEXUS_NR_COMPRESS; alg++) {
		if (threads.compress_users[alg]) {
			err=compress_add(&threads.ts[cpu], alg);
			if (err)
				goto bad;
			alg_count++;
		}
	}
	debug("Allocated %d suites and %d compression algorithms for cpu %d",
				suite_count, alg_count, cpu);
	return 0;
	
bad:
	/* gcc makes enums unsigned.  Rather than making assumptions, we test
	   for both signed and unsigned underflow. */
	while (--alg >= 0 && alg < NEXUS_NR_COMPRESS) {
		if (threads.compress_users[alg])
			compress_remove(&threads.ts[cpu], alg);
	}
	while (--suite >= 0 && suite < NEXUS_NR_CRYPTO) {
		if (threads.suite_users[suite])
			suite_remove(&threads.ts[cpu], suite);
	}
	return err;
}

static void free_all_on_cpu(int cpu)
{
	enum nexus_crypto suite;
	enum nexus_compress alg;
	int suite_count;
	int alg_count;
	
	BUG_ON(!mutex_is_locked(&threads.lock));
	
	for (suite=0, suite_count=0; suite<NEXUS_NR_CRYPTO; suite++) {
		if (threads.suite_users[suite]) {
			suite_remove(&threads.ts[cpu], suite);
			suite_count++;
		}
	}
	for (alg=0, alg_count=0; alg<NEXUS_NR_COMPRESS; alg++) {
		if (threads.compress_users[alg]) {
			compress_remove(&threads.ts[cpu], alg);
			alg_count++;
		}
	}
	debug("Freed %d suites and %d compression algorithms for cpu %d",
				suite_count, alg_count, cpu);
}

int thread_register(struct nexus_dev *dev)
{
	enum nexus_compress alg;
	int err;
	
	/* We could use the interruptible variant and fail the device ctr
	   if we get a signal, but that seems sorta stupid. */
	mutex_lock(&threads.lock);
	
	/* Register suite */
	if (threads.suite_users[dev->suite] == 0) {
		err=alloc_suite_on_all(dev->suite);
		if (err)
			goto bad;
	}
	threads.suite_users[dev->suite]++;
	
	/* Register compression */
	for (alg=0; alg<NEXUS_NR_COMPRESS; alg++) {
		if (dev->supported_compression & (1 << alg)) {
			if (threads.compress_users[alg] == 0) {
				err=alloc_compress_on_all(alg);
				if (err)
					goto bad_dealloc;
			}
			threads.compress_users[alg]++;
		}
	}
	mutex_unlock(&threads.lock);
	
	/* Locking is not strictly necessary, since we're only called from
	   the ctr, but them's the rules so we follow them. */
	mutex_lock(&dev->lock);
	BUG_ON(dev->flags & DEV_THR_REGISTERED);
	dev->flags |= DEV_THR_REGISTERED;
	mutex_unlock(&dev->lock);
	return 0;
	
bad_dealloc:
	/* gcc makes enums unsigned.  Rather than making assumptions, we test
	   for both signed and unsigned underflow. */
	while (--alg >= 0 && alg < NEXUS_NR_COMPRESS) {
		if (dev->supported_compression & (1 << alg)) {
			if (--threads.compress_users[alg] == 0)
				free_compress_on_all(alg);
		}
	}
	if (--threads.suite_users[dev->suite] == 0)
		free_suite_on_all(dev->suite);
bad:
	mutex_unlock(&threads.lock);
	return err;
}

void thread_unregister(struct nexus_dev *dev)
{
	enum nexus_compress alg;
	int registered;
	
	/* Locking is not strictly necessary, since we're only called in the
	   ctr/dtr cases. */
	mutex_lock(&dev->lock);
	registered=dev->flags & DEV_THR_REGISTERED;
	dev->flags &= ~DEV_THR_REGISTERED;
	mutex_unlock(&dev->lock);
	/* Avoid corrupting refcounts if the registration failed earlier */
	if (!registered)
		return;
	
	mutex_lock(&threads.lock);
	
	/* Unregister suite */
	if (--threads.suite_users[dev->suite] == 0)
		free_suite_on_all(dev->suite);
	
	/* Unregister compression */
	for (alg=0; alg<NEXUS_NR_COMPRESS; alg++) {
		if (dev->supported_compression & (1 << alg)) {
			if (--threads.compress_users[alg] == 0)
				free_compress_on_all(alg);
		}
	}
	
	mutex_unlock(&threads.lock);
}

static int cpu_start(int cpu)
{
	struct task_struct *thr;
	int err;
	
	BUG_ON(!mutex_is_locked(&threads.lock));
	if (threads.task[cpu] != NULL)
		return 0;  /* See comment in cpu_callback() */
	
	debug("Onlining CPU %d", cpu);
	err=alloc_all_on_cpu(cpu);
	if (err) {
		debug("Failed to allocate transforms for CPU %d", cpu);
		return err;
	}
	thr=kthread_create(nexus_thread, &threads.ts[cpu], KTHREAD_NAME "/%d",
				cpu);
	if (IS_ERR(thr)) {
		free_all_on_cpu(cpu);
		return PTR_ERR(thr);
	}
	threads.task[cpu]=thr;
	threads.count++;
	kthread_bind(thr, cpu);
	/* Make sure the thread doesn't have a higher priority than interactive
	   processes (e.g. the X server) because they'll become somewhat
	   less interactive under high I/O load */
	set_user_nice(thr, 0);
	wake_up_process(thr);
	return 0;
}

static void cpu_stop(int cpu)
{
	BUG_ON(!mutex_is_locked(&threads.lock));
	if (threads.task[cpu] == NULL)
		return;
	
	debug("Offlining CPU %d", cpu);
	kthread_stop(threads.task[cpu]);
	debug("...done");
	free_all_on_cpu(cpu);
	threads.task[cpu]=NULL;
	threads.count--;
}

/* Runs in process context; can sleep */
static int cpu_callback(struct notifier_block *nb, unsigned long action,
			void *data)
{
	int cpu=(int)data;
	
	/* Due to the implementation of CPU hotplug, it is possible to receive
	   CPU_ONLINE for cpus that thread_start() has already configured, or
	   to receive CPU_DEAD for cpus we never started.  We can handle this
	   without special locking, so we ignore CPU_LOCK_ACQUIRE/RELEASE.
	   (Also, it's not portable to older kernel releases.) */
	mutex_lock(&threads.lock);
	switch (action) {
	case CPU_ONLINE:
		/* CPU is already up */
		if (cpu_start(cpu))
			log(KERN_ERR, "Failed to start thread for CPU %d", cpu);
		break;
	case CPU_DOWN_PREPARE:
		if (threads.count == 1 && threads.task[cpu] != NULL) {
			/* This is the last CPU on which we have a running
			   thread, since we were unable to start a thread
			   for a new CPU at some point in the past.  Cancel
			   the shutdown. */
			log(KERN_ERR, "Refusing to stop CPU %d: it is running "
						"our last worker thread", cpu);
			mutex_unlock(&threads.lock);
			return NOTIFY_BAD;
		}
		break;
	case CPU_DEAD:
		/* CPU is already down */
		cpu_stop(cpu);
		break;
	}
	mutex_unlock(&threads.lock);
	return NOTIFY_OK;
}

static struct notifier_block cpu_notifier = {
	.notifier_call = cpu_callback
};

void schedule_callback(enum callback type, struct list_head *entry)
{
	unsigned long flags;
	
	BUG_ON(type < 0 || type >= NR_CALLBACKS);
	BUG_ON(!list_empty(entry));
	spin_lock_irqsave(&queues.lock, flags);
	list_add_tail(entry, &queues.list[type]);
	spin_unlock_irqrestore(&queues.lock, flags);
	wake_up_interruptible(&queues.wq);
}

void thread_shutdown(void)
{
	int cpu;
	
	/* unregister_cpu_notifier must be called unlocked, in case the
	   notifier chain is currently running */
	unregister_cpu_notifier(&cpu_notifier);
	mutex_lock(&threads.lock);
	for_each_possible_cpu(cpu)
		cpu_stop(cpu);
	mutex_unlock(&threads.lock);
}

int __init thread_start(void)
{
	int cpu;
	int ret;
	int i;
	
	spin_lock_init(&queues.lock);
	for (i=0; i<NR_CALLBACKS; i++)
		INIT_LIST_HEAD(&queues.list[i]);
	init_waitqueue_head(&queues.wq);
	mutex_init(&threads.lock);
	
	/* lock_cpu_hotplug() only protects the online cpu map; it doesn't
	   prevent notifier callbacks from occurring.  threads.lock makes
	   sure the callback can't run until we've finished initialization */
	mutex_lock(&threads.lock);
	ret=register_cpu_notifier(&cpu_notifier);
	if (ret) {
		mutex_unlock(&threads.lock);
		return ret;
	}
	
	lock_cpu_hotplug();
	for_each_online_cpu(cpu) {
		ret=cpu_start(cpu);
		if (ret)
			break;
	}
	unlock_cpu_hotplug();
	mutex_unlock(&threads.lock);
	
	if (ret) {
		/* One of the threads failed to start.  Clean up. */
		thread_shutdown();
	}
	return ret;
}
