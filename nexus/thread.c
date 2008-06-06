/* thread.c - kernel threads */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (R)
 *         system
 * 
 * Copyright (C) 2006-2008 Carnegie Mellon University
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/notifier.h>
#include <linux/interrupt.h>
#include "defs.h"

/* XXX percpu vars */

/**
 * struct threads - singleton for per-CPU thread state
 * @lock          : lock for the other fields
 * @task          : task struct for a given per-CPU thread, or NULL if none
 * @count         : number of running threads
 * @ts            : per-CPU preallocated transforms and compress buffers
 * @suite_users   : number of devs holding a reference to each suite
 * @compress_users: number of devs holding a reference to each compress alg
 **/
static struct threads {
	MUTEX lock;
	struct task_struct *task[NR_CPUS];
	int count;
	struct nexus_tfm_state ts[NR_CPUS];
	unsigned suite_users[NEXUS_NR_CRYPTO];
	unsigned compress_users[NEXUS_NR_COMPRESS];
} threads;

/**
 * struct queues - singleton for nexus_thread
 * @lock: lock for the other fields; may be taken in interrupt context
 * @list: queue of pending tasks for each callback type
 * @wq  : wait queue for new work
 **/
static struct queues {
	spinlock_t lock;
	struct list_head list[NR_CALLBACKS];
	wait_queue_head_t wq;
} queues;

/**
 * struct pending_io - singleton for nexus_io_thread
 * @lock: lock for the other fields
 * @head: the next bio to be submitted
 * @tail: the last bio in line to be submitted
 * @wq  : wait queue for new work
 *
 * &struct bio does not contain a list_head that we can use to enqueue it;
 * bios are linked into a &struct request via a singly linked list.  Thus,
 * @head and @tail are used to implement a singly linked list.
 **/
static struct pending_io {
	spinlock_t lock;
	struct bio *head;
	struct bio *tail;
	wait_queue_head_t wq;
} pending_io;

/**
 * struct pending_requests - singleton for nexus_request_thread
 * @lock: lock for the other fields
 * @list: queue of pending tasks
 * @wq  : wait queue for new work
 **/
static struct pending_requests {
	spinlock_t lock;
	struct list_head list;
	wait_queue_head_t wq;
} pending_requests;

static struct task_struct *io_thread;
static struct task_struct *request_thread;


/**
 * nexus_thread - thread function for per-CPU callback processor
 * @data: pointer to &nexus_tfm_state for this thread
 * 
 * One of these will normally be running on each CPU in the system; this is
 * the process context in which much of the Nexus code runs.  It is structured
 * in terms of callbacks; Nexus code calls schedule_callback() passing
 * a callback type and a pointer to a &list_head to be queued for that callback
 * type.  nexus_thread() then runs callbacks in priority order.  Callback
 * types are assigned a priority by their enumeration order in &enum callback;
 * the thread will run all priority-zero callbacks before running any
 * priority-one callbacks, and so on.  Starvation is prevented by the fact
 * that the chunkdata state machine requires each chunk to proceed through each
 * of the callbacks in some order; if only high-priority callbacks are
 * processed, eventually every chunk in the chunkdata cache will be waiting for
 * crypto and the low-priority crypto callback will be reached.  The priority
 * order is chosen so that quick tasks, or those which start I/O, are
 * high-priority, and crypto (which is long-running) is always the lowest
 * priority.
 * 
 * nexus_thread() will always run on the specific processor to which it is
 * bound, *except* during hot-unplug of that CPU (or in a corner case on
 * <= 2.6.9), when it will run on an arbitrary processor.
 **/
static int nexus_thread(void *data)
{
	struct nexus_tfm_state *ts=data;
	enum callback type;
	struct list_head *entry;
	DEFINE_WAIT(wait);
	
	set_nonfreezable();
	while (!kthread_should_stop()) {
		spin_lock_irq(&queues.lock);
		for (type=0; type<NR_CALLBACKS; type++) {
			if (!list_empty(&queues.list[type])) {
				entry=queues.list[type].next;
				list_del_init(entry);
				spin_unlock_irq(&queues.lock);
				
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
				cond_resched();
				goto next;
			}
		}
		
		/* No pending callbacks */
		prepare_to_wait_exclusive(&queues.wq, &wait,
					TASK_INTERRUPTIBLE);
		spin_unlock_irq(&queues.lock);
		if (!kthread_should_stop())
			schedule();
		finish_wait(&queues.wq, &wait);
next:
		barrier();  /* nop to make compiler happy */
	}
	return 0;
}

/**
 * schedule_callback - arrange for a callback to be run as soon as possible
 * @type : the callback type, indicating which callback function should be used
 * @entry: the &list_head to be passed to the callback function
 * 
 * This must be safe to call from any context, including hardirq.
 **/
void schedule_callback(enum callback type, struct list_head *entry)
{
	unsigned long flags;
	
	/* Can't call BUG() from interrupt context */
	WARN_ON(type < 0 || type >= NR_CALLBACKS);
	WARN_ON(!list_empty(entry));
	spin_lock_irqsave(&queues.lock, flags);
	list_add_tail(entry, &queues.list[type]);
	spin_unlock_irqrestore(&queues.lock, flags);
	wake_up_interruptible(&queues.wq);
}

/**
 * nexus_io_thread - helper thread to submit I/O to chunk store
 * 
 * This just loops calling generic_make_request().  We don't want to make
 * these calls from the per-CPU thread because generic_make_request() is
 * allowed to block if there are already too many outstanding requests to the
 * chunk store, and we want to be able to continue to do crypto and service
 * other requests while we wait.
 * 
 * Technically we could spawn one thread per device so that a blocked queue
 * for one chunk store won't affect unrelated devices, but we have too many
 * threads already.  This can be changed later if it becomes a problem.
 **/
static int nexus_io_thread(void *ignored)
{
	struct bio *bio;
	DEFINE_WAIT(wait);
	
	set_nonfreezable();
	while (!kthread_should_stop()) {
		spin_lock(&pending_io.lock);
		bio=pending_io.head;
		if (bio != NULL) {
			pending_io.head=bio->bi_next;
			bio->bi_next=NULL;
		} else {
			prepare_to_wait_exclusive(&pending_io.wq, &wait,
						TASK_INTERRUPTIBLE);
		}
		spin_unlock(&pending_io.lock);
		
		if (bio != NULL) {
			generic_make_request(bio);
		} else {
			if (!kthread_should_stop())
				schedule();
			finish_wait(&pending_io.wq, &wait);
		}
	}
	return 0;
}

/**
 * schedule_io - arrange for @bio to be submitted later from process context
 *
 * This just queues bios for nexus_io_thread().  It is only safe to call from
 * process context.
 * 
 * We don't want to have to do a memory allocation to queue I/O, so we need
 * to use the linked list mechanism already included in struct bio.
 * Unfortunately, this is just a "next" pointer rather than a &list_head.
 **/
void schedule_io(struct bio *bio)
{
	BUG_ON(bio->bi_next != NULL);
	/* We don't use _bh or _irq spinlock variants */
	WARN_ON(in_interrupt());
	spin_lock(&pending_io.lock);
	if (pending_io.head == NULL) {
		pending_io.head=bio;
		pending_io.tail=bio;
	} else {
		pending_io.tail->bi_next=bio;
		pending_io.tail=bio;
	}
	spin_unlock(&pending_io.lock);
	wake_up_interruptible(&pending_io.wq);
}

/**
 * nexus_request_thread - helper thread to run request queues
 * 
 * Request queues are different from other types of callbacks.  The request
 * queue code needs to be able to return callbacks to the head of the queue if
 * an allocation failure occurs, and this operation must always preserve queue
 * order; it needs to be able to delay walking the queue if there's an
 * out-of-memory condition; and we need to be able to process one dev's
 * requests even if another dev is out of chunkdata buffers.  Therefore, we use
 * a two-stage queue walk: there's a per-dev request list, and one callback
 * processes the entire per-dev list at once (in request.c).
 * 
 * In order to ensure that allocation failures do not reorder requests in a
 * particular dev's list, we must make sure that only one thread can process
 * a dev's request list at a time.  We could do this in the per-CPU crypto
 * threads using a per-dev lock, but then we'd have to choose between
 * complex code, race conditions, or allowing crypto threads to uselessly
 * block on a dev mutex when they could be getting work done.  For simplicity,
 * therefore, we only allow one thread to be processing request queues at a
 * time.  There's no clean way to do that within the per-CPU thread
 * architecture, so we have a special singleton thread for this purpose.  This
 * is separate from the I/O thread because we still want to process incoming
 * requests even if our underlying chunk store's request queue is full.
 **/
static int nexus_request_thread(void *ignored)
{
	struct list_head *entry;
	DEFINE_WAIT(wait);
	
	set_nonfreezable();
	while (!kthread_should_stop()) {
		spin_lock_irq(&pending_requests.lock);
		if (!list_empty(&pending_requests.list)) {
			entry=pending_requests.list.next;
			list_del_init(entry);
			spin_unlock_irq(&pending_requests.lock);
			nexus_run_requests(entry);
		} else {
			prepare_to_wait_exclusive(&pending_requests.wq, &wait,
						TASK_INTERRUPTIBLE);
			spin_unlock_irq(&pending_requests.lock);
			if (!kthread_should_stop())
				schedule();
			finish_wait(&pending_requests.wq, &wait);
		}
	}
	return 0;
}

/**
 * schedule_request_callback - arrange for a request callback to run later
 *
 * This can safely be called from any context.
 **/
void schedule_request_callback(struct list_head *entry)
{
	unsigned long flags;
	
	/* Can't call BUG() from interrupt context */
	WARN_ON(!list_empty(entry));
	spin_lock_irqsave(&pending_requests.lock, flags);
	list_add_tail(entry, &pending_requests.list);
	spin_unlock_irqrestore(&pending_requests.lock, flags);
	wake_up_interruptible(&pending_requests.wq);
}

/**
 * wake_all_threads - make all Nexus threads runnable
 *
 * Only for debug use via sysfs.
 **/
void wake_all_threads(void)
{
	log(KERN_NOTICE, "Unwedging threads");
	wake_up_all(&queues.wq);
	wake_up_all(&pending_io.wq);
	wake_up_all(&pending_requests.wq);
}

#define nexus_suite nexus_crypto

/**
 * alloc_TYPE_on_all - allocate transform structures on every running CPU
 * @TYPE: "suite" or "compress"
 * @arg: suite or compression algorithm to be allocated
 *
 * Allocates data structures for processing the given suite or compression
 * algorithm on every running CPU.  The suite or algorithm must not already
 * be allocated.  On allocation failure, backs out the allocation and returns
 * an error code.  Thread lock must be held.
 **/
#define DEFINE_ALLOC_ON_ALL(TYPE)					\
static int alloc_##TYPE##_on_all(enum nexus_##TYPE arg)			\
{									\
	int cpu;							\
	int count;							\
	int err;							\
									\
	BUG_ON(!mutex_is_locked(&threads.lock));			\
	debug(DBG_THREAD, "Allocating " #TYPE " %s...",			\
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
	debug(DBG_THREAD, "...allocated on %d cpus", count);		\
	return 0;							\
									\
bad:									\
	while (--cpu >= 0) {						\
		if (threads.task[cpu] != NULL)				\
			TYPE##_remove(&threads.ts[cpu], arg);		\
	}								\
	return err;							\
}

/**
 * free_TYPE_on_all - free transform structures on every running CPU
 * @TYPE: "suite" or "compress"
 * @arg: suite or compression algorithm to be freed
 *
 * Thread lock must be held.
 **/
#define DEFINE_FREE_ON_ALL(TYPE)					\
static void free_##TYPE##_on_all(enum nexus_##TYPE arg)			\
{									\
	int cpu;							\
	int count;							\
									\
	BUG_ON(!mutex_is_locked(&threads.lock));			\
	debug(DBG_THREAD, "Freeing " #TYPE " %s...",			\
				TYPE##_info(arg)->user_name);		\
	for (cpu=0, count=0; cpu<NR_CPUS; cpu++) {			\
		if (threads.task[cpu] == NULL)				\
			continue;					\
		TYPE##_remove(&threads.ts[cpu], arg);			\
		count++;						\
	}								\
	debug(DBG_THREAD, "...freed on %d cpus", count);				\
}

DEFINE_ALLOC_ON_ALL(suite)
DEFINE_FREE_ON_ALL(suite)
DEFINE_ALLOC_ON_ALL(compress)
DEFINE_FREE_ON_ALL(compress)

#undef DEFINE_ALLOC_ON_ALL
#undef DEFINE_FREE_ON_ALL
#undef nexus_suite

/**
 * alloc_all_on_cpu - allocate suite and compress structures for new CPU
 * 
 * For each suite or compression algorithm which is currently allocated
 * on the other CPUs, performs the same allocation for CPU @cpu.  Backs out
 * allocations on failure.  Thread lock must be held.
 **/
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
	debug(DBG_THREAD, "Allocated %d suites and %d compression algorithms "
				"for cpu %d", suite_count, alg_count, cpu);
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

/**
 * free_all_on_cpu - free all suite and compress structures from @cpu
 *
 * Thread lock must be held.
 **/
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
	debug(DBG_THREAD, "Freed %d suites and %d compression algorithms for "
				"cpu %d", suite_count, alg_count, cpu);
}

/**
 * thread_register - allocate per-thread tfm structures for @dev
 *
 * Validates the transforms associated with @dev and registers them with the
 * thread code.  A successful return indicates that all per-CPU threads will
 * be able to process the transforms required by @dev.
 **/
int thread_register(struct nexus_dev *dev)
{
	enum nexus_compress alg;
	int err;
	
	err=transform_validate(dev);
	if (err)
		return err;
	
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
	
	if (test_and_set_bit(__DEV_THR_REGISTERED, &dev->flags))
		BUG();
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

/**
 * thread_unregister - release tfm registration for @dev
 *
 * This function reverses the effects of thread_register().  This is safe
 * to call even if thread_register() has not been called on this @dev or did
 * not complete successfully.
 **/
void thread_unregister(struct nexus_dev *dev)
{
	enum nexus_compress alg;
	
	/* Avoid corrupting refcounts if the registration failed earlier */
	if (!test_and_clear_bit(__DEV_THR_REGISTERED, &dev->flags))
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

/**
 * cpu_start - allocate data structures and start a new thread for @cpu
 *
 * If a per-CPU thread is already running on @cpu, cpu_start() will return
 * success and take no other action.  Thread lock must be held.
 **/
static int cpu_start(int cpu)
{
	struct task_struct *thr;
	int err;
	
	BUG_ON(!mutex_is_locked(&threads.lock));
	if (threads.task[cpu] != NULL) {
		/* This may happen in some hotplug cases.  Ignore the duplicate
		   start request. */
		return 0;
	}
	
	debug(DBG_THREAD, "Onlining CPU %d", cpu);
	err=alloc_all_on_cpu(cpu);
	if (err) {
		debug(DBG_THREAD, "Failed to allocate transforms for CPU %d",
					cpu);
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
	/* Give the thread a lower priority than garden-variety interactive
	   processes so that we don't kill their scheduling latency */
	set_user_nice(thr, 5);
	wake_up_process(thr);
	return 0;
}

/**
 * cpu_stop - kill the per-CPU thread on @cpu and free its data structures
 *
 * This is safe to call if no thread is running on @cpu.  Thread lock must
 * be held.
 **/
static void cpu_stop(int cpu)
{
	BUG_ON(!mutex_is_locked(&threads.lock));
	if (threads.task[cpu] == NULL)
		return;
	
	debug(DBG_THREAD, "Offlining CPU %d", cpu);
	kthread_stop(threads.task[cpu]);
	debug(DBG_THREAD, "...done");
	free_all_on_cpu(cpu);
	threads.task[cpu]=NULL;
	threads.count--;
}

/**
 * cpu_callback - CPU hotplug notification handler
 *
 * The CPU hotplug code calls this to let us know when CPUs come and go.  Runs
 * in process context, and is permitted to sleep.
 *
 * Any running thread must be able to handle any transform which is associated
 * with any nexus_dev.  If we encounter allocation failures when bringing up
 * a new CPU, cpu_start() will refuse to start the thread.  This may cause some
 * running CPUs not to have associated threads.
 *
 * We do not tear down a per-CPU thread until after its CPU has been shut
 * down.  In the meantime, the kthread code will unbind the thread so that
 * it can be scheduled on any processor.
 *
 * We will try to prevent the kernel from hot-unplugging any CPU which is
 * running our only per-CPU thread.  (This can only occur if previous CPU
 * hot-adds have failed.)  If the kernel completes the hot-unplug anyway,
 * we will print a warning and refuse to stop the thread.  In this case,
 * the thread will persist, runnable on any CPU, until module unload or until
 * another plug-unplug cycle occurs on the thread's original CPU.  The
 * thread will continue to use the downed CPU's data structure, and will
 * compete for CPU time with any threads which are (subsequently) properly
 * bound to particular CPUs.  However, correctness should not be compromised.
 *
 * Returning %NOTIFY_BAD to %CPU_DOWN_PREPARE may oops some kernels; apparently
 * that part of the API was never well-tested.  If this becomes a problem
 * in practice, we can change the DOWN_PREPARE handling to fall back on the
 * unbound-thread solution for the affected kernels.
 **/
static int cpu_callback(struct notifier_block *nb, unsigned long action,
			void *data)
{
	int cpu=(long)data;
	
	/* Any of these handlers may run before thread_start() has actually
	   started any threads, so they must not make assumptions about the
	   state of the system. */
	mutex_lock(&threads.lock);
	switch (action) {
	case CPU_ONLINE:
		/* CPU is already up */
		if (cpu_start(cpu))
			log(KERN_ERR, "Failed to start thread for CPU %d", cpu);
		break;
	case CPU_DOWN_PREPARE:
		/* This is only called for >= 2.6.10 */
		if (threads.count == 1 && threads.task[cpu] != NULL) {
			log(KERN_ERR, "Refusing to stop CPU %d: it is running "
						"our last worker thread", cpu);
			mutex_unlock(&threads.lock);
			return NOTIFY_BAD;
		}
		break;
	case CPU_DEAD:
		/* CPU is already down */
		if (threads.count == 1) {
			/* CPU_DOWN_PREPARE will prevent this for kernels
			   >= 2.6.10. */
			log(KERN_NOTICE, "Disabled CPU %d, which was running "
						"our last worker thread", cpu);
			log(KERN_NOTICE, "Leaving "KTHREAD_NAME"/%d running "
						"without CPU affinity", cpu);
			break;
		}
		cpu_stop(cpu);
		/* Make sure someone takes over any work the downed thread
		   was about to do */
		wake_up_interruptible(&queues.wq);
		break;
	}
	mutex_unlock(&threads.lock);
	return NOTIFY_OK;
}

static struct notifier_block cpu_notifier = {
	.notifier_call = cpu_callback
};

#if !defined(CONFIG_HOTPLUG_CPU) && \
			LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18) && \
			LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,19)
/* 2.6.18 and 2.6.19 have a bug with !CONFIG_HOTPLUG_CPU that causes the
   compiler to complain that cpu_notifier is unused.  Avoid the warning. */
struct notifier_block *__dummy_nb=&cpu_notifier;
#endif

/**
 * thread_shutdown - module de-initialization for thread code
 *
 * Stops per-CPU and singleton threads, if running.  Called from thread_start()
 * error path.
 **/
void thread_shutdown(void)
{
	int cpu;
	
	/* unregister_hotcpu_notifier must be called unlocked, in case the
	   notifier chain is currently running */
	unregister_hotcpu_notifier(&cpu_notifier);
	mutex_lock(&threads.lock);
	for_each_possible_cpu(cpu)
		cpu_stop(cpu);
	mutex_unlock(&threads.lock);
	
	if (io_thread != NULL) {
		debug(DBG_THREAD, "Stopping I/O thread");
		kthread_stop(io_thread);
		debug(DBG_THREAD, "...done");
		io_thread=NULL;
	}
	if (request_thread != NULL) {
		debug(DBG_THREAD, "Stopping request thread");
		kthread_stop(request_thread);
		debug(DBG_THREAD, "...done");
		request_thread=NULL;
	}
}

/**
 * thread_start - module initialization for thread code
 *
 * Starts per-CPU and singleton threads.  Backs out and returns error if any
 * thread fails to start.
 **/
int __init thread_start(void)
{
	struct task_struct *thr;
	int cpu;
	int ret=0;
	int i;
	
	spin_lock_init(&queues.lock);
	for (i=0; i<NR_CALLBACKS; i++)
		INIT_LIST_HEAD(&queues.list[i]);
	init_waitqueue_head(&queues.wq);
	mutex_init(&threads.lock);
	spin_lock_init(&pending_io.lock);
	init_waitqueue_head(&pending_io.wq);
	spin_lock_init(&pending_requests.lock);
	INIT_LIST_HEAD(&pending_requests.list);
	init_waitqueue_head(&pending_requests.wq);
	
	/* Lock-ordering issues dictate the order of these calls.  (2.6.19
	   takes the hotplug lock in register_hotcpu_notifier(), and we must
	   take the hotplug lock before threads.lock for consistency with
	   cpu_callback().)  As a result, we may get a callback before we
	   actually start any threads. */
	register_hotcpu_notifier(&cpu_notifier);
	get_online_cpus();
	mutex_lock(&threads.lock);
	for_each_online_cpu(cpu) {
		ret=cpu_start(cpu);
		if (ret)
			break;
	}
	mutex_unlock(&threads.lock);
	put_online_cpus();
	if (ret)
		goto bad;
	
	debug(DBG_THREAD, "Starting singleton threads");
	thr=kthread_create(nexus_io_thread, NULL, IOTHREAD_NAME);
	if (IS_ERR(thr)) {
		ret=PTR_ERR(thr);
		goto bad;
	}
	io_thread=thr;
	wake_up_process(thr);
	thr=kthread_create(nexus_request_thread, NULL, REQTHREAD_NAME);
	if (IS_ERR(thr)) {
		ret=PTR_ERR(thr);
		goto bad;
	}
	/* Make sure the request thread doesn't have a higher priority than
	   interactive processes.  This is not hugely necessary but seems to
	   improve scheduling latency a little bit. */
	set_user_nice(thr, 0);
	request_thread=thr;
	wake_up_process(thr);
	
	return 0;
	
bad:
	thread_shutdown();
	return ret;
}
