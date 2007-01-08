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
					chunk_tfm(entry);
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

static int cpu_start(int cpu)
{
	struct task_struct *thr;
	
	BUG_ON(!mutex_is_locked(&threads.lock));
	if (threads.task[cpu] != NULL)
		return 0;  /* See comment in cpu_callback() */
	
	debug("Onlining %d", cpu);
	thr=kthread_create(nexus_thread, NULL, KTHREAD_NAME "/%d", cpu);
	if (IS_ERR(thr))
		return PTR_ERR(thr);
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
	
	debug("Offlining %d", cpu);
	kthread_stop(threads.task[cpu]);
	debug("...done");
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
	   to receive CPU_DEAD for cpus we never started. */
	mutex_lock(&threads.lock);
	switch (action) {
	case CPU_ONLINE:
		/* CPU is already up */
		if (cpu_start(cpu))
			log(KERN_ERR, "Failed to start thread for cpu %d", cpu);
		break;
	case CPU_DOWN_PREPARE:
		debug("Preparing to offline %d", cpu);
		if (threads.count == 1 && threads.task[cpu] != NULL) {
			/* This is the last CPU on which we have a running
			   thread, since we were unable to start a thread
			   for a new CPU at some point in the past.  Cancel
			   the shutdown. */
			debug("...refusing");
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

int __init thread_start(void)
{
	int cpu;
	int err;
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
	err=register_cpu_notifier(&cpu_notifier);
	if (err) {
		mutex_unlock(&threads.lock);
		return err;
	}
	
	lock_cpu_hotplug();
	for_each_online_cpu(cpu) {
		err=cpu_start(cpu);
		if (err) {
			unlock_cpu_hotplug();
			goto bad;
		}
	}
	unlock_cpu_hotplug();
	mutex_unlock(&threads.lock);
	return 0;
	
bad:
	unregister_cpu_notifier(&cpu_notifier);
	for_each_possible_cpu(cpu)
		cpu_stop(cpu);
	return err;
}

void __exit thread_shutdown(void)
{
	int cpu;
	
	mutex_lock(&threads.lock);
	unregister_cpu_notifier(&cpu_notifier);
	for_each_possible_cpu(cpu)
		cpu_stop(cpu);
	mutex_unlock(&threads.lock);
}
