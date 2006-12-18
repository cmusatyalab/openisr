#include <linux/kthread.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include "defs.h"

/* XXX percpu vars */
static struct task_struct *thr[NR_CPUS];

/* This will always run on the processor to which it is bound, *except* during
   hot-unplug of that CPU, when it will run on an arbitrary processor. */
static int nexus_thread(void *data)
{
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}
	return 0;
}

static int cpu_start(int cpu)
{
	int err;
	
	BUG_ON(thr[cpu] != NULL);
	thr[cpu]=kthread_create(nexus_thread, NULL, KTHREAD_NAME "/%d", cpu);
	if (IS_ERR(thr[cpu])) {
		err=PTR_ERR(thr[cpu]);
		thr[cpu]=NULL;
		return err;
	}
	kthread_bind(thr[cpu], cpu);
	/* Make sure the thread doesn't have a higher priority than interactive
	   processes (e.g. the X server) because they'll become somewhat
	   less interactive under high I/O load */
	set_user_nice(thr[cpu], 0);
	wake_up_process(thr[cpu]);
	return 0;
}

static void cpu_stop(int cpu)
{
	if (thr[cpu]) {
		debug("Calling kthread_stop on %d", cpu);
		kthread_stop(thr[cpu]);
		debug("...done");
		thr[cpu]=NULL;
	}
}

/* Runs in process context; can sleep */
static int cpu_callback(struct notifier_block *nb, unsigned long action,
			void *data)
{
	int cpu=(int)data;
	
	switch (action) {
	case CPU_ONLINE:
		/* CPU is already up */
		debug("Onlining %d", cpu);
		if (cpu_start(cpu))
			log(KERN_ERR, "Failed to start thread for cpu %d", cpu);
		break;
	case CPU_DEAD:
		/* CPU is already down */
		debug("Offlining %d", cpu);
		cpu_stop(cpu);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block cpu_notifier = {
	.notifier_call = cpu_callback
};

int __init thread_start(void)
{
	int cpu;
	int err;
	
	lock_cpu_hotplug();
	err=register_cpu_notifier(&cpu_notifier);
	if (err) {
		unlock_cpu_hotplug();
		return err;
	}
	for_each_online_cpu(cpu) {
		err=cpu_start(cpu);
		if (err)
			goto bad;
	}
	unlock_cpu_hotplug();
	return 0;
	
bad:
	unregister_cpu_notifier(&cpu_notifier);
	unlock_cpu_hotplug();
	for_each_possible_cpu(cpu)
		cpu_stop(cpu);
	return err;
}

void __exit thread_shutdown(void)
{
	int cpu;
	
	unregister_cpu_notifier(&cpu_notifier);
	for_each_possible_cpu(cpu)
		cpu_stop(cpu);
}
