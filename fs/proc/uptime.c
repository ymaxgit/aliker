#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <linux/pid_namespace.h>
#include <asm/cputime.h>

#ifdef CONFIG_CGROUP_CPUACCT
extern struct kernel_cpustat *task_ca_kcpustat_ptr(struct task_struct*, int);
extern bool task_in_nonroot_cpuacct(struct task_struct *);
#else
bool task_in_nonroot_cpuacct(struct task_struct *tsk)
{
	return false;
}

struct kernel_cpustat *task_ca_kcpustat_ptr(struct task_struct*, int)
{
	return NULL;
}
#endif

static int uptime_proc_show(struct seq_file *m, void *v)
{
	struct timespec uptime;
	struct timespec idle;
	int i;
	u64 idletime = 0;
	struct task_struct *init_tsk;
	struct kernel_cpustat *kcpustat;

	for_each_possible_cpu(i)
		idletime += kcpustat_cpu(i).cpustat[CPUTIME_IDLE];

	do_posix_clock_monotonic_gettime(&uptime);
	monotonic_to_bootbased(&uptime);

	/* instance view in container */
	if (in_noninit_pid_ns(current->nsproxy->pid_ns) &&
		task_in_nonroot_cpuacct(current)) {
		for_each_possible_cpu(i) {
			kcpustat = task_ca_kcpustat_ptr(current, i);
			/*
			 * Cause that CPUs set to this namespace may be changed,
			 * the real idle for this namespace is complicated.
			 *
			 * Just count the global idletime after this namespace 
			 * starts. When namespace is idle, but in global
			 * there still have tasks running, the idle won't be
			 * calculated in.
			 */
			idletime -= kcpustat->cpustat[CPUTIME_IDLE_BASE];
		}
		init_tsk = current->nsproxy->pid_ns->child_reaper;
		uptime = timespec_sub(uptime, init_tsk->start_time);
	}

	cputime_to_timespec(idletime, &idle);
	seq_printf(m, "%lu.%02lu %lu.%02lu\n",
			(unsigned long) uptime.tv_sec,
			(uptime.tv_nsec / (NSEC_PER_SEC / 100)),
			(unsigned long) idle.tv_sec,
			(idle.tv_nsec / (NSEC_PER_SEC / 100)));
	return 0;
}

static int uptime_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, uptime_proc_show, NULL);
}

static const struct file_operations uptime_proc_fops = {
	.open		= uptime_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_uptime_init(void)
{
	proc_create("uptime", 0, NULL, &uptime_proc_fops);
	return 0;
}
module_init(proc_uptime_init);
