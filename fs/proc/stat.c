#include <linux/cpumask.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/irqnr.h>
#include <asm/cputime.h>
#include <linux/tick.h>
#include <linux/cgroup.h>
#include <linux/cpuset.h>
#include <linux/cpumask.h>
#include <linux/pid_namespace.h>

#ifndef arch_irq_stat_cpu
#define arch_irq_stat_cpu(cpu) 0
#endif
#ifndef arch_irq_stat
#define arch_irq_stat() 0
#endif

#ifdef CONFIG_CGROUP_CPUACCT
extern struct kernel_cpustat *task_ca_kcpustat_ptr(struct task_struct*, int);
extern bool task_in_nonroot_cpuacct(struct task_struct *);
extern unsigned long task_ca_running(struct task_struct *, int);
#else
bool task_in_nonroot_cpuacct(struct task_struct *tsk) { return false; }
struct kernel_cpustat *task_ca_kcpustat_ptr(struct task_struct*, int) { return NULL; }
unsigned long task_ca_running(struct task_struct *, int) { return 0; }
#endif

#ifdef arch_idle_time

static cputime64_t get_idle_time(int cpu)
{
	cputime64_t idle;

	idle = kstat_cpu(cpu).cpustat.idle;
	if (cpu_online(cpu) && !nr_iowait_cpu(cpu))
		idle += arch_idle_time(cpu);
	return idle;
}

static cputime64_t get_iowait_time(int cpu)
{
	cputime64_t iowait;

	iowait = kstat_cpu(cpu).cpustat.iowait;
	if (cpu_online(cpu) && nr_iowait_cpu(cpu))
		iowait += arch_idle_time(cpu);
	return iowait;
}

#else

#define arch_idle_time(cpu) 0

u64 get_idle_time(int cpu)
{
	u64 idle, idle_time = get_cpu_idle_time_us(cpu, NULL);

	if (idle_time == -1ULL)
		/* !NO_HZ so we can rely on cpustat.idle */
		idle = kcpustat_cpu(cpu).cpustat[CPUTIME_IDLE];
	else
		idle = usecs_to_cputime64(idle_time);

	return idle;
}

u64 get_iowait_time(int cpu)
{
	u64 iowait, iowait_time = get_cpu_iowait_time_us(cpu, NULL);

	if (iowait_time == -1ULL)
		/* !NO_HZ so we can rely on cpustat.iowait */
		iowait = kcpustat_cpu(cpu).cpustat[CPUTIME_IOWAIT];
	else
		iowait = usecs_to_cputime64(iowait_time);

	return iowait;
}

#endif

static int show_stat(struct seq_file *p, void *v)
{
	int i, j, seq = 0;
	unsigned long jif;
	u64 user, nice, system, idle, iowait, irq, softirq, steal;
	u64 guest;
	u64 sum = 0;
	u64 sum_softirq = 0;
	unsigned int per_softirq_sums[NR_SOFTIRQS] = {0};
	struct timespec boottime;
	struct kernel_cpustat *kcpustat;
	struct cpumask cpus_allowed;
	unsigned long nr_runnable = 0;

	user = nice = system = idle = iowait =
		irq = softirq = steal = 0;
	guest = 0;
	getboottime(&boottime);
	jif = boottime.tv_sec;

	rcu_read_lock();
	if (in_noninit_pid_ns(current->nsproxy->pid_ns) &&
		task_in_nonroot_cpuacct(current)) {

		/*-----fix btime in instance-----*/
		struct task_struct *init_tsk = NULL;
		if (likely(current->nsproxy->pid_ns))
			init_tsk = current->nsproxy->pid_ns->child_reaper;
		if (likely(init_tsk))
			jif = jif + init_tsk->start_time.tv_sec;
		/* ----------end----------- */

		cpumask_copy(&cpus_allowed, cpu_possible_mask);
		if (task_subsys_state(current, cpuset_subsys_id)) {
			memset(&cpus_allowed, 0, sizeof(cpus_allowed));
			get_tsk_cpu_allowed(current, &cpus_allowed);
		}

		for_each_cpu_and(i, cpu_possible_mask, &cpus_allowed) {
			kcpustat = task_ca_kcpustat_ptr(current, i);
			user += kcpustat->cpustat[CPUTIME_USER];
			nice += kcpustat->cpustat[CPUTIME_NICE];
			system += kcpustat->cpustat[CPUTIME_SYSTEM];
			guest += kcpustat->cpustat[CPUTIME_GUEST];

			idle += kcpustat_cpu(i).cpustat[CPUTIME_IDLE];
			idle += arch_idle_time(i);
			idle -= kcpustat->cpustat[CPUTIME_IDLE_BASE];

			iowait += kcpustat_cpu(i).cpustat[CPUTIME_IOWAIT];
			iowait -= kcpustat->cpustat[CPUTIME_IOWAIT_BASE];

			irq += kcpustat->cpustat[CPUTIME_IRQ];
			softirq += kcpustat->cpustat[CPUTIME_SOFTIRQ];

			steal += kcpustat_cpu(i).cpustat[CPUTIME_USER]
				- kcpustat->cpustat[CPUTIME_USER]
				+ kcpustat_cpu(i).cpustat[CPUTIME_NICE]
				- kcpustat->cpustat[CPUTIME_NICE]
				+ kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM]
				- kcpustat->cpustat[CPUTIME_SYSTEM]
				+ kcpustat_cpu(i).cpustat[CPUTIME_IRQ]
				- kcpustat->cpustat[CPUTIME_IRQ]
				+ kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ]
				- kcpustat->cpustat[CPUTIME_SOFTIRQ]
				+ kcpustat_cpu(i).cpustat[CPUTIME_GUEST]
				- kcpustat->cpustat[CPUTIME_GUEST]
				- kcpustat->cpustat[CPUTIME_STEAL_BASE];
		}
	} else {
		for_each_possible_cpu(i) {
			user += kcpustat_cpu(i).cpustat[CPUTIME_USER];
			nice += kcpustat_cpu(i).cpustat[CPUTIME_NICE];
			system += kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
			idle += get_idle_time(i);
			iowait += get_iowait_time(i);
			irq += kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
			softirq += kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
			steal += kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
			guest += kcpustat_cpu(i).cpustat[CPUTIME_GUEST];
		}

	}
	rcu_read_unlock();

	for_each_possible_cpu(i) {
		sum += kstat_cpu_irqs_sum(i);
		sum += arch_irq_stat_cpu(i);

		for (j = 0; j < NR_SOFTIRQS; j++) {
			unsigned int softirq_stat = kstat_softirqs_cpu(j, i);

			per_softirq_sums[j] += softirq_stat;
			sum_softirq += softirq_stat;
		}
	}
	sum += arch_irq_stat();

	seq_printf(p,
		"cpu  %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
		(unsigned long long)cputime64_to_clock_t(user),
		(unsigned long long)cputime64_to_clock_t(nice),
		(unsigned long long)cputime64_to_clock_t(system),
		(unsigned long long)cputime64_to_clock_t(idle),
		(unsigned long long)cputime64_to_clock_t(iowait),
		(unsigned long long)cputime64_to_clock_t(irq),
		(unsigned long long)cputime64_to_clock_t(softirq),
		(unsigned long long)cputime64_to_clock_t(steal),
		(unsigned long long)cputime64_to_clock_t(guest));

	rcu_read_lock();
	if (in_noninit_pid_ns(current->nsproxy->pid_ns) &&
		task_in_nonroot_cpuacct(current)) {
		cpumask_copy(&cpus_allowed, cpu_possible_mask);
		if (task_subsys_state(current, cpuset_subsys_id)) {
			memset(&cpus_allowed, 0, sizeof(cpus_allowed));
			get_tsk_cpu_allowed(current, &cpus_allowed);
		}

		for_each_cpu_and(i, cpu_possible_mask, &cpus_allowed) {
			kcpustat = task_ca_kcpustat_ptr(current, i);
			user = kcpustat->cpustat[CPUTIME_USER];
			nice = kcpustat->cpustat[CPUTIME_NICE];
			system = kcpustat->cpustat[CPUTIME_SYSTEM];
			guest = kcpustat->cpustat[CPUTIME_GUEST];

			idle = kcpustat_cpu(i).cpustat[CPUTIME_IDLE];
			idle += arch_idle_time(i);
			idle -= kcpustat->cpustat[CPUTIME_IDLE_BASE];

			iowait = kcpustat_cpu(i).cpustat[CPUTIME_IOWAIT];
			iowait -= kcpustat->cpustat[CPUTIME_IOWAIT_BASE];

			irq = kcpustat->cpustat[CPUTIME_IRQ];
			softirq = kcpustat->cpustat[CPUTIME_SOFTIRQ];

			steal = kcpustat_cpu(i).cpustat[CPUTIME_USER]
				- kcpustat->cpustat[CPUTIME_USER]
				+ kcpustat_cpu(i).cpustat[CPUTIME_NICE]
				- kcpustat->cpustat[CPUTIME_NICE]
				+ kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM]
				- kcpustat->cpustat[CPUTIME_SYSTEM]
				+ kcpustat_cpu(i).cpustat[CPUTIME_IRQ]
				- kcpustat->cpustat[CPUTIME_IRQ]
				+ kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ]
				- kcpustat->cpustat[CPUTIME_SOFTIRQ]
				+ kcpustat_cpu(i).cpustat[CPUTIME_GUEST]
				- kcpustat->cpustat[CPUTIME_GUEST]
				- kcpustat->cpustat[CPUTIME_STEAL_BASE];

			seq_printf(p,
			"cpu%d %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
			seq,
			(unsigned long long)cputime64_to_clock_t(user),
			(unsigned long long)cputime64_to_clock_t(nice),
			(unsigned long long)cputime64_to_clock_t(system),
			(unsigned long long)cputime64_to_clock_t(idle),
			(unsigned long long)cputime64_to_clock_t(iowait),
			(unsigned long long)cputime64_to_clock_t(irq),
			(unsigned long long)cputime64_to_clock_t(softirq),
			(unsigned long long)cputime64_to_clock_t(steal),
			(unsigned long long)cputime64_to_clock_t(guest));

			seq ++;

		}
	} else {
		for_each_online_cpu(i) {
			/* Copy values here to work around gcc-2.95.3, gcc-2.96 */
			user = kcpustat_cpu(i).cpustat[CPUTIME_USER];
			nice = kcpustat_cpu(i).cpustat[CPUTIME_NICE];
			system = kcpustat_cpu(i).cpustat[CPUTIME_SYSTEM];
			idle = get_idle_time(i);
			iowait = get_iowait_time(i);
			irq = kcpustat_cpu(i).cpustat[CPUTIME_IRQ];
			softirq = kcpustat_cpu(i).cpustat[CPUTIME_SOFTIRQ];
			steal = kcpustat_cpu(i).cpustat[CPUTIME_STEAL];
			guest = kcpustat_cpu(i).cpustat[CPUTIME_GUEST];

			seq_printf(p,
			"cpu%d %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
			i,
			(unsigned long long)cputime64_to_clock_t(user),
			(unsigned long long)cputime64_to_clock_t(nice),
			(unsigned long long)cputime64_to_clock_t(system),
			(unsigned long long)cputime64_to_clock_t(idle),
			(unsigned long long)cputime64_to_clock_t(iowait),
			(unsigned long long)cputime64_to_clock_t(irq),
			(unsigned long long)cputime64_to_clock_t(softirq),
			(unsigned long long)cputime64_to_clock_t(steal),
			(unsigned long long)cputime64_to_clock_t(guest));
		}
	}
	rcu_read_unlock();
	seq_printf(p, "intr %llu", (unsigned long long)sum);

	/* sum again ? it could be updated? */
	for_each_irq_nr(j)
		seq_printf(p, " %u", kstat_irqs(j));

	rcu_read_lock();
	if (in_noninit_pid_ns(current->nsproxy->pid_ns) &&
		task_in_nonroot_cpuacct(current)) {
		cpumask_copy(&cpus_allowed, cpu_possible_mask);
		if (task_subsys_state(current, cpuset_subsys_id)) {
			memset(&cpus_allowed, 0, sizeof(cpus_allowed));
			get_tsk_cpu_allowed(current, &cpus_allowed);
		}

		for_each_cpu_and(i, cpu_possible_mask, &cpus_allowed)
			nr_runnable += task_ca_running(current, i);
	} else
		nr_runnable = nr_running();
	rcu_read_unlock();

	seq_printf(p,
		"\nctxt %llu\n"
		"btime %lu\n"
		"processes %lu\n"
		"procs_running %lu\n"
		"procs_blocked %lu\n",
		nr_context_switches(),
		(unsigned long)jif,
		total_forks,
		nr_runnable,
		nr_iowait());

	seq_printf(p, "softirq %llu", (unsigned long long)sum_softirq);

	for (i = 0; i < NR_SOFTIRQS; i++)
		seq_printf(p, " %u", per_softirq_sums[i]);
	seq_printf(p, "\n");

	seq_printf(p, "per_cpu_ctxt");
	nr_context_switches_cpu(p);
	seq_printf(p, "\n");

	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	unsigned size = 4096 * (1 + num_possible_cpus() / 32);
	char *buf;
	struct seq_file *m;
	int res;

	/* don't ask for more than the kmalloc() max size, currently 128 KB */
	if (size > 128 * 1024)
		size = 128 * 1024;
	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	res = single_open(file, show_stat, NULL);
	if (!res) {
		m = file->private_data;
		m->buf = buf;
		m->size = size;
	} else
		kfree(buf);
	return res;
}

static const struct file_operations proc_stat_operations = {
	.open		= stat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_stat_init(void)
{
	proc_create("stat", 0, NULL, &proc_stat_operations);
	return 0;
}
module_init(proc_stat_init);
