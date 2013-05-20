#include <linux/bottom_half.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/hash.h>
#include <linux/kthread.h>
#include <linux/completion.h>

#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/ipv6.h>

#include <linux/inet.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/hookers.h>

/* the maxmimum number of address that we are tracking */
#define RT_TABLE_SIZE	(1<<6)

/* the number of buckets in the response time internal hash table */
#define RT_HASH_TABLE_SIZE	(RT_TABLE_SIZE>>1)
#define RT_HASH_TABLE_MASK	(RT_HASH_TABLE_SIZE-1)

#define RT_ENTRY_BITMAP_SIZE	((RT_TABLE_SIZE)/BITS_PER_LONG + 1)

static int rt_stat_nr_entries_min = 1;
static int rt_stat_nr_entries_max = RT_TABLE_SIZE;
static int sysctl_rt_stat_nr_entries = RT_TABLE_SIZE; /* sample numbers */

static int rt_stat_period_min = 1;
static int rt_stat_period_max = 7200;
static int sysctl_rt_stat_period = 60; /* sampling period, in seconds  */

static int sysctl_rt_stat_on = 1;

struct rt {
	struct rb_node rt_node;
	struct rb_node time_node;
	struct hlist_node ip_node;
	int nr;
	unsigned long jiffies;
	u32 ip;
	int rt;
};

struct rt_stat {
	struct rt entries[RT_TABLE_SIZE];
	unsigned long ready_entries_bitmap[RT_ENTRY_BITMAP_SIZE];
	struct rb_root table;
	struct rb_root time_table;
	struct hlist_head ip_table[RT_HASH_TABLE_SIZE];
};

struct rt_stat_avg {
	unsigned long sum;
	unsigned long count;
};

/* All RT statictis are saved here */
/* It must be accessed under disabled softirq context */
static struct rt_stat __percpu *rt_stat_array;
static struct rt_stat_avg __percpu * rt_avg_array;

static struct sock *tcp_v4_syn_recv_sock_rt_stat(struct sock *sk,
				struct sk_buff *skb, struct request_sock *req,
				struct dst_entry *dst, struct sock **ret);
static struct sock *tcp_v6_syn_recv_sock_rt_stat_spec(struct sock *sk,
				struct sk_buff *skb, struct request_sock *req,
				struct dst_entry *dst, struct sock **ret);
static struct sock *tcp_v6_syn_recv_sock_rt_stat_mapped(struct sock *sk,
				struct sk_buff *skb, struct request_sock *req,
				  struct dst_entry *dst, struct sock **ret);

static struct hooker tcp_v4_hooker = {
	.func = tcp_v4_syn_recv_sock_rt_stat,
};

static struct hooker tcp_v6_spec_hooker = {
	.func = tcp_v6_syn_recv_sock_rt_stat_spec,
};

static struct hooker tcp_v6_mapped_hooker = {
	.func = tcp_v6_syn_recv_sock_rt_stat_mapped,
};

static int rt_table_setup(int cpu)
{
	int i;
	struct rt_stat *rt_stat;
	struct rt_stat_avg *rt_avg;

	if (!rt_avg_array) {
		rt_avg_array = alloc_percpu(struct rt_stat_avg);
		if (!rt_avg_array)
			return -ENOMEM;
	}

	if (!rt_stat_array) {
		rt_stat_array = alloc_percpu(struct rt_stat);
		if (!rt_stat_array) {
			free_percpu(rt_avg_array);
			return -ENOMEM;
		}
	}

	rt_avg = per_cpu_ptr(rt_avg_array, cpu);
	memset(rt_avg, 0, sizeof(struct rt_stat_avg));

	rt_stat = per_cpu_ptr(rt_stat_array, cpu);
	for (i = 0; i < RT_TABLE_SIZE; i++) {
		struct rt *rt = &rt_stat->entries[i];

		memset(rt, 0, sizeof(struct rt));
		rt->nr = i;
		RB_CLEAR_NODE(&rt->rt_node);
		RB_CLEAR_NODE(&rt->time_node);
		INIT_HLIST_NODE(&rt->ip_node);
		__set_bit(rt->nr, rt_stat->ready_entries_bitmap);
	}

	rt_stat->table = RB_ROOT;
	rt_stat->time_table = RB_ROOT;
	for (i = 0; i < RT_HASH_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&rt_stat->ip_table[i]);
	return 0;
}

static void rt_remove(struct rt_stat *rt_stat, struct rt *rt)
{
	rb_erase(&rt->rt_node, &rt_stat->table);
	rb_erase(&rt->time_node, &rt_stat->time_table);
	hlist_del_init(&rt->ip_node);
	RB_CLEAR_NODE(&rt->rt_node);
	RB_CLEAR_NODE(&rt->time_node);
	rt->jiffies = 0UL;
	rt->ip = 0;
	rt->rt = 0;
	/* only get_rt_entry() and rt_aging() update free-bitmap */
}

static struct rt *get_rt_entry(struct rt_stat *rt_stat)
{
	struct rt *rt;
	unsigned long idx;

	idx = find_first_bit(rt_stat->ready_entries_bitmap,
					sysctl_rt_stat_nr_entries);
	if (idx < sysctl_rt_stat_nr_entries) {
		rt = &rt_stat->entries[idx];
		__clear_bit(idx, rt_stat->ready_entries_bitmap);
		/* rt_aging() will recycle these entries */
		return rt;
	}
	return NULL;
}

static int rt_aging(struct rt_stat *rt_stat, unsigned long now)
{
	struct rb_node *n;
	struct rt *earliest;
	unsigned long prev;

	/*
	 * We do not care sysctl_rt_stat_nr_entries here, so that
	 * decreasing that sysctl parameter has not effect on RT
	 * statistics at once.
	 */

	prev = now - HZ*sysctl_rt_stat_period;
	if (unlikely((long)prev < 0))
		return -ENODEV;

	n = rb_first(&rt_stat->time_table);
	if (!n)
		return 0;
	earliest = container_of(n, struct rt, time_node);
	while (time_before(earliest->jiffies, prev)) {
		rt_remove(rt_stat, earliest);
		__set_bit(earliest->nr, rt_stat->ready_entries_bitmap);
		n = rb_first(&rt_stat->time_table);
		if (!n)
			return 0;
		earliest = container_of(n, struct rt, time_node);
	}

	return 0;
}

static void rt_table_insert(struct rt_stat *rt_stat, struct rt *rt)
{
	struct rb_node **new, *parent;

	new = &rt_stat->table.rb_node;
	parent = NULL;
	while (*new) {
		struct rt *this = container_of(*new, struct rt, rt_node);
		int result = rt->rt - this->rt;

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else /* >= */
			new = &((*new)->rb_right);
	}
	rb_link_node(&rt->rt_node, parent, new);
	rb_insert_color(&rt->rt_node, &rt_stat->table);
}

static inline void rt_table_adjust(struct rt_stat *rt_stat,
						struct rt *rt, int interval)
{
	rt->rt = interval;
	rb_erase(&rt->rt_node, &rt_stat->table);
	rt_table_insert(rt_stat, rt);
}

static void rt_time_table_insert(struct rt_stat *rt_stat, struct rt *rt)
{
	struct rb_node **new, *parent;

	new = &rt_stat->time_table.rb_node;
	parent = NULL;
	while (*new) {
		parent = *new;
		new = &((*new)->rb_right);
	}
	rb_link_node(&rt->time_node, parent, new);
	rb_insert_color(&rt->time_node, &rt_stat->time_table);
}

static inline void rt_time_table_adjust(struct rt_stat *rt_stat,
					struct rt *rt, unsigned long now)
{
	rt->jiffies = now;
	rb_erase(&rt->time_node, &rt_stat->time_table);
	rt_time_table_insert(rt_stat, rt);
}

/* return NULL if rt_stat update process is done */
static struct hlist_head *update_existed_rt(struct rt_stat *rt_stat,
					unsigned long now, u32 ip, int interval)
{
	struct hlist_head *bucket;
	struct hlist_node *node;
	struct rt *rt;
	unsigned int key;

	key = ip * GOLDEN_RATIO_PRIME_32;
	key &= RT_HASH_TABLE_MASK;
	bucket = &rt_stat->ip_table[key];
	hlist_for_each_entry(rt, node, bucket, ip_node) {
		if (rt->ip == ip)
			break;
	}
	if (!node)	/* not found */
		return bucket;

	if (rt->rt >= interval)
		return NULL;

	if (time_after(now, rt->jiffies))
		rt_time_table_adjust(rt_stat, rt, now);

	rt_table_adjust(rt_stat, rt, interval);
	return NULL;
}

static void replace_rt(struct rt_stat *rt_stat,
	unsigned long now, u32 ip, int interval, struct hlist_head *bucket)
{
	struct rb_node **new, *parent;
	struct rb_node *shortest_node;
	struct rt *shortest;
	int is_shortest;

	new = &rt_stat->table.rb_node;
	parent = NULL;
	is_shortest = 1;
	while (*new) {
		struct rt *this = container_of(*new, struct rt, rt_node);
		int result = interval - this->rt;

		parent = *new;
		if (result <= 0)
			new = &((*new)->rb_left);
		else {
			is_shortest = 0;
			new = &((*new)->rb_right);
		}
	}

	if (is_shortest)
		return; /* this RT is shorter than all recorded rt_entry */

	shortest_node = rb_first(&rt_stat->table);
	shortest = container_of(shortest_node, struct rt, rt_node);

	if (time_after(now, shortest->jiffies))
		rt_time_table_adjust(rt_stat, shortest, now);

	if (shortest->rt != interval)
		rt_table_adjust(rt_stat, shortest, interval);

	hlist_del_init(&shortest->ip_node);
	shortest->ip = ip;
	hlist_add_head(&shortest->ip_node, bucket);
}

static void rt_table_update(int cpu, unsigned long now, u32 ip, int interval)
{
	struct hlist_head *bucket;
	struct rt *rt;
	struct rt_stat *rt_stat;

	rt_stat = per_cpu_ptr(rt_stat_array, cpu);

	if (rt_aging(rt_stat, now))
		return;

	bucket = update_existed_rt(rt_stat, now, ip, interval);
	if (!bucket)
		return; /* we already updated an existed rt entry */

	rt = get_rt_entry(rt_stat);
	if (rt) { /* we have a empty rt_entry to add */
		rt->ip = ip;
		hlist_add_head(&rt->ip_node, bucket);
		rt->jiffies = now;
		rt_time_table_insert(rt_stat, rt);
		rt->rt = interval;
		rt_table_insert(rt_stat, rt);
		return;
	}
	replace_rt(rt_stat, now, ip, interval, bucket);
}

static inline void rt_avg_update(unsigned int cpu, s64 interval)
{
	struct rt_stat_avg *rt_avg;

	rt_avg = per_cpu_ptr(rt_avg_array, cpu);
	rt_avg->sum += interval;
	rt_avg->count++;

	/*
	 * Don't compute avgerage RT now, leave it to userland.
	 */
}

static void tcp_rt_stat(unsigned int cpu, struct request_sock *req)
{
	s64 interval;
	u64 now;

	now = get_jiffies_64();
	interval = (s64)now - (s64)req->ts_incoming;
	if (unlikely(interval < 0))
		return;

	rt_avg_update(cpu, interval);

	local_bh_disable();
	rt_table_update(cpu, jiffies, inet_rsk(req)->rmt_addr, (int)interval);
	local_bh_enable();
}

static inline struct sock *do_tcp_rt_stat(struct hooker *hooker,
				struct sock *sk, struct sk_buff *skb,
				struct request_sock *req, struct dst_entry *dst)
{
	unsigned cpu;

	preempt_disable();
	cpu = smp_processor_id();
	if (req->ts_incoming
			&& !req->retrans
			&& AF_INET == req->rsk_ops->family) {
		tcp_rt_stat(cpu, req);
		req->ts_incoming = 0;
	}
	preempt_enable();

	return NULL;
}

static struct sock *tcp_v4_syn_recv_sock_rt_stat(struct sock *sk,
				struct sk_buff *skb, struct request_sock *req,
				struct dst_entry *dst, struct sock **ret)
{
	return do_tcp_rt_stat(&tcp_v4_hooker, sk, skb, req, dst);
}

static struct sock *tcp_v6_syn_recv_sock_rt_stat_spec(struct sock *sk,
				struct sk_buff *skb, struct request_sock *req,
				struct dst_entry *dst, struct sock **ret)
{
	return do_tcp_rt_stat(&tcp_v6_spec_hooker, sk, skb, req, dst);
}

static struct sock *tcp_v6_syn_recv_sock_rt_stat_mapped(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req,
				  struct dst_entry *dst, struct sock **ret)
{
	return do_tcp_rt_stat(&tcp_v6_mapped_hooker, sk, skb, req, dst);
}

struct rt_stat_snapshot_t {
	struct completion done;
	struct rt entries[RT_TABLE_SIZE];
	int cursor;
	unsigned long sum;
	unsigned long count;
};

static int rt_stat_do_snapshot(void *p)
{
	int cpu;
	struct rt_stat_snapshot_t *s = (struct rt_stat_snapshot_t *)p;
	struct rt_stat *rt_stat;
	struct rt_stat_avg *rt_avg;
	struct rb_node *node;
	int i;

	local_bh_disable();

	cpu = smp_processor_id();
	rt_stat = per_cpu_ptr(rt_stat_array, cpu);
	rt_aging(rt_stat, jiffies);

	node = rb_last(&rt_stat->table);
	i = 0;
	while (node) {
		struct rt *rt = container_of(node, struct rt, rt_node);
		s->entries[i++] = *rt;
		node = rb_prev(node);
	}
	rt_avg = per_cpu_ptr(rt_avg_array, cpu);
	s->sum = rt_avg->sum;
	s->count = rt_avg->count;

	local_bh_enable();

	complete(&s->done);
	return 0;
}

static struct rt_stat_snapshot_t *rt_stat_snapshot_create(void)
{
	long cpu;
	struct rt_stat_snapshot_t *s, *this_s;

	s = alloc_percpu(struct rt_stat_snapshot_t);
	if (!s)
		return NULL;

	for_each_possible_cpu(cpu) {
		this_s = per_cpu_ptr(s, cpu);
		memset(&this_s->entries, 0, sizeof(struct rt)*RT_TABLE_SIZE);
		init_completion(&this_s->done);
		this_s->sum = 0;
		this_s->count = 0;
		this_s->cursor = 0;
	}

	for_each_online_cpu(cpu) {
		struct task_struct *t;

		this_s = per_cpu_ptr(s, cpu);
		t = kthread_create(rt_stat_do_snapshot,
					(void *)this_s, "rt_stat/%ld", cpu);
		if (IS_ERR(t))
			goto err;
		kthread_bind(t, cpu);
		wake_up_process(t);
		wait_for_completion(&this_s->done);
	}

	return s;

err:
	free_percpu(s);
	return NULL;
}

static int rt_stat_snapshot_check_duplicate(struct rt_stat_snapshot_t *s,
							struct rt *max_rt)
{
	int cpu;
	struct rt *rt;
	struct rt_stat_snapshot_t *this_s;

	for_each_online_cpu(cpu) {
		int i;

		this_s = per_cpu_ptr(s, cpu);
		for (i = 0; i < this_s->cursor; i++) {
			rt = &this_s->entries[i];
			if (rt != max_rt && rt->ip == max_rt->ip)
				return 1;
		}
	}
	return 0;
}

static struct rt *rt_stat_snapshot_next(struct rt_stat_snapshot_t *s,
								loff_t *pos)
{
	int cpu, cursor, *max_cursor = NULL;
	struct rt *rt, *max_rt, zero_rt;
	struct rt_stat_snapshot_t *this_s;

	if (*pos >= sysctl_rt_stat_nr_entries)
		return NULL;

	zero_rt.rt = 0;
find_next:
	max_rt = &zero_rt;
	for_each_online_cpu(cpu) {
		this_s = per_cpu_ptr(s, cpu);
		cursor = this_s->cursor;

		if (cursor >= RT_TABLE_SIZE)
			continue;
		rt = &this_s->entries[cursor];
		if (!rt->ip || !rt->rt)
			continue;
		if (rt->rt > max_rt->rt) {
			max_rt = rt;
			max_cursor = &this_s->cursor;
		}
	}

	if (max_rt->rt) {
		(*max_cursor)++;
		if (rt_stat_snapshot_check_duplicate(s, max_rt))
			goto find_next;
		(*pos)++;
		return max_rt;
	}

	*pos = sysctl_rt_stat_nr_entries;
	return NULL;
}

static void *rt_stat_seq_start(struct seq_file *seq, loff_t *pos)
{
	unsigned long sum, count;
	int cpu;
	struct rt_stat_snapshot_t *s;
	void *v;

	if (*pos >= sysctl_rt_stat_nr_entries)
		return NULL;

	s = seq->private;
	sum = count = 0;
	for_each_online_cpu(cpu) {
		struct rt_stat_snapshot_t *this_s = per_cpu_ptr(s, cpu);
		sum += jiffies_to_msecs(this_s->sum);
		count += this_s->count;
	}

	v = rt_stat_snapshot_next(s, pos);
	if (v) {
		seq_printf(seq, "Sum: %lums\n", sum);
		seq_printf(seq, "Count: %lu\n", count);
	}
	return v;
}

static void *rt_stat_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct rt_stat_snapshot_t *s;

	s = (struct rt_stat_snapshot_t *)seq->private;
	return rt_stat_snapshot_next(s, pos);
}

static void rt_stat_seq_stop(struct seq_file *seq, void *v)
{
	struct rt_stat_snapshot_t *s;

	s = (struct rt_stat_snapshot_t *)seq->private;
	if (s) {
		free_percpu(s);
		seq->private = NULL;
	}
}

static int rt_stat_seq_show(struct seq_file *seq, void *v)
{
	struct rt *rt = (struct rt *)v;
	seq_printf(seq, "%pI4 %ums\n", &rt->ip, jiffies_to_msecs(rt->rt));
	return 0;
}

static const struct seq_operations rt_stat_seq_ops = {
	.start = rt_stat_seq_start,
	.next  = rt_stat_seq_next,
	.stop  = rt_stat_seq_stop,
	.show  = rt_stat_seq_show,
};

static int rt_stat_seq_open(struct inode *inode, struct file *file)
{
	int ret;
	struct rt_stat_snapshot_t *s;

	s = rt_stat_snapshot_create();
	if (!s)
		return -ENOMEM;

	ret = seq_open(file, &rt_stat_seq_ops);
	if (ret)
		return ret;

	((struct seq_file *)file->private_data)->private = s;
	return 0;
}

static int rt_stat_seq_release(struct inode *ino, struct file *f)
{
	struct seq_file *seq;
	struct rt_stat_snapshot_t *s;

	seq = (struct seq_file *)f->private_data;
	s = (struct rt_stat_snapshot_t *)seq->private;
	if (s) {
		free_percpu(s);
		seq->private = NULL;
	}

	seq_release(ino, f);
	return 0;
}

static const struct file_operations tcp_ipv4_rt_stat_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = rt_stat_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = rt_stat_seq_release,
};

static void percpu_data_clearup(void)
{
	free_percpu(rt_avg_array);
	rt_avg_array = NULL;
	free_percpu(rt_stat_array);
	rt_stat_array = NULL;
}

static int percpu_data_setup(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (rt_table_setup(cpu)) {
			percpu_data_clearup();
			return -ENOMEM;
		}
	}

	return 0;
}

static int rt_stat_on_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int old_on, ret;

	old_on = sysctl_rt_stat_on;
	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret || old_on == sysctl_rt_stat_on)
		return ret;
	if (sysctl_rt_stat_on) {
		ret = hooker_install(&ipv4_specific.syn_recv_sock,
							&tcp_v4_hooker);
		ret |= hooker_install(&ipv6_specific.syn_recv_sock,
							&tcp_v6_spec_hooker);
		ret |= hooker_install(&ipv6_mapped.syn_recv_sock,
							&tcp_v6_mapped_hooker);
		if (ret) {
			hooker_uninstall(&tcp_v4_hooker);
			hooker_uninstall(&tcp_v6_spec_hooker);
			hooker_uninstall(&tcp_v6_mapped_hooker);
			printk(KERN_INFO "rt_stat: the hookers install failed,");
			return -ENODEV;
		}
		sysctl_rt_stat_on = 1;
	} else {
		hooker_uninstall(&tcp_v4_hooker);
		hooker_uninstall(&tcp_v6_spec_hooker);
		hooker_uninstall(&tcp_v6_mapped_hooker);
	}
	return 0;
}

static ctl_table rt_stat_table[] = {
	{
	.ctl_name = CTL_UNNUMBERED,
	.procname = "nr_entries",
	.data = &sysctl_rt_stat_nr_entries,
	.maxlen = sizeof(int),
	.mode = 0644,
	.proc_handler = &proc_dointvec_minmax,
	.extra1 = &rt_stat_nr_entries_min,
	.extra2 = &rt_stat_nr_entries_max
	},

	{
	.ctl_name = CTL_UNNUMBERED,
	.procname = "period",
	.data = &sysctl_rt_stat_period,
	.maxlen = sizeof(int),
	.mode = 0644,
	.proc_handler = &proc_dointvec_minmax,
	.extra1 = &rt_stat_period_min,
	.extra2 = &rt_stat_period_max
	},

	{
	.ctl_name = CTL_UNNUMBERED,
	.procname = "switch",
	.data = &sysctl_rt_stat_on,
	.maxlen = sizeof(int),
	.mode = 0644,
	.proc_handler = &rt_stat_on_handler,
	},

	{.ctl_name = 0}
};

static ctl_table rt_stat_root[] = {
	{
	.ctl_name = CTL_UNNUMBERED,
	.procname = "rt_stat",
	.maxlen = 0,
	.mode = 0555,
	.child = rt_stat_table,
	},
	{.ctl_name = 0}
};

static struct ctl_table_header *sysctl_header;

int rt_stat_init(void)
{
	int ret;

	/* only support IPv4 and IPv6-mapped IPv4 family so far */
	ret = hooker_install(&ipv4_specific.syn_recv_sock,
							&tcp_v4_hooker);
	ret |= hooker_install(&ipv6_specific.syn_recv_sock,
							&tcp_v6_spec_hooker);
	ret |= hooker_install(&ipv6_mapped.syn_recv_sock,
							&tcp_v6_mapped_hooker);
	if (ret) {
		printk(KERN_INFO "rt_stat: the hookers install failed,");
		goto exit_hookers;
	}

	if (!proc_net_fops_create(&init_net, "tcp_rt_stat", \
					S_IRUGO, &tcp_ipv4_rt_stat_seq_fops)) {
		printk(KERN_INFO "rt_stat: failed to create proc entries.");
		ret = -ENODEV;
		goto exit_hookers;
	}

	ret = percpu_data_setup();
	if (ret) {
		printk(KERN_INFO "rt_stat: failed to setup percpu array\n");
		ret = -ENODEV;
		goto exit_proc;
	}

	sysctl_header = register_sysctl_table(rt_stat_root);
	if (!sysctl_header) {
		printk(KERN_INFO "rt_stat: failed to register sysctl table\n");
		ret = -ENODEV;
		goto exit_percpu;
	}

	return 0;

exit_percpu:
	percpu_data_clearup();
exit_proc:
	proc_net_remove(&init_net, "tcp_rt_stat");
exit_hookers:
	hooker_uninstall(&tcp_v4_hooker);
	hooker_uninstall(&tcp_v6_spec_hooker);
	hooker_uninstall(&tcp_v6_mapped_hooker);
	return ret;
}

void rt_stat_exit(void)
{
	hooker_uninstall(&tcp_v4_hooker);
	hooker_uninstall(&tcp_v6_spec_hooker);
	hooker_uninstall(&tcp_v6_mapped_hooker);

	unregister_sysctl_table(sysctl_header);
	proc_net_remove(&init_net, "tcp_rt_stat");
	percpu_data_clearup();
}

module_init(rt_stat_init);
module_exit(rt_stat_exit);
MODULE_LICENSE("GPL");
