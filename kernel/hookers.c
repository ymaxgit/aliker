#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/hookers.h>

#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/transp_v6.h>
#include <net/inet_common.h>
#include <net/ipv6.h>
#include <linux/inet.h>

struct hooked_place {
	char *name;	/* position information shown in procfs */
	void *place;	/* the kernel address to be hook */
	void *orig;	/* original content at hooked place */
	void *stub;	/* hooker function stub */
	int nr_hookers;	/* how many hookers are linked at below chain */
	struct list_head chain;	/* hookers chain */
};

static spinlock_t hookers_lock;

static struct sock *ipv4_specific_syn_recv_sock_stub(struct sock *sk,
		struct sk_buff *skb, struct request_sock *req,
		struct dst_entry *dst);
static struct sock *ipv6_specific_syn_recv_sock_stub(struct sock *sk,
		struct sk_buff *skb, struct request_sock *req,
		struct dst_entry *dst);
static struct sock *ipv6_mapped_syn_recv_sock_stub(struct sock *sk,
		struct sk_buff *skb, struct request_sock *req,
		struct dst_entry *dst);
static int inet_stream_ops_getname_stub(struct socket *sock,
		struct sockaddr *uaddr, int *uaddr_len, int peer);
static int inet6_stream_ops_getname_stub(struct socket *sock,
		struct sockaddr *uaddr, int *uaddr_len, int peer);

static struct hooked_place place_table[] = {

	{
		.name = "ipv4_specific.syn_recv_sock",
		.place = &ipv4_specific.syn_recv_sock,
		.stub = ipv4_specific_syn_recv_sock_stub,
	},

	{
		.name = "ipv6_specific.syn_recv_sock",
		.place = &ipv6_specific.syn_recv_sock,
		.stub = ipv6_specific_syn_recv_sock_stub,
	},

	{
		.name = "ipv6_mapped.syn_recv_sock",
		.place = &ipv6_mapped.syn_recv_sock,
		.stub = ipv6_mapped_syn_recv_sock_stub,
	},

	{
		.name = "inet_stream_ops.getname",
		.place = &inet_stream_ops.getname,
		.stub = inet_stream_ops_getname_stub,
	},

	{
		.name = "inet6_stream_ops.getname",
		.place = &inet6_stream_ops.getname,
		.stub = inet6_stream_ops_getname_stub,
	},

};

static struct sock *__syn_recv_sock_hstub(struct hooked_place *place,
				struct sock *sk, struct sk_buff *skb,
			  struct request_sock *req, struct dst_entry *dst)
{
	struct hooker *iter;
	struct sock *(*hooker_func)(struct sock *sk, struct sk_buff *skb,
		  struct request_sock *req, struct dst_entry *dst,
						struct sock **ret);
	struct sock *(*orig_func)(struct sock *sk, struct sk_buff *skb,
		  struct request_sock *req, struct dst_entry *dst);
	struct sock *ret;

	orig_func = place->orig;
	ret = orig_func(sk, skb, req, dst);

	rcu_read_lock();
	list_for_each_entry_rcu(iter, &place->chain, chain) {
		hooker_func = iter->func;
		hooker_func(sk, skb, req, dst, &ret);
	}
	rcu_read_unlock();

	return ret;
}

static int __getname_hstub(struct hooked_place *place,
				struct socket *sock, struct sockaddr *uaddr,
						int *uaddr_len, int peer)
{
	struct hooker *iter;
	int (*hooker_func)(struct socket *sock, struct sockaddr *uaddr,
			 int *uaddr_len, int peer, int *ret);
	int (*orig_func)(struct socket *sock, struct sockaddr *uaddr,
			 int *uaddr_len, int peer);
	int ret;

	orig_func = place->orig;
	ret = orig_func(sock, uaddr, uaddr_len, peer);

	rcu_read_lock();
	list_for_each_entry_rcu(iter, &place->chain, chain) {
		hooker_func = iter->func;
		hooker_func(sock, uaddr, uaddr_len, peer, &ret);
	}
	rcu_read_unlock();

	return ret;
}

static struct sock *ipv4_specific_syn_recv_sock_stub(struct sock *sk,
		struct sk_buff *skb, struct request_sock *req,
		struct dst_entry *dst)
{
	return __syn_recv_sock_hstub(&place_table[0], sk, skb, req, dst);
}

static struct sock *ipv6_specific_syn_recv_sock_stub(struct sock *sk,
		struct sk_buff *skb, struct request_sock *req,
		struct dst_entry *dst)
{
	return __syn_recv_sock_hstub(&place_table[1], sk, skb, req, dst);
}

static struct sock *ipv6_mapped_syn_recv_sock_stub(struct sock *sk,
		struct sk_buff *skb, struct request_sock *req,
		struct dst_entry *dst)
{
	return __syn_recv_sock_hstub(&place_table[2], sk, skb, req, dst);
}

static int inet_stream_ops_getname_stub(struct socket *sock,
		struct sockaddr *uaddr, int *uaddr_len, int peer)
{
	return __getname_hstub(&place_table[3], sock, uaddr, uaddr_len, peer);
}

static int inet6_stream_ops_getname_stub(struct socket *sock,
		struct sockaddr *uaddr, int *uaddr_len, int peer)
{
	return __getname_hstub(&place_table[4], sock, uaddr, uaddr_len, peer);
}

#define PLACE_TABLE_SZ	(sizeof((place_table))/sizeof((place_table)[0]))

int hooker_install(void *place, struct hooker *h)
{
	int i;
	struct hooked_place *hplace;

	might_sleep(); /* synchronize_rcu() */

	if (!place || !h || !h->func)
		return -EINVAL;

	for (i = 0; i < PLACE_TABLE_SZ; i++) {
		hplace = &place_table[i];
		if (hplace->place == place) {
			INIT_LIST_HEAD(&h->chain);
			spin_lock(&hookers_lock);
			hplace->nr_hookers++;
			h->hplace = hplace;
			list_add_tail_rcu(&h->chain, &place_table[i].chain);
			spin_unlock(&hookers_lock);
			synchronize_rcu();
			break;
		}
	}

	return (i >= PLACE_TABLE_SZ) ? -EINVAL : 0;
}
EXPORT_SYMBOL_GPL(hooker_install);

void hooker_uninstall(struct hooker *h)
{
	might_sleep(); /* synchronize_rcu(); */

	spin_lock(&hookers_lock);
	list_del_rcu(&h->chain);
	h->hplace->nr_hookers--;
	h->hplace = NULL;
	spin_unlock(&hookers_lock);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(hooker_uninstall);

static void *hookers_seq_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos < PLACE_TABLE_SZ)
		return &place_table[*pos];
	return NULL;
}

static void *hookers_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (++(*pos) >= PLACE_TABLE_SZ)
		return NULL;

	return (void *)&place_table[*pos];
}

static void hookers_seq_stop(struct seq_file *seq, void *v)
{
}

static int hookers_seq_show(struct seq_file *seq, void *v)
{
	struct hooked_place *hplace = (struct hooked_place *)v;

	seq_printf(seq, "name:%-24s addr:0x%p hookers:%-10d\n",
			hplace->name, hplace->place, hplace->nr_hookers);
	return 0;
}

static const struct seq_operations hookers_seq_ops = {
	.start = hookers_seq_start,
	.next  = hookers_seq_next,
	.stop  = hookers_seq_stop,
	.show  = hookers_seq_show,
};

static int hookers_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &hookers_seq_ops);
}

static const struct file_operations hookers_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = hookers_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int hookers_init(void)
{
	int i;

	if (!proc_create("hookers", 0, NULL, &hookers_seq_fops))
		return -ENODEV;

	spin_lock_init(&hookers_lock);
	for (i = 0; i < PLACE_TABLE_SZ; i++) {
		void **place = place_table[i].place;

		place_table[i].orig = *place;
		INIT_LIST_HEAD(&place_table[i].chain);
		if (!place_table[i].stub)
			break;
		*place = place_table[i].stub;
	}

	return 0;
}

static void hookers_exit(void)
{
	int i;

	remove_proc_entry("hookers", NULL);

	for (i = 0; i < PLACE_TABLE_SZ; i++) {
		void **place = place_table[i].place;
		*place = place_table[i].orig;
	}
	synchronize_rcu();
}

module_init(hookers_init);
module_exit(hookers_exit);
MODULE_LICENSE("GPL");
