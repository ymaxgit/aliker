#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/vmalloc.h>
#include <linux/hash.h>

#include <net/net_namespace.h>
#include <net/ipv6.h>

int sysctl_tcp_fastopen;

struct tfo_inetpeer_addr_base {
	union {
		__be32 a4;
		__be32 a6[4];
	};
};

struct tfo_inetpeer_addr {
	struct tfo_inetpeer_addr_base addr;
	__u16			      family;
};

struct tcp_fastopen_metrics {
	u16 mss;
	struct tcp_fastopen_cookie cookie;
};

struct tfo_hash_entry {
	struct tfo_hash_entry __rcu *tfoe_next;
	struct tfo_inetpeer_addr     tfoe_addr;
	unsigned long		     tfoe_stamp;
	struct tcp_fastopen_metrics  tfoe_fastopen;
};

struct tfo_hash_bucket {
	struct tfo_hash_entry __rcu *chain;
};

static DEFINE_SPINLOCK(tfo_hash_lock);

static struct tfo_hash_entry *__tfo_get_entry(const struct tfo_inetpeer_addr *addr,
					      struct net *net, unsigned int hash);

static void tfo_hash_suck_dst(struct tfo_hash_entry *te, struct dst_entry *dst)
{
	te->tfoe_stamp = jiffies;
	te->tfoe_fastopen.mss = 0;
	te->tfoe_fastopen.cookie.len = 0;
}

static bool addr_same(const struct tfo_inetpeer_addr *a,
		      const struct tfo_inetpeer_addr *b)
{
	const struct in6_addr *a6, *b6;

	if (a->family != b->family)
		return false;
	if (a->family == AF_INET)
		return a->addr.a4 == b->addr.a4;

	a6 = (const struct in6_addr *) &a->addr.a6[0];
	b6 = (const struct in6_addr *) &b->addr.a6[0];

	return ipv6_addr_equal(a6, b6);
}

#define TFO_HASH_TIMEOUT	(60 * 60 * HZ)

static void tfo_hash_check_stamp(struct tfo_hash_entry *te, struct dst_entry *dst)
{
	if (te && unlikely(time_after(jiffies, te->tfoe_stamp + TFO_HASH_TIMEOUT)))
		tfo_hash_suck_dst(te, dst);
}

#define TFO_HASH_RECLAIM_DEPTH	5
#define TFO_HASH_RECLAIM_PTR	(struct tfo_hash_entry *) 0x1UL

static struct tfo_hash_entry *tfo_hash_new(struct dst_entry *dst,
					   struct tfo_inetpeer_addr *addr,
					   unsigned int hash)
{
	struct tfo_hash_entry *te;
	struct net *net;
	bool reclaim = false;

	spin_lock_bh(&tfo_hash_lock);
	net = dev_net(dst->dev);

	te = __tfo_get_entry(addr, net, hash);
	if (te == TFO_HASH_RECLAIM_PTR) {
		reclaim = true;
		te = NULL;
	}
	if (te) {
		tfo_hash_check_stamp(te, dst);
		goto out_unlock;
	}

	if (unlikely(reclaim)) {
		struct tfo_hash_entry *oldest;

		oldest = rcu_dereference(net->ipv4.tfo_hash[hash].chain);
		for (te = rcu_dereference(oldest->tfoe_next); te;
		     te = rcu_dereference(te->tfoe_next)) {
			if (time_before(te->tfoe_stamp, oldest->tfoe_stamp))
				oldest = te;
		}
		te = oldest;
	} else {
		te = kmalloc(sizeof(*te), GFP_ATOMIC);
		if (!te)
			goto out_unlock;
	}
	te->tfoe_addr = *addr;

	tfo_hash_suck_dst(te, dst);

	if (likely(!reclaim)) {
		te->tfoe_next = net->ipv4.tfo_hash[hash].chain;
		rcu_assign_pointer(net->ipv4.tfo_hash[hash].chain, te);
	}

out_unlock:
	spin_unlock_bh(&tfo_hash_lock);
	return te;
}

static struct tfo_hash_entry *tcp_get_encode(struct tfo_hash_entry *te, int depth)
{
	if (te)
		return te;
	if (depth > TFO_HASH_RECLAIM_DEPTH)
		return TFO_HASH_RECLAIM_PTR;
	return NULL;
}

static struct tfo_hash_entry *
__tfo_get_entry(const struct tfo_inetpeer_addr *addr,
		struct net *net, unsigned int hash)
{
	struct tfo_hash_entry *te;
	int depth = 0;

	for (te = rcu_dereference(net->ipv4.tfo_hash[hash].chain); te;
	     te = rcu_dereference(te->tfoe_next)) {
		if (addr_same(&te->tfoe_addr, addr))
			break;
		depth++;
	}
	return tcp_get_encode(te, depth);
}

static struct tfo_hash_entry *tfo_get_entry(struct sock *sk,
					    struct dst_entry *dst, bool create)
{
	struct tfo_hash_entry *te;
	struct tfo_inetpeer_addr addr;
	unsigned int hash;
	struct net *net;

	if (sk->sk_family == AF_INET) {
		addr.family = AF_INET;
		addr.addr.a4 = inet_sk(sk)->daddr;
		hash = (__force unsigned int) addr.addr.a4;
	}
#ifdef CONFIG_IPV6
	else if (sk->sk_family == AF_INET6) {
		if (ipv6_addr_v4mapped(&sk->sk_v6_daddr)) {
			addr.family = AF_INET;
			addr.addr.a4 = inet_sk(sk)->daddr;
			hash = (__force unsigned int) addr.addr.a4;
		} else {
			daddr.family = AF_INET6;
			*(struct in6_addr *) addr.addr.a6 = inet6_sk(sk)->daddr;
			hash = ipv6_addr_hash(inet6_sk(sk)->daddr);
		}
	}
#endif
	else
		return NULL;

	hash ^= (hash >> 24) ^ (hash >> 16) ^ (hash >> 8);

	net = dev_net(dst->dev);
	hash = hash_32(hash, net->ipv4.tfo_hash_log);

	te = __tfo_get_entry(&addr, net, hash);
	if (te == TFO_HASH_RECLAIM_PTR)
		te = NULL;
	if (!te && create)
		te = tfo_hash_new(dst, &addr, hash);
	else
		tfo_hash_check_stamp(te, dst);

	return te;
}

static DEFINE_SEQLOCK(fastopen_seqlock);

void tcp_fastopen_cache_get(struct sock *sk, u16 *mss,
			    struct tcp_fastopen_cookie *cookie)
{
	struct tfo_hash_entry *te;

	rcu_read_lock();
	te = tfo_get_entry(sk, __sk_dst_get(sk), false);
	if (te) {
		struct tcp_fastopen_metrics *tfom = &te->tfoe_fastopen;
		unsigned int seq;

		do {
			seq = read_seqbegin(&fastopen_seqlock);
			if (tfom->mss)
				*mss = tfom->mss;
			*cookie = tfom->cookie;
		} while (read_seqretry(&fastopen_seqlock, seq));
	}
	rcu_read_unlock();
}

void tcp_fastopen_cache_set(struct sock *sk, u16 mss,
			    struct tcp_fastopen_cookie *cookie)
{
	struct tfo_hash_entry *te;

	rcu_read_lock();
	te = tfo_get_entry(sk, __sk_dst_get(sk), true);
	if (te) {
		struct tcp_fastopen_metrics *tfom = &te->tfoe_fastopen;

		write_seqlock_bh(&fastopen_seqlock);
		tfom->mss = mss;
		if (cookie->len > 0)
			tfom->cookie = *cookie;
		write_sequnlock_bh(&fastopen_seqlock);
	}
	rcu_read_unlock();
}

static unsigned long tfo_hash_entries;
static int __init set_tfo_hash_entries(char *str)
{
	ssize_t ret;

	if (!str)
		return 0;

	ret = kstrtoul(str, 0, &tfo_hash_entries);
	if (ret)
		return 0;

	return 1;
}
__setup("tfo_hash_entries", set_tfo_hash_entries);

static int __net_init tfo_hash_init(struct net *net)
{
	int slots, size;

	slots = tfo_hash_entries;
	if (!slots) {
		if (totalram_pages >= 128 * 1024)
			slots = 16 * 1024;
		else
			slots = 8 * 1024;
	}

	net->ipv4.tfo_hash_log = order_base_2(slots);
	size = sizeof(struct tfo_hash_bucket) << net->ipv4.tfo_hash_log;

	net->ipv4.tfo_hash = kzalloc(size, GFP_KERNEL);
	if (!net->ipv4.tfo_hash)
		net->ipv4.tfo_hash = vzalloc(size);

	if (!net->ipv4.tfo_hash)
		return -ENOMEM;

	return 0;
}

static void __net_exit tfo_hash_exit(struct net *net)
{
	unsigned int i;

	for (i = 0; i < (1U << net->ipv4.tfo_hash_log); i++) {
		struct tfo_hash_entry *te, *next;

		te = rcu_dereference_protected(net->ipv4.tfo_hash[i].chain, 1);
		while (te) {
			next = rcu_dereference_protected(te->tfoe_next, 1);
			kfree(te);
			te = next;
		}
	}
	if (is_vmalloc_addr(net->ipv4.tfo_hash))
		vfree(net->ipv4.tfo_hash);
	else
		kfree(net->ipv4.tfo_hash);
}

static __net_initdata struct pernet_operations tfo_hash_ops = {
	.init	=	tfo_hash_init,
	.exit	=	tfo_hash_exit,
};

static int __init tcp_fastopen_init(void)
{
	register_pernet_subsys(&tfo_hash_ops);
	return 0;
}

late_initcall(tcp_fastopen_init);
