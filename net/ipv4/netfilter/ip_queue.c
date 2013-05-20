/*
 * This is a module which is used for queueing IPv4 packets and
 * communicating with userspace via netlink.
 *
 * Support for network namespace at Oct 2011.
 *
 * (C) 2000-2002 James Morris <jmorris@intercode.com.au>
 * (C) 2003-2005 Netfilter Core Team <coreteam@netfilter.org>
 * (C) 2012 Zhu Yanhai <gaoyang.zyh@taobao.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_queue.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/security.h>
#include <linux/net.h>
#include <linux/mutex.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/netfilter/nf_queue.h>
#include <net/ip.h>
#include <linux/hash.h>

#define IPQ_QMAX_DEFAULT 1024
#define IPQ_PROC_FS_NAME "ip_queue"
#define NET_IPQ_QMAX 2088
#define NET_IPQ_QMAX_NAME "ip_queue_maxlen"


#if defined(CONFIG_LOCK_KERNEL)
/* sysctl handler is serialized if the kernel big lock is enabled. */
static inline void ipq_sysctl_lock(void) {};
static inline void ipq_sysctl_unlock(void) {};
#else
static DEFINE_MUTEX(ipq_sysctl_mutex);

static inline void ipq_sysctl_lock(void)
{
	mutex_lock(&ipq_sysctl_mutex);
}

static inline void ipq_sysctl_unlock(void)
{
	mutex_unlock(&ipq_sysctl_mutex);
}
#endif


typedef int (*ipq_cmpfn)(struct nf_queue_entry *, unsigned long);

static unsigned int queue_maxlen = IPQ_QMAX_DEFAULT;

/*
static DEFINE_MUTEX(ipqnl_mutex);
*/

struct ipq_instance {
	struct hlist_node hlist;
	struct sock *ipqnl;
	int peer_pid;
	struct list_head queue_list;
	rwlock_t queue_lock;
	unsigned char copy_mode;
	unsigned int copy_range;
	unsigned int queue_total;
	unsigned int queue_dropped;
	unsigned int queue_user_dropped;
	unsigned int queue_maxlen;
};




static inline struct net *find_current_net_ns(void)
{
	struct net *net;
	struct pid *pid;

	pid = get_task_pid(current, PIDTYPE_PID);
	net = get_net_ns_by_pid(pid_vnr(pid));
	return net;
}

static inline void
__ipq_enqueue_entry(struct nf_queue_entry *entry,
		struct ipq_instance *instance)
{
       list_add_tail(&entry->list, &instance->queue_list);
       instance->queue_total++;
}

static inline int
__ipq_set_mode(unsigned char mode, unsigned int range,
		struct ipq_instance *instance)
{
	int status = 0;

	switch (mode) {
	case IPQ_COPY_NONE:
	case IPQ_COPY_META:
		instance->copy_mode = mode;
		instance->copy_range = 0;
		break;

	case IPQ_COPY_PACKET:
		instance->copy_mode = mode;
		instance->copy_range = range;
		if (instance->copy_range > 0xFFFF)
			instance->copy_range = 0xFFFF;
		break;

	default:
		status = -EINVAL;

	}
	return status;
}

static void __ipq_flush(ipq_cmpfn cmpfn, unsigned long data,
		struct ipq_instance *instance);

static inline void
__ipq_reset(struct ipq_instance *instance)
{
	instance->peer_pid = 0;
	net_disable_timestamp();
	__ipq_set_mode(IPQ_COPY_NONE, 0, instance);
	__ipq_flush(NULL, 0, instance);
}

static struct nf_queue_entry *
ipq_find_dequeue_entry(unsigned long id, struct ipq_instance *instance)
{
	struct nf_queue_entry *entry = NULL, *i;

	write_lock_bh(&instance->queue_lock);

	list_for_each_entry(i, &instance->queue_list, list) {
		if ((unsigned long)i == id) {
			entry = i;
			break;
		}
	}

	if (entry) {
		list_del(&entry->list);
		instance->queue_total--;
	}

	write_unlock_bh(&instance->queue_lock);
	return entry;
}

static void
__ipq_flush(ipq_cmpfn cmpfn, unsigned long data,
	struct ipq_instance *instance)
{
	struct nf_queue_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &instance->queue_list, list) {
		if (!cmpfn || cmpfn(entry, data)) {
			list_del(&entry->list);
			instance->queue_total--;
			nf_reinject(entry, NF_DROP);
		}
	}
}

static void
ipq_flush(ipq_cmpfn cmpfn, unsigned long data,
		struct ipq_instance *instance)
{
	write_lock_bh(&instance->queue_lock);
	__ipq_flush(cmpfn, data, instance);
	write_unlock_bh(&instance->queue_lock);
}

static struct sk_buff *
ipq_build_packet_message(struct nf_queue_entry *entry, int *errp,
		struct ipq_instance *instance)
{
	sk_buff_data_t old_tail;
	size_t size = 0;
	size_t data_len = 0;
	struct sk_buff *skb;
	struct ipq_packet_msg *pmsg;
	struct nlmsghdr *nlh;
	struct timeval tv;
	int copy_mode;
	int copy_range;

	copy_mode = instance->copy_mode;
	copy_range = instance->copy_range;

	read_lock_bh(&instance->queue_lock);

	switch (copy_mode) {
	case IPQ_COPY_META:
	case IPQ_COPY_NONE:
		size = NLMSG_SPACE(sizeof(*pmsg));
		break;

	case IPQ_COPY_PACKET:
		if ((entry->skb->ip_summed == CHECKSUM_PARTIAL ||
		     entry->skb->ip_summed == CHECKSUM_COMPLETE) &&
		    (*errp = skb_checksum_help(entry->skb))) {
			read_unlock_bh(&instance->queue_lock);
			return NULL;
		}
		if (copy_range == 0 || copy_range > entry->skb->len)
			data_len = entry->skb->len;
		else
			data_len = copy_range;

		size = NLMSG_SPACE(sizeof(*pmsg) + data_len);
		break;

	default:
		*errp = -EINVAL;
		read_unlock_bh(&instance->queue_lock);
		return NULL;
	}

	read_unlock_bh(&instance->queue_lock);

	skb = alloc_skb(size, GFP_ATOMIC);
	if (!skb)
		goto nlmsg_failure;

	old_tail = skb->tail;
	nlh = NLMSG_PUT(skb, 0, 0, IPQM_PACKET, size - sizeof(*nlh));
	pmsg = NLMSG_DATA(nlh);
	memset(pmsg, 0, sizeof(*pmsg));

	pmsg->packet_id       = (unsigned long)entry;
	pmsg->data_len        = data_len;
	tv = ktime_to_timeval(entry->skb->tstamp);
	pmsg->timestamp_sec   = tv.tv_sec;
	pmsg->timestamp_usec  = tv.tv_usec;
	pmsg->mark            = entry->skb->mark;
	pmsg->hook            = entry->hook;
	pmsg->hw_protocol     = entry->skb->protocol;

	if (entry->indev)
		strcpy(pmsg->indev_name, entry->indev->name);
	else
		pmsg->indev_name[0] = '\0';

	if (entry->outdev)
		strcpy(pmsg->outdev_name, entry->outdev->name);
	else
		pmsg->outdev_name[0] = '\0';

	if (entry->indev && entry->skb->dev) {
		pmsg->hw_type = entry->skb->dev->type;
		pmsg->hw_addrlen = dev_parse_header(entry->skb,
						    pmsg->hw_addr);
	}

	if (data_len)
		if (skb_copy_bits(entry->skb, 0, pmsg->payload, data_len))
			BUG();

	nlh->nlmsg_len = skb->tail - old_tail;
	return skb;

nlmsg_failure:
	*errp = -EINVAL;
	printk(KERN_ERR "ip_queue: error creating packet message\n");
	return NULL;
}

static int
ipq_enqueue_packet(struct nf_queue_entry *entry, unsigned int queuenum)
{
	int status = -EINVAL;
	struct sk_buff *nskb;
	struct sock *ipqnl = NULL;
	struct ipq_instance *instance;
	struct net *net = NULL;
	int peer_pid = 0;

	if (entry->indev)
		net = entry->indev->nd_net;
	else if (entry->outdev)
		net = entry->outdev->nd_net;

	if (unlikely(!net)) {
		printk(KERN_INFO "Cannot find net in %s\n", __func__);
		return -EINVAL;
	}

	instance = net->ipq;
	if (unlikely(!instance)) {
		printk(KERN_INFO "Cannot find instance: %s\n", __func__);
		return -EINVAL;
	}
	peer_pid = instance->peer_pid;
	ipqnl = instance->ipqnl;

	if (instance->copy_mode == IPQ_COPY_NONE)
		return -EAGAIN;

	nskb = ipq_build_packet_message(entry, &status, instance);
	if (nskb == NULL)
		return status;

	write_lock_bh(&instance->queue_lock);

	if (!peer_pid)
		goto err_out_free_nskb;

	if (instance->queue_total >= instance->queue_maxlen) {
		instance->queue_dropped++;
		status = -ENOSPC;
		if (net_ratelimit())
			  printk (KERN_WARNING "ip_queue: full at %d entries, "
				  "dropping packets(s). Dropped: %d\n",
				  instance->queue_total,
				  instance->queue_dropped);
		goto err_out_free_nskb;
	}

	/* netlink_unicast will either free the nskb or attach it to a socket */
	status = netlink_unicast(ipqnl, nskb, peer_pid, MSG_DONTWAIT);
	if (status < 0) {
		instance->queue_user_dropped++;
		goto err_out_unlock;
	}

	__ipq_enqueue_entry(entry, instance);

	write_unlock_bh(&instance->queue_lock);
	return status;

err_out_free_nskb:
	kfree_skb(nskb);

err_out_unlock:
	write_unlock_bh(&instance->queue_lock);
	return status;
}

static int
ipq_mangle_ipv4(ipq_verdict_msg_t *v, struct nf_queue_entry *e)
{
	int diff;
	struct iphdr *user_iph = (struct iphdr *)v->payload;
	struct sk_buff *nskb;

	if (v->data_len < sizeof(*user_iph))
		return 0;
	diff = v->data_len - e->skb->len;
	if (diff < 0) {
		if (pskb_trim(e->skb, v->data_len))
			return -ENOMEM;
	} else if (diff > 0) {
		if (v->data_len > 0xFFFF)
			return -EINVAL;
		if (diff > skb_tailroom(e->skb)) {
			nskb = skb_copy_expand(e->skb, skb_headroom(e->skb),
					       diff, GFP_ATOMIC);
			if (!nskb) {
				printk(KERN_WARNING "ip_queue: error "
				      "in mangle, dropping packet\n");
				return -ENOMEM;
			}
			kfree_skb(e->skb);
			e->skb = nskb;
		}
		skb_put(e->skb, diff);
	}
	if (!skb_make_writable(e->skb, v->data_len))
		return -ENOMEM;
	skb_copy_to_linear_data(e->skb, v->payload, v->data_len);
	e->skb->ip_summed = CHECKSUM_NONE;

	return 0;
}

static int
ipq_set_verdict(struct ipq_verdict_msg *vmsg, unsigned int len,
		struct ipq_instance *instance)
{
	struct nf_queue_entry *entry;

	if (vmsg->value > NF_MAX_VERDICT)
		return -EINVAL;

	entry = ipq_find_dequeue_entry(vmsg->id, instance);
	if (entry == NULL)
		return -ENOENT;
	else {
		int verdict = vmsg->value;

		if (vmsg->data_len && vmsg->data_len == len)
			if (ipq_mangle_ipv4(vmsg, entry) < 0)
				verdict = NF_DROP;

		nf_reinject(entry, verdict);
		return 0;
	}
}

static int
ipq_set_mode(unsigned char mode, unsigned int range, struct ipq_instance *instance)
{
	int status;

	write_lock_bh(&instance->queue_lock);
	status = __ipq_set_mode(mode, range, instance);
	write_unlock_bh(&instance->queue_lock);
	return status;
}

static int
ipq_receive_peer(struct ipq_peer_msg *pmsg,
		 unsigned char type, unsigned int len,
		 struct ipq_instance *instance)
{
	int status = 0;

	if (len < sizeof(*pmsg))
		return -EINVAL;

	switch (type) {
	case IPQM_MODE:
		status = ipq_set_mode(pmsg->msg.mode.value,
				      pmsg->msg.mode.range, instance);
		break;

	case IPQM_VERDICT:
		if (pmsg->msg.verdict.value > NF_MAX_VERDICT)
			status = -EINVAL;
		else
			status = ipq_set_verdict(&pmsg->msg.verdict,
						 len - sizeof(*pmsg), instance);
			break;
	default:
		status = -EINVAL;
	}
	return status;
}

static int
dev_cmp(struct nf_queue_entry *entry, unsigned long ifindex)
{
	if (entry->indev)
		if (entry->indev->ifindex == ifindex)
			return 1;
	if (entry->outdev)
		if (entry->outdev->ifindex == ifindex)
			return 1;
#ifdef CONFIG_BRIDGE_NETFILTER
	if (entry->skb->nf_bridge) {
		if (entry->skb->nf_bridge->physindev &&
		    entry->skb->nf_bridge->physindev->ifindex == ifindex)
			return 1;
		if (entry->skb->nf_bridge->physoutdev &&
		    entry->skb->nf_bridge->physoutdev->ifindex == ifindex)
			return 1;
	}
#endif
	return 0;
}

static void
ipq_dev_drop(int ifindex, struct ipq_instance *instance)
{
	ipq_flush(dev_cmp, ifindex, instance);
}

#define RCV_SKB_FAIL(err) do { netlink_ack(skb, nlh, (err)); return; } while (0)

static inline void
__ipq_rcv_skb(struct sk_buff *skb)
{
	int status, type, pid, flags, nlmsglen, skblen;
	struct nlmsghdr *nlh;
	struct net *net;
	struct ipq_instance *instance = NULL;


	skblen = skb->len;
	if (skblen < sizeof(*nlh))
		return;

	nlh = nlmsg_hdr(skb);
	nlmsglen = nlh->nlmsg_len;
	if (nlmsglen < sizeof(*nlh) || skblen < nlmsglen)
		return;

	pid = nlh->nlmsg_pid;

	net = get_net_ns_by_pid(pid);

	pid = pid_nr(find_vpid(pid));

	flags = nlh->nlmsg_flags;

	if (pid <= 0 || !(flags & NLM_F_REQUEST) || flags & NLM_F_MULTI)
		RCV_SKB_FAIL(-EINVAL);

	if (flags & MSG_TRUNC)
		RCV_SKB_FAIL(-ECOMM);

	type = nlh->nlmsg_type;
	if (type < NLMSG_NOOP || type >= IPQM_MAX)
		RCV_SKB_FAIL(-EINVAL);

	if (type <= IPQM_BASE)
		return;

	if (security_netlink_recv(skb, CAP_NET_ADMIN))
		RCV_SKB_FAIL(-EPERM);

	instance = net->ipq;
	BUG_ON(instance->ipqnl != skb->sk);

	write_lock(&instance->queue_lock);
	if (instance->peer_pid) {
		if (instance->peer_pid != pid) {
			write_unlock(&instance->queue_lock);
			RCV_SKB_FAIL(-EBUSY);
		}
	} else {
		net_enable_timestamp();
		instance->peer_pid = pid;
	}
	write_unlock(&instance->queue_lock);


	status = ipq_receive_peer(NLMSG_DATA(nlh), type,
				  nlmsglen - NLMSG_LENGTH(0), instance);
	if (status < 0)
		RCV_SKB_FAIL(status);

	if (flags & NLM_F_ACK)
		netlink_ack(skb, nlh, 0);
	return;
}

static inline void
ipq_rcv_skb(struct sk_buff *skb)
{
	/* mutex_lock(&ipqnl_mutex); */
	__ipq_rcv_skb(skb);
	/* mutex_unlock(&ipqnl_mutex); */
}

static int
ipq_rcv_dev_event(struct notifier_block *this,
		  unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct ipq_instance *instance = NULL;

	instance = dev_net(dev)->ipq;
	if (unlikely(!instance))
		return NOTIFY_DONE;

	/* Drop any packets associated with the downed device */
	if (event == NETDEV_DOWN)
		ipq_dev_drop(dev->ifindex, instance);
	return NOTIFY_DONE;
}

static struct notifier_block ipq_dev_notifier = {
	.notifier_call	= ipq_rcv_dev_event,
};

static int
ipq_rcv_nl_event(struct notifier_block *this,
		 unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;
	struct ipq_instance *instance = NULL;

	if (event == NETLINK_URELEASE &&
	    n->protocol == NETLINK_FIREWALL && n->pid) {

		instance = n->net->ipq;

		if (instance->peer_pid != n->pid)
			instance = NULL;

		if (unlikely(!instance)) {
			printk(KERN_INFO "failed to find instance: %s",
					__func__);
			return NOTIFY_DONE;
		}

		write_lock_bh(&instance->queue_lock);
		__ipq_reset(instance);
		write_unlock_bh(&instance->queue_lock);
	}
	return NOTIFY_DONE;
}

static struct notifier_block ipq_nl_notifier = {
	.notifier_call	= ipq_rcv_nl_event,
};

#ifdef CONFIG_SYSCTL

static int ipq_do_sysctl(ctl_table *ctl, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	struct ipq_instance *instance;
	struct net *net;

	net = find_current_net_ns();
	instance = net->ipq;

	ipq_sysctl_lock();

	if (!write)
		queue_maxlen = instance->queue_maxlen;

	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
	if (ret) {
		ipq_sysctl_unlock();
		return ret;
	}

	if (write)
		instance->queue_maxlen = queue_maxlen;

	ipq_sysctl_unlock();
	return 0;
}

static struct ctl_table_header *ipq_sysctl_header;

static ctl_table ipq_table[] = {
	{
		.ctl_name	= NET_IPQ_QMAX,
		.procname	= NET_IPQ_QMAX_NAME,
		.data		= &queue_maxlen,
		.maxlen		= sizeof(queue_maxlen),
		.mode		= 0644,
		.proc_handler	= ipq_do_sysctl,
	},
	{ .ctl_name = 0 }
};



#endif

#ifdef CONFIG_PROC_FS
static int ip_queue_show(struct seq_file *m, void *v)
{
	struct net *net;
	struct pid *pid;
	struct ipq_instance *instance;
	pid_t vpid;

	net = find_current_net_ns();

	instance = net->ipq;
	if (unlikely(!instance)) {
		printk(KERN_WARNING "Cannot find instance for net: %p\n", net);
		return 0;
	}

	pid = find_pid_ns(instance->peer_pid, &init_pid_ns);
	vpid = pid_vnr(pid);

	read_lock_bh(&instance->queue_lock);

	seq_printf(m,
		      "Peer PID          : %d\n"
		      "Copy mode         : %hu\n"
		      "Copy range        : %u\n"
		      "Queue length      : %u\n"
		      "Queue max. length : %u\n"
		      "Queue dropped     : %u\n"
		      "Netlink dropped   : %u\n",
		      vpid,
		      instance->copy_mode,
		      instance->copy_range,
		      instance->queue_total,
		      instance->queue_maxlen,
		      instance->queue_dropped,
		      instance->queue_user_dropped);

	read_unlock_bh(&instance->queue_lock);
	return 0;
}

static int ip_queue_open(struct inode *inode, struct file *file)
{
	return single_open(file, ip_queue_show, NULL);
}

static const struct file_operations ip_queue_proc_fops = {
	.open		= ip_queue_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};
#endif

static const struct nf_queue_handler nfqh = {
	.name	= "ip_queue",
	.outfn	= &ipq_enqueue_packet,
};

static int ipq_netlink_init(struct net *net)
{
	struct sock *sk;
	struct ipq_instance *instance = NULL;
	int ret = -ENOMEM;
	struct proc_dir_entry *proc = NULL;
	instance = kzalloc(sizeof(struct ipq_instance), GFP_KERNEL);
	if (!instance)
		goto out;

	sk = netlink_kernel_create(net, NETLINK_FIREWALL, 0,
				      ipq_rcv_skb, NULL, THIS_MODULE);
	if (!sk)
		goto free_instance;

#ifdef CONFIG_PROC_FS
	proc = proc_create(IPQ_PROC_FS_NAME, 0, net->proc_net,
			&ip_queue_proc_fops);
	if (!proc) {
		printk(KERN_ERR "ip_queue: failed to create proc entry\n");
		goto destroy_sk;
	}
#endif
	instance->ipqnl = sk;
	instance->peer_pid = 0;
	INIT_LIST_HEAD(&instance->queue_list);
	rwlock_init(&instance->queue_lock);

	instance->copy_mode = IPQ_COPY_NONE;
	instance->copy_range = 0;
	instance->queue_total = 0;
	instance->queue_dropped = 0;
	instance->queue_user_dropped = 0;
	instance->queue_maxlen = IPQ_QMAX_DEFAULT;

	net->ipq = instance;

	return 0;
destroy_sk:
	netlink_kernel_release(sk);
free_instance:
	kfree(instance);
out:
	return ret;
}

static void ipq_netlink_exit(struct net *net)
{
	struct ipq_instance *instance = NULL;

	instance = net->ipq;
	net->ipq = NULL;
	if (!instance)
		goto out;

	__ipq_flush(NULL, 0, instance);


	netlink_kernel_release(instance->ipqnl);

	kfree(instance);

out:
	proc_net_remove(net, IPQ_PROC_FS_NAME);
	return;
}

static struct pernet_operations ipq_netlink_ops = {
	.init = ipq_netlink_init,
	.exit = ipq_netlink_exit,
};

static int __init ip_queue_init(void)
{
	int status = -ENOMEM;
	struct proc_dir_entry *proc __maybe_unused;


	netlink_register_notifier(&ipq_nl_notifier);

	if (register_pernet_subsys(&ipq_netlink_ops)) {
		printk(KERN_ERR"ip_queue: failed to register pernet subsys\n");
		goto cleanup_netlink_notifier;
	}

	register_netdevice_notifier(&ipq_dev_notifier);
#ifdef CONFIG_SYSCTL
	ipq_sysctl_header = register_sysctl_paths(net_ipv4_ctl_path, ipq_table);
#endif
	status = nf_register_queue_handler(NFPROTO_IPV4, &nfqh);
	if (status < 0) {
		printk(KERN_ERR "ip_queue: failed to register queue handler\n");
		goto cleanup_sysctl;
	}


	return status;

cleanup_sysctl:
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(ipq_sysctl_header);
#endif
	unregister_netdevice_notifier(&ipq_dev_notifier);
cleanup_ipqnl: __maybe_unused
	unregister_pernet_subsys(&ipq_netlink_ops);
	       /*
	mutex_lock(&ipqnl_mutex);
	mutex_unlock(&ipqnl_mutex);
	*/

cleanup_netlink_notifier:
	netlink_unregister_notifier(&ipq_nl_notifier);
	return status;
}

static void __exit ip_queue_fini(void)
{
	nf_unregister_queue_handlers(&nfqh);
	synchronize_net();

#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(ipq_sysctl_header);
#endif
	unregister_netdevice_notifier(&ipq_dev_notifier);

	unregister_pernet_subsys(&ipq_netlink_ops);

	/*
	mutex_lock(&ipqnl_mutex);
	mutex_unlock(&ipqnl_mutex);
	*/

	netlink_unregister_notifier(&ipq_nl_notifier);
}

MODULE_DESCRIPTION("IPv4 packet queue handler, with full network namespace support");
MODULE_AUTHOR("James Morris <jmorris@intercode.com.au>");
MODULE_AUTHOR("rewritten by Zhu Yanhai <gaoyang.zyh@taobao.com>");

MODULE_LICENSE("GPL");
MODULE_ALIAS_NET_PF_PROTO(PF_NETLINK, NETLINK_FIREWALL);

module_init(ip_queue_init);
module_exit(ip_queue_fini);
