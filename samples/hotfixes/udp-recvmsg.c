#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/hotfixes.h>

struct kiocb;
struct sock;
struct msghdr;

static int overwrite_udp_recvmsg(struct kiocb *iocb, struct sock *sk,
				struct msghdr *msg, size_t len,
				int noblock, int flags, int *addr_len);

#define HOTFIX_UDP_RECVMSG	0

static struct ali_hotfix_desc hotfix_list[] = {

	[HOTFIX_UDP_RECVMSG] = ALI_DEFINE_HOTFIX(\
		"A hotfix sample", \
		"udp_recvmsg",\
		overwrite_udp_recvmsg),

	{},
};

static int __init hotfix_init(void)
{
	return ali_hotfix_register_list(hotfix_list);
}

static void __exit hotfix_exit(void)
{
	ali_hotfix_unregister_list(hotfix_list);
}

module_init(hotfix_init)
module_exit(hotfix_exit)
MODULE_LICENSE("GPL");

static int (*orig_udp_recvmsg)(struct kiocb *iocb, struct sock *sk,
				struct msghdr *msg, size_t len,
				int noblock, int flags, int *addr_len);

static int overwrite_udp_recvmsg(struct kiocb *iocb, struct sock *sk,
				struct msghdr *msg, size_t len,
				int noblock, int flags, int *addr_len)
{
	pr_info("udp_recvmsg() fixed\n");
	orig_udp_recvmsg = ali_hotfix_orig_func(&hotfix_list[0]);
	return orig_udp_recvmsg(iocb, sk, msg, len, noblock, flags, addr_len);
}
