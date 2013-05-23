#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/cpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>

#include <asm/hotfixes.h>

#define PROC_ENTRY_NAME "hotfixes"

#define RELATIVEJUMP_OPCODE 0xe9

static void *(*my_text_poke_smp)(void *addr, const void *opcode, size_t len);
static struct mutex *my_text_mutex;
static void *(*my_module_alloc)(unsigned long size);

void *ali_get_symbol_address(const char *name)
{
	struct kprobe kp;
	unsigned long (*kallsyms_lookup_name)(const char *name);

	/* for symbols in text sections */
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = name;
	register_kprobe(&kp);
	unregister_kprobe(&kp);

	if (kp.addr)
		return kp.addr;

	/* for symbols in data sections */
	/* for old kernel, this function is not exported */
	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	register_kprobe(&kp);
	unregister_kprobe(&kp);
	if (!kp.addr)
		return NULL;

	kallsyms_lookup_name = (void *)kp.addr;
	return (void *)kallsyms_lookup_name(name);
}
EXPORT_SYMBOL(ali_get_symbol_address);

int ali_get_symbol_address_list(struct ali_sym_addr *list, int *failed)
{
	int i;

	i = 0;
	while (1) {
		if (!list[i].name)
			return 0;
		*list[i].ptr = ali_get_symbol_address(list[i].name);
		if (NULL == *list[i].ptr) {
			if (failed)
				*failed = i;
			return -EINVAL;
		}
		i++;
	}
}
EXPORT_SYMBOL(ali_get_symbol_address_list);

static void try_to_create_orig_stub(struct ali_hotfix *h)
{
	unsigned char *addr = h->addr;
	int len = 0;
	s32 offset;

	h->orig_stub = NULL;
	while (len < RELATIVEJUMP_SIZE)
		switch (*addr) {
		case 0x55: /* push %rbp */
		case 0x53: /* push %rbx */
			addr++;
			len++;
			break;
		case 0x48:
			if (addr[1] == 0x89 && addr[2] == 0xe5) {
				/* mov    %rsp,%rbp */
				addr += 3;
				len += 3;
			} else if (addr[1] == 0x83 && addr[2] == 0xec) {
				/* sub    $0xHH,%rsp */
				addr += 4; /* and an extra offset byte */
				len += 4;
			} else
				goto out;
			break;
		case 0x41:
			switch (addr[1]) {
			case 0x54 ... 0x57: /* push   %r12/r13/r14/r15 */
				addr += 2;
				len += 2;
				break;
			default:
				goto out;
			}
			break;
		default:
			goto out;
	};

	h->orig_stub = my_module_alloc(PAGE_SIZE);
	if (!h->orig_stub)
		return;
	memcpy(h->orig_stub, h->addr, len);

	offset = (s32)((long)h->addr + len
				- ((long)h->orig_stub + len)
				- RELATIVEJUMP_SIZE);

	h->orig_stub[len] = RELATIVEJUMP_OPCODE;
	(*(s32 *)(&h->orig_stub[len+1])) = offset;

out:
	if (h->orig_stub)
		return;
	{
		int i;

		pr_warn("hotfixes: failed to create orig "
				"stub of %s(), binary are:", h->func);
		for (i = 0; i < 16; i++)
			printk(" %x", *(((unsigned char *)h->addr)+i));
		printk("\n");
	}
	return;
}

static int add_hotfix(struct ali_hotfix *h)
{
	unsigned char e9_jmp[RELATIVEJUMP_SIZE];
	s32 offset;

	if (RELATIVEJUMP_OPCODE == h->addr[0])
		return -EBUSY;

	try_to_create_orig_stub(h);

	offset = (s32)((long)h->fix
				- (long)h->addr
				- RELATIVEJUMP_SIZE);

	memcpy(h->saved_inst, h->addr, RELATIVEJUMP_SIZE);

	e9_jmp[0] = RELATIVEJUMP_OPCODE;
	(*(s32 *)(&e9_jmp[1])) = offset;

	get_online_cpus();
	mutex_lock(my_text_mutex);
	my_text_poke_smp(h->addr, e9_jmp, RELATIVEJUMP_SIZE);
	mutex_unlock(my_text_mutex);
	put_online_cpus();

	return 0;
}

static void del_hotfix(struct ali_hotfix *h)
{
	get_online_cpus();
	mutex_lock(my_text_mutex);
	my_text_poke_smp(h->addr, h->saved_inst, RELATIVEJUMP_SIZE);
	mutex_unlock(my_text_mutex);
	put_online_cpus();
}

static int init_hotfix(void)
{
	my_text_poke_smp = (void *)ali_get_symbol_address("text_poke_smp");
	if (!my_text_poke_smp)
		return -EINVAL;

	my_text_mutex = (void *)ali_get_symbol_address("text_mutex");
	if (!my_text_mutex)
		return -EINVAL;

	my_module_alloc = (void *)ali_get_symbol_address("module_alloc");

	return 0;
}

static LIST_HEAD(hotfix_desc_head);
static DEFINE_MUTEX(hotfix_lock);

static int is_dup(struct ali_hotfix_desc *n)
{
	struct list_head *pos;
	struct ali_hotfix_desc *descp;
	bool dup = false;

	mutex_lock(&hotfix_lock);
	list_for_each(pos, &hotfix_desc_head) {
		descp = container_of(pos, struct ali_hotfix_desc, list);
		if (n->hotfix.addr == descp->hotfix.addr) {
			dup = true;
			break;
		}
	}
	mutex_unlock(&hotfix_lock);
	return dup;
}

int ali_hotfix_register(struct ali_hotfix_desc *descp)
{
	int ret;

	if (!descp || !descp->hotfix.fix || !descp->hotfix.func)
		return -EINVAL;

	descp->hotfix.addr = (void *)ali_get_symbol_address(descp->hotfix.func);
	if (!descp->hotfix.addr)
		return -EINVAL;

	if (is_dup(descp))
		return -EBUSY;

	ret = add_hotfix(&descp->hotfix);
	if (ret)
		return ret;
	INIT_LIST_HEAD(&descp->list);
	mutex_lock(&hotfix_lock);
	list_add_tail(&descp->list, &hotfix_desc_head);
	mutex_unlock(&hotfix_lock);
	return 0;
}
EXPORT_SYMBOL(ali_hotfix_register);

void ali_hotfix_unregister(struct ali_hotfix_desc *descp)
{
	if (!descp)
		return;
	mutex_lock(&hotfix_lock);
	list_del(&descp->list);
	mutex_unlock(&hotfix_lock);
	del_hotfix(&descp->hotfix);
	if (descp->hotfix.orig_stub) {
		vfree(descp->hotfix.orig_stub);
		descp->hotfix.orig_stub = NULL;
	}
}
EXPORT_SYMBOL(ali_hotfix_unregister);

int ali_hotfix_register_list(struct ali_hotfix_desc *desc_list)
{
	int ret = -EINVAL, i;

	for (i = 0; desc_list[i].memo != NULL; i++) {
		ret = ali_hotfix_register(&desc_list[i]);
		if (ret)
			break;
	}

	if (!ret)
		return 0;

	for (--i; i >= 0; --i)
		ali_hotfix_unregister(&desc_list[i]);

	return ret;
}
EXPORT_SYMBOL(ali_hotfix_register_list);

void ali_hotfix_unregister_list(struct ali_hotfix_desc *desc_list)
{
	int i;

	for (i = 0; desc_list[i].memo != NULL; i++)
		ali_hotfix_unregister(&desc_list[i]);
}
EXPORT_SYMBOL(ali_hotfix_unregister_list);

static int hotfix_info_show(struct seq_file *m, void *v)
{
	struct list_head *pos;
	struct ali_hotfix_desc *descp;
	seq_printf(m, "Kernel Function Hotfix Version: v%d, %s %.*s\n",
		KERNEL_HOTFIXES_VERSION,
		init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);

#define SN(x) ((x) ? (x) : "Unknown")
	mutex_lock(&hotfix_lock);
	list_for_each(pos, &hotfix_desc_head) {
		descp = container_of(pos, struct ali_hotfix_desc, list);
		seq_printf(m, "-----------------------------------------\n");
		seq_printf(m, "Func: %s/%p\n",
			descp->hotfix.func, descp->hotfix.addr);
		seq_printf(m, "Module:  %s\n", module_name(descp->module));
		seq_printf(m, "OrigStub:  %p\n", descp->hotfix.orig_stub);
		seq_printf(m, "Fix:  %p\n", descp->hotfix.fix);
		seq_printf(m, "Description:\n%s\n", SN(descp->memo));
	}
	mutex_unlock(&hotfix_lock);
#undef SN
	return 0;
}

static int hotfix_info_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, hotfix_info_show, NULL);
}

static const struct file_operations hotfix_info_fops = {
	.open		=	hotfix_info_open,
	.read		=	seq_read,
	.llseek		=	seq_lseek,
	.release	=	single_release,
};

static int __init hf_init(void)
{
	struct proc_dir_entry *pe;
	int ret;

	ret = init_hotfix();
	if (ret)
		return ret;

	pe = proc_create(PROC_ENTRY_NAME, 0444, NULL, &hotfix_info_fops);
	if (!pe)
		return -ENOMEM;
	return 0;
}


static void __exit hf_exit(void)
{
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
	return;
}

module_init(hf_init)
module_exit(hf_exit)
MODULE_AUTHOR("Bing Tian <bingtian.ly@taobao.com>, "
			"Gao Yang <gaoyang.zyh@taobao.com>");
MODULE_DESCRIPTION("Kernel function hotfix support modules");
MODULE_LICENSE("GPL");
