#ifndef _ASM_HOTFIXES_H_
#define _ASM_HOTFIXES_H_ 1

#include <linux/list.h>

#define KERNEL_HOTFIXES_VERSION	1

#define RELATIVEJUMP_SIZE   5

struct ali_hotfix {
	unsigned char *func;
	unsigned char *addr;
	void *fix;
	unsigned char saved_inst[RELATIVEJUMP_SIZE];
	unsigned char *orig_stub;
};

struct ali_hotfix_desc {
    struct list_head list;
    char *memo;
    struct module *module;
    struct ali_hotfix hotfix;
};

struct ali_sym_addr {
	char *name;
	void **ptr;
};

#define ALI_DEFINE_SYM_ADDR(symname) \
{\
	.name = #symname,\
	.ptr = (void **)(&p_##symname)\
}

void *ali_get_symbol_address(const char *name);
int ali_get_symbol_address_list(struct ali_sym_addr *list, int *failed);

extern int ali_hotfix_register(struct ali_hotfix_desc *descp);
extern void ali_hotfix_unregister(struct ali_hotfix_desc *descp);

extern int ali_hotfix_register_list(struct ali_hotfix_desc *desc_list);
extern void ali_hotfix_unregister_list(struct ali_hotfix_desc *desc_list);

static inline void *ali_hotfix_orig_func(struct ali_hotfix_desc *descp)
{
	return descp->hotfix.orig_stub;
}

#define ALI_DEFINE_HOTFIX(m, funcname, fixfunc) \
{\
	.memo = m, \
	.module = THIS_MODULE, \
	.hotfix.func = funcname, \
	.hotfix.fix = fixfunc\
}

#define ALI_INIT_HOTFIX(hf, m, funcname, fixfunc) \
do {\
	INIT_LIST_HEAD(&(hf)->list); \
	(hf)->memo = m; \
	(hf)->module = THIS_MODULE; \
	(hf)->hotfix.func = funcname;\
	(hf)->hotfix.fix = fixfunc;\
} while (0)

#endif
