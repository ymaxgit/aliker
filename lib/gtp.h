#ifndef _GTP_PLUGIN_H_
#define _GTP_PLUGIN_H_

/* Follow part for ARCH.  */
#ifdef CONFIG_X86
#define ULONGEST		uint64_t
#define LONGEST			int64_t
#define CORE_ADDR		unsigned long

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24))
#define GTP_REGS_PC(regs)	((regs)->ip)
#else
#ifdef CONFIG_X86_32
#define GTP_REGS_PC(regs)	((regs)->eip)
#else
#define GTP_REGS_PC(regs)	((regs)->rip)
#endif
#endif

#ifdef CONFIG_X86_32
#define GTP_REG_ASCII_SIZE	128
#define GTP_REG_BIN_SIZE	64

#define GTP_SP_NUM		4
#define GTP_PC_NUM		8
#else
#define GTP_REG_ASCII_SIZE	296
#define GTP_REG_BIN_SIZE	148

#define GTP_SP_NUM		7
#define GTP_PC_NUM		16
#endif
#endif

#ifdef CONFIG_MIPS
#define ULONGEST		uint64_t
#define LONGEST			int64_t
#define CORE_ADDR		unsigned long

#define GTP_REGS_PC(regs)	((regs)->cp0_epc)

#ifdef CONFIG_32BIT
#define GTP_REG_ASCII_SIZE	304
#define GTP_REG_BIN_SIZE	152
#else
#define GTP_REG_ASCII_SIZE	608
#define GTP_REG_BIN_SIZE	304
#endif

#define GTP_SP_NUM		29
#define GTP_PC_NUM		37
#endif

#ifdef CONFIG_ARM
#define ULONGEST		uint64_t
#define LONGEST			int64_t
#define CORE_ADDR		unsigned long

#define GTP_REGS_PC(regs)	((regs)->uregs[15])

#define GTP_REG_ASCII_SIZE	336
#define GTP_REG_BIN_SIZE	168

#define GTP_SP_NUM		13
#define GTP_PC_NUM		15
#endif

struct gtp_var;

struct gtp_trace_s {
	struct gtp_entry		*tpe;
	struct pt_regs			*regs;
	long				(*read_memory)(void *dst,
						       void *src,
						       size_t size);
#ifdef GTP_FRAME_SIMPLE
	/* Next part set it to prev part.  */
	char				**next;
#endif
#ifdef GTP_FTRACE_RING_BUFFER
	/* NULL means doesn't have head.  */
	char				*next;
#endif
#ifdef GTP_RB
	/* rb of current cpu.  */
	struct gtp_rb_s			*next;
	u64				id;
#endif
	int				step;
	struct kretprobe_instance	*ri;
	int				*run;
	struct timespec			xtime;
	int64_t				printk_tmp;
	unsigned int			printk_level;
	unsigned int			printk_format;
	struct gtpsrc			*printk_str;
};

struct gtp_var_hooks {
	int	(*gdb_set_val)(struct gtp_trace_s *unused, struct gtp_var *var,
			       int64_t val);
	int	(*gdb_get_val)(struct gtp_trace_s *unused, struct gtp_var *var,
			       int64_t *val);
	int	(*agent_set_val)(struct gtp_trace_s *gts, struct gtp_var *var,
				 int64_t val);
	int	(*agent_get_val)(struct gtp_trace_s *gts, struct gtp_var *var,
				 int64_t *val);
};

extern int gtp_plugin_mod_register(struct module *mod);
extern int gtp_plugin_mod_unregister(struct module *mod);

extern struct gtp_var *gtp_plugin_var_add(char *name, int64_t val,
					  struct gtp_var_hooks *hooks);
extern int gtp_plugin_var_del(struct gtp_var *var);

extern ULONGEST gtp_action_reg_read(struct gtp_trace_s *gts, int num);

#endif /* _GTP_PLUGIN_H_ */
