#ifndef __PERF_JIT
#define __PERF_JIT

#include "types.h"

#define JIT_SYMBOL_STATUS_LOAD 1
#define JIT_SYMBOL_STATUS_UNLOAD 2

struct jit_symbol {
	u8      status;
	u64     add;
	u64     len;
	u16     name_len;
	char    name[0];
};

struct jit_map {
	u32     next_sym_offset;
	struct  jit_symbol symbols[0];
};

#endif /* __PERF_JIT */

