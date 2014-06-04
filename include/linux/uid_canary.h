#ifndef __LINUX_UID_CANARY_H
#define __LINUX_UID_CANARY_h

#define KERNEL_VUL_DISABLED             0x00

#define KERNEL_VUL_WARN                 0x01
#define KERNEL_VUL_KILL                 0x02
#define KERNEL_VUL_PANIC                0x04

#define KERNEL_VUL_NS                   0x10
#define KERNEL_VUL_LOW                  0x20
#define KERNEL_VUL_HIGH                 0x40

#define kernel_vul_detect(x)            ((detect_kernel_vul & 0x0f) == x ? 1 : 0)
#define kernel_vul_level(x)             ((detect_kernel_vul & 0xf0) == x ? 1 : 0)

#endif
