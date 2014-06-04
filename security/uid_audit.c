/*
 * uid_audit.c - Taotao security enhance feature.
 *
 * The linux kernel and userspace tools has many vulnerabilities
 * that can be exploited. the common exploit technology is set
 * the process's uid as 0. the goal of this patch is:
 *
 * 1. set a uid_canary in the task_struct.
 * 2. check the uid and uid_canary when the process exited.
 * 3. print some messages or panic if the system is attacked.
 *
 * Detect_kernel_vul is 8bit map in /proc/sys/kernel.
 * High 4bit control security level:
 * 
 * KERNEL_VUL_NS	0x10 (detect program only in namespace)
 * KERNEL_VUL_LOW       0x20 (detect all the programs expect sudo and su)
 * KERNEL_VUL_HIGH      0x40 (detect all the programs include sudo and su)
 *
 * Low 4bit control behavior:
 *
 * KERNEL_VUL_WARN      0x01 (only print warning messages)
 * KERNEL_VUL_KILL      0x02 (kill the process)
 * KERNEL_VUL_PANIC     0x04 (casue kernel painc)
 *
 * Exp:
 * enable this feature:
 *
 * a. In namespace and will only print warning mesages. 
 *    echo "17">/proc/sys/kernel/detect_kernel_vul
 *
 * b. All process without sudo and su and will kill the process.
 *    echo "34">/proc/sys/kernel/detect_kernel_vul
 *
 * c. All process and casue kernel panic.
 *    echo "68">/proc/sys/kernel/detect_kernel_vul
 *
 * disable this feature:
 *
 *    echo "0">/proc/sys/kernel/detect_kernel_vul
 *
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/mm.h>
#include <linux/threads.h>
#include <linux/nsproxy.h>
#include <linux/kref.h>
#include <linux/init_task.h>
#include <linux/pid_namespace.h>
#include <linux/capability.h>
#include <linux/uid_canary.h>

int detect_kernel_vul = 0;

void force_sig_info_warn(char *buf)
{
	struct task_struct *tsk = current;
	siginfo_t info;

	printk("[Kernel Attack Warning] %s\n", buf);

	info.si_signo = SIGKILL;
	info.si_errno = 0;
	info.si_code = 0;
	info.si_addr = NULL;
	info.si_addr_lsb = 0;

	force_sig_info(SIGKILL, &info, tsk);
}

void uid_warning(const char *fmt, ...)
{
        static char buf[1024];
        va_list args;

        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        if (kernel_vul_detect(KERNEL_VUL_WARN)) {
                printk("[Kernel Attack Warning] %s\n", buf);
        }
        else if (kernel_vul_detect(KERNEL_VUL_KILL)) {
                force_sig_info_warn(buf);
        }
        else if (kernel_vul_detect(KERNEL_VUL_PANIC)) {
                panic("[Kernel Attack Warning] %s\n", buf);
        }
        else {
                printk("[Kernel Attack Warning] bad parameters.\n");
        }
}

int uid_canary_check(struct cred *cred)
{

        struct task_struct *tsk = current;
        struct nsproxy *ns = current->nsproxy;

        if (kernel_vul_detect(KERNEL_VUL_DISABLED))
                return -1;

        if (!ns || !ns->pid_ns || !cred)
                return -1;

        if (kernel_vul_level(KERNEL_VUL_NS)) {
                /* ingore the process in init namespace. */
                if (ns->pid_ns == &init_pid_ns)
                        return -1;
        }

        /* uid canary has changed. */
        if (!cred->uid && tsk->uid_canary) {
                uid_warning("task: %s pid: %d uid: %d euid %d "
                        "suid: %d uid_canary: %d changed.",
                        tsk->comm, tsk->pid, cred->uid,
                        cred->euid, cred->suid, tsk->uid_canary);
                return 0;
        }

	return -1;
}
