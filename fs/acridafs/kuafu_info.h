#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#endif

#define DEFAULT_GROUPS 1024
#define DEFAULT_TASKS  256
#define DEFAULT_APPS   256
#define BUFFER_SIZE    (512*1024)
#define BUCKETS_NUM    503

struct pid_group {
	pid_t   pid;
	char    groupname[8];
	char    role;   /* 'c', 's' or 'b' */
	int     groupname_len;
};

struct pid_msgsize {
	pid_t   pid;
	int     msgsize;
};

struct pid_app {
	pid_t   pid;
	char    appname[64];
	int     appname_len;
};

struct app_bucket {
	int             entrys_num;
	struct pid_app  entrys[DEFAULT_APPS];
};

int init_kuafu_info(void);
int exit_kuafu_info(void);

int kuafu_info_exists_pid(pid_t pid);
int kuafu_info_store_group(pid_t pid, const char *name, int len);
int kuafu_info_exists_group(pid_t pid, const char *name, int len);
int kuafu_info_clear_group(pid_t pid);
/* Another agent with same group same role already exists */
int kuafu_info_exists_agent(const char *name, int len, char role);

int kuafu_info_store_msgsize(pid_t pid, int msgsize);
int kuafu_info_fetch_msgsize(pid_t pid);
int kuafu_info_clear_msgsize(pid_t pid);

int kuafu_info_store_app(pid_t pid, const char *name, int len);
int kuafu_info_exists_in_buckets_app(struct app_bucket *bk, pid_t pid,
		const char *name, int len);
int kuafu_info_remove_app(pid_t pid, const char *name, int len);
int kuafu_info_clear_pid_app(pid_t pid);

int kuafu_info_remove_pid(pid_t pid);

char *kuafu_info_traverse(char *buff, int *slen);
