#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/module.h>
#define MALLOC(size)   kzalloc(size, GFP_KERNEL)
#define FREE(p)                 kfree(p)
#else
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define MALLOC(size)   malloc(size)
#define FREE(p)                 free(p)
#endif

#include "kuafu_info.h"

static struct pid_group g_groups[DEFAULT_GROUPS];
static struct pid_msgsize g_msgsizes[DEFAULT_TASKS];
static struct app_bucket *g_apps[BUCKETS_NUM];

int init_kuafu_info(void)
{
	int ino;
	int i;
	struct app_bucket *bk = NULL;

	for (ino = 0; ino < BUCKETS_NUM; ino++) {
		bk = MALLOC(sizeof(struct app_bucket));
		if (bk) {
				g_apps[ino] = bk;
				g_apps[ino]->entrys_num = 0;
		} else
				goto rollback;
	}
	return 0;

rollback:
	for (i = ino-1; i >= 0; i--)
		FREE(g_apps[i]);
	return -1;
}

int exit_kuafu_info(void)
{
	int ino;
	for (ino = 0; ino < BUCKETS_NUM; ino++)
		FREE(g_apps[ino]);
	return 0;
}

int kuafu_info_exists_pid(pid_t pid)
{
	int i = 0;
	struct pid_group *pg = NULL;

	for (; i < DEFAULT_GROUPS; i++) {
		pg = g_groups + i;
		if (pg->pid == pid)
				return 1;
	}
	return 0;
}

int kuafu_info_exists_group(pid_t pid, const char *name, int len)
{
	int i = 0;
	struct pid_group *pg = NULL;

	for (; i < DEFAULT_GROUPS; i++) {
		pg = g_groups + i;
		if (pg->pid == pid &&
				pg->groupname_len == len &&
				!strncmp(pg->groupname, name, len))
				return 1;
	}
	return 0;
}

int kuafu_info_store_group(pid_t pid, const char *name, int len)
{
	int i = 0;
	struct pid_group *pg = NULL;

	if (kuafu_info_exists_agent(name, len - 2, name[len - 1]))
		return -1;

	for (; i < DEFAULT_GROUPS; i++) {
		pg = g_groups + i;
		if (!pg->pid) {
				pg->pid = pid;
				strncpy(pg->groupname, name, len-2);
				pg->groupname_len = len-2;
				pg->role = name[len - 1];
				return 0;
		}
	}
	return -2;
}

int kuafu_info_clear_group(pid_t pid)
{
	int i = 0;
	struct pid_group *pg = NULL;

	for (; i < DEFAULT_GROUPS; i++) {
		pg = g_groups + i;
		if (pg->pid == pid)
				pg->pid = 0;
	}
	return 0;
}

int kuafu_info_fetch_msgsize(pid_t pid)
{
	int i = 0;
	struct pid_msgsize *pm = NULL;

	for (; i < DEFAULT_TASKS; i++) {
		pm = g_msgsizes + i;
		if (pm->pid == pid)
				return pm->msgsize;
	}
	return 0;
}

int kuafu_info_store_msgsize(pid_t pid, int msgsize)
{
	int i = 0;
	struct pid_msgsize *pm = NULL;

	for (; i < DEFAULT_TASKS; i++) {
		pm = g_msgsizes + i;
		if (!pm->pid) {
				pm->pid = pid;
				pm->msgsize = msgsize;
				break;
		}
	}
	return 0;
}

int kuafu_info_clear_msgsize(pid_t pid)
{
	int i = 0;
	struct pid_msgsize *pm = NULL;

	for (; i < DEFAULT_TASKS; i++) {
		pm = g_msgsizes + i;
		if (pm->pid == pid)
				pm->pid = 0;
	}
	return 0;
}

int kuafu_info_exists_in_buckets_app(struct app_bucket *bk, pid_t pid,
		const char *name, int len)
{
	int i = 0;
	struct pid_app *pa = NULL;

	for (; i < bk->entrys_num; i++) {
		pa = bk->entrys + i;
		if (pa->pid == pid &&
					 pa->appname_len == len &&
					 !strncmp(pa->appname, name, len))
				return 1;
	}

	return 0;
}

int kuafu_info_store_app(pid_t pid, const char *name, int len)
{
	int no = pid % BUCKETS_NUM;
	struct app_bucket *bk = g_apps[no];
	struct pid_app *pa = NULL;

	if (bk->entrys_num >= DEFAULT_APPS)
		return -1;

	if (kuafu_info_exists_in_buckets_app(bk, pid, name, len))
		return -1;

	pa = bk->entrys + bk->entrys_num;
	pa->pid = pid;
	strncpy(pa->appname, name, len);
	pa->appname_len = len;
	bk->entrys_num++;
	return 0;
}

int kuafu_info_remove_app(pid_t pid, const char *name, int len)
{
	int i = 0;
	int no = pid % BUCKETS_NUM;
	struct pid_app *pa = NULL;
	struct app_bucket *bk = g_apps[no];

	for (; i < bk->entrys_num; i++) {
		pa = bk->entrys + i;
		if (pa->pid == pid &&
			pa->appname_len == len &&
			!strncmp(pa->appname, name, len)) {
			memmove(pa, pa + 1,
				((bk->entrys + bk->entrys_num - 1) - pa) *
				sizeof(struct pid_app));
			bk->entrys_num--;
			return 0;
		}
	}
	return -1;
}

int kuafu_info_clear_pid_app(pid_t pid)
{
	int i = 0;
	int no = pid % BUCKETS_NUM;
	struct pid_app *pa = NULL;
	struct app_bucket *bk = g_apps[no];
	int num = bk->entrys_num;

	while (i < num) {
		pa = bk->entrys + i;
		if (pa->pid == pid) {
			memmove(pa, pa + 1, ((bk->entrys + num - 1) - pa) *
				sizeof(struct pid_app));
			num--;
			continue;
		}
		i++;
	}
	bk->entrys_num = num;
	return 0;
}

int kuafu_info_remove_pid(pid_t pid)
{
	int i = 0;
	struct pid_group *pg = NULL;
	struct pid_msgsize *pm = NULL;

	for (; i < DEFAULT_GROUPS; i++) {
		pg = g_groups + i;
		if (pg->pid == pid)
			pg->pid = 0;
	}

	for (i = 0; i < DEFAULT_TASKS; i++) {
		pm = g_msgsizes + i;
		if (pm->pid == pid)
			pm->pid = 0;
	}
	return 0;
}

char *kuafu_info_traverse(char *buffer, int *slen)
{
	int i = 0, j = 0;
	int len = 0;
	struct pid_group *pg = NULL;
	struct pid_msgsize *pm = NULL;
	struct pid_app *pa = NULL;
	char *begin = buffer;
	struct app_bucket *bk = NULL;

	len = sprintf(begin, "[group]\n");
	begin += len;

	for (; i < DEFAULT_GROUPS; i++) {
		pg = g_groups + i;
		if (pg->pid) {
			len = sprintf(begin, "%d:%.*s:%c\n", pg->pid,
				pg->groupname_len, pg->groupname, pg->role);
			begin += len;
		}
	}

	len = sprintf(begin, "\n[msgsize]\n");
	begin += len;

	for (i = 0; i < DEFAULT_TASKS; i++) {
		pm = g_msgsizes + i;
		if (pm->pid) {
			len = sprintf(begin, "%d:%d\n", pm->pid, pm->msgsize);
			begin += len;
		}
	}

	len = sprintf(begin, "\n[apps]\n");
	begin += len;
	for (j = 0; j < BUCKETS_NUM; j++) {
		bk = g_apps[j];
		for (i = 0; i < bk->entrys_num; i++) {
			pa = bk->entrys + i;
			if (pa->pid) {
				len = sprintf(begin, "%.*s\n",
				pa->appname_len, pa->appname);
				begin += len;
			}
		}
	}
	*slen = begin - buffer;
	return buffer;
}

int kuafu_info_exists_agent(const char *name, int len, char role)
{
	int i = 0;
	struct pid_group *pg = NULL;

	for (; i < DEFAULT_GROUPS; i++) {
		pg = g_groups + i;
		if (pg->pid &&
			pg->groupname_len == len &&
			!strncmp(pg->groupname, name, len)) {
			if (role == 'b' || pg->role == 'b' || pg->role == role)
				return 1;
		}
	}
	return 0;
}

