/*
 * Limits on kernel resource counters that are not covered by existing cgroup
 * subsys'.  This actually is the counterpart of ulimit except the limit is per
 * cgroup.
 *
 * Copyright 2014 Alibaba, Inc.
 * Author: Zhiyuan Zhou <wenzhang.zzy@alibaba-inc.com>
 *
 * Base on task counter cgroup patch.
 * http://thread.gmane.org/gmane.linux.kernel/1246704
 *
 * Limits on number of tasks subsystem for cgroups
 *
 * Copyright (C) 2011-2012 Red Hat, Inc., Frederic Weisbecker <fweisbec@redhat.com>
 *
 * Thanks to Andrew Morton, Johannes Weiner, Li Zefan, Oleg Nesterov and
 * Paul Menage for their suggestions.
 *
 */

#include <linux/err.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/res_counter.h>

enum kcounter_type {
	COUNTER_NPROC = 0,
	COUNTER_MAX = 1,
};

struct kcounter {
	struct res_counter		res[COUNTER_MAX];
	struct cgroup_subsys_state	css;
};

/*
 * The root counters doesn't exist because it's not part of the
 * whole task counting. We want to optimize the trivial case of only
 * one root cgroup living.
 */
static struct cgroup_subsys_state root_css;

static inline struct kcounter *cgroup_kcounter(struct cgroup *cgrp)
{
	if (!cgrp->parent)
		return NULL;

	return container_of(cgroup_subsys_state(cgrp, kcounter_subsys_id),
			    struct kcounter, css);
}

static inline struct res_counter *
cgroup_kcounter_rescnt(struct cgroup *cgrp, int type)
{
	struct kcounter *kcnt;

	kcnt = cgroup_kcounter(cgrp);
	if (!kcnt)
		return NULL;

	if (type >= COUNTER_MAX)
		return NULL;

	return &kcnt->res[type];
}

static struct cgroup_subsys_state *
kcounter_create(struct cgroup_subsys *ss, struct cgroup *cgrp)
{
	int i;
	struct kcounter *kcnt;
	struct res_counter *parent_res;

	if (!cgrp->parent)
		return &root_css;

	kcnt = kzalloc(sizeof(*kcnt), GFP_KERNEL);
	if (!kcnt)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < COUNTER_MAX; i++) {
		parent_res = cgroup_kcounter_rescnt(cgrp->parent, i);
		res_counter_init(&kcnt->res[i], parent_res);
	}

	return &kcnt->css;
}

/*
 * Inherit the limit value of the parent. This is not really to enforce
 * a limit below or equal to the one of the parent which can be changed
 * concurrently anyway. This is just to honour the clone flag.
 */
static void kcounter_post_clone(struct cgroup_subsys *ss,
				    struct cgroup *cgrp)
{
	int i;

	/* cgrp can't be root, so cgroup_kcounter_rescnt() can't return NULL */
	for (i = 0; i < COUNTER_MAX; i++)
		res_counter_inherit(cgroup_kcounter_rescnt(cgrp, i), RES_LIMIT);
}

static void kcounter_destroy(struct cgroup_subsys *ss, struct cgroup *cgrp)
{
	struct kcounter *cnt = cgroup_kcounter(cgrp);

	kfree(cnt);
}

/*
 * On process exit:
 *
 * the only thing needed here is to uncharge the nproc counter.
 * For now nothing for other counters.
 */
static void kcounter_exit(struct cgroup_subsys *ss, struct cgroup *cgrp,
			      struct cgroup *old_cgrp, struct task_struct *task)
{
	struct res_counter *res;

	res = cgroup_kcounter_rescnt(old_cgrp, COUNTER_NPROC);

	/* Optimize for the root cgroup case */
	if (old_cgrp->parent)
		res_counter_uncharge(res, 1);
}

/*
 * This does more than just probing the ability to attach to the dest cgroup.
 * We can not just _check_ if we can attach to the destination and do the real
 * attachment later in nproc_attach() because a task in the dest cgroup can fork
 * before and steal the last remaining count.  Thus we need to charge the dest
 * cgroup right now.
 *
 * This is a special case. Not required for other counters.
 *
 * NOTE in 2.6.32 attaching a group of threads to cgroup is not supported.
 */
static int kcounter_can_attach(struct cgroup_subsys *ss,
		    struct cgroup *cgrp, struct task_struct *tsk)
{
	struct res_counter *old_res, *res;
	struct cgroup *old_cgrp;
	struct res_counter *common_ancestor;
	struct cgroupfs_root *root = ss->root;
	int err = 0;

	/* nproc counter part */

	/* It's possible old_cgrp is the top_cgroup, in this case old_res will
	 * be NULL. */
	old_cgrp = task_cgroup_from_root(tsk, root);
	old_res = cgroup_kcounter_rescnt(old_cgrp, COUNTER_NPROC);
	res = cgroup_kcounter_rescnt(cgrp, COUNTER_NPROC);
	/*
	 * When moving a task from a cgroup to another, we don't want to charge
	 * the common ancestors, even though they will be uncharged later from
	 * attach_task(), because during that short window between charge and
	 * uncharge, a task could fork in the ancestor and spuriously fail due
	 * to the temporary charge.
	 */
	common_ancestor = res_counter_common_ancestor(res, old_res);

	/*
	 * If cgrp is the root then res is NULL, however in this case
	 * the common ancestor is NULL as well, making the below a NOP.
	 *
	 * The charging is an atomic operation. No rollback is required on
	 * failure.
	 */
	err = res_counter_charge_until(res, common_ancestor, 1, NULL);
	if (err) {
		return -EINVAL;
	}

	return 0;
}

/* Uncharge the dest cgroup that we charged in kcounter_can_attach() */
static void kcounter_cancel_attach(struct cgroup_subsys *ss,
				       struct cgroup *cgrp,
				       struct task_struct *task)
{
	struct res_counter *old_res, *res;
	struct cgroup *old_cgrp;
	struct res_counter *common_ancestor;
	struct cgroupfs_root *root = cgrp->root;

	/* nproc counter part */

	old_cgrp = task_cgroup_from_root(task, root);
	old_res = cgroup_kcounter_rescnt(old_cgrp, COUNTER_NPROC);
	res = cgroup_kcounter_rescnt(cgrp, COUNTER_NPROC);
	common_ancestor = res_counter_common_ancestor(res, old_res);

	res_counter_uncharge_until(res, common_ancestor, 1);
}

/*
 * On task attachment:
 *
 * Uncharge the old cgroups. We can do that now that we are sure the
 * attachment can't cancelled anymore, because this uncharge operation
 * couldn't be reverted later: a task in the old cgroup could fork after
 * we uncharge and reach the task counter limit, making our return there
 * not possible.
 */
static void kcounter_attach(struct cgroup_subsys *ss, struct cgroup *cgrp,
			struct cgroup *old_cgrp, struct task_struct *tsk)
{
	struct res_counter *old_res, *res;
	struct res_counter *common_ancestor;

	/* nproc counter part */

	old_res = cgroup_kcounter_rescnt(old_cgrp, COUNTER_NPROC);
	res = cgroup_kcounter_rescnt(cgrp, COUNTER_NPROC);
	common_ancestor =
		res_counter_common_ancestor(res, old_res);

	res_counter_uncharge_until(old_res, common_ancestor, 1);
}

/* for encoding cft->private value on file */
#define CFTFILE_PRIVATE(x, val)	(((x) << 16) | (val))
#define CFTFILE_TYPE(val)	(((val) >> 16) & 0xffff)
#define CFTFILE_ATTR(val)	((val) & 0xffff)

static u64 kcounter_read_u64(struct cgroup *cgrp, struct cftype *cft)
{
	int type, name;

	type = CFTFILE_TYPE(cft->private);
	name = CFTFILE_ATTR(cft->private);

	return res_counter_read_u64(cgroup_kcounter_rescnt(cgrp, type), name);
}

static int kcounter_write_u64(struct cgroup *cgrp, struct cftype *cft,
				  u64 val)
{
	int type, name;

	type = CFTFILE_TYPE(cft->private);
	name = CFTFILE_ATTR(cft->private);

	res_counter_write_u64(cgroup_kcounter_rescnt(cgrp, type), name, val);

	return 0;
}

static struct cftype files[] = {
	{
		.name		= "nproc.limit",
		.read_u64	= kcounter_read_u64,
		.write_u64	= kcounter_write_u64,
		.private	= CFTFILE_PRIVATE(COUNTER_NPROC, RES_LIMIT),
	},

	{
		.name		= "nproc.usage",
		.read_u64	= kcounter_read_u64,
		.private	= CFTFILE_PRIVATE(COUNTER_NPROC, RES_USAGE),
	},
};

static int kcounter_populate(struct cgroup_subsys *ss, struct cgroup *cgrp)
{
	if (!cgrp->parent)
		return 0;

	return cgroup_add_files(cgrp, ss, files, ARRAY_SIZE(files));
}

/*
 * For nproc counter:
 *
 * Charge the nproc counter with the new child coming, or reject it if we
 * reached the limit.
 */
static int kcounter_fork(struct cgroup_subsys *ss,
			     struct task_struct *child)
{
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;
	int err;
	struct res_counter *res;

	css = child->cgroups->subsys[kcounter_subsys_id];
	cgrp = css->cgroup;

	/* Optimize for the root cgroup case, which doesn't have a limit */
	if (!cgrp->parent)
		return 0;

	/* Charge task counter */
	res = cgroup_kcounter_rescnt(cgrp, COUNTER_NPROC);
	err = res_counter_charge(res, 1, NULL);
	if (err)
		return -EAGAIN;

	return 0;
}

struct cgroup_subsys kcounter_subsys = {
	.name			= "kcounter",
	.subsys_id		= kcounter_subsys_id,
	.create			= kcounter_create,
	.post_clone		= kcounter_post_clone,
	.destroy		= kcounter_destroy,
	.exit			= kcounter_exit,
	.can_attach		= kcounter_can_attach,
	.cancel_attach		= kcounter_cancel_attach,
	.attach			= kcounter_attach,
	.fork			= kcounter_fork,
	.populate		= kcounter_populate,
};
