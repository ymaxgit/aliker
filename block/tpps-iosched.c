/*
 *  TPPS, or Taobao Parallel Proportion disk Scheduler.
 *
 *  Based on ideas from Zhu Yanhai <gaoyang.zyh@taobao.com>
 *
 *  Copyright (C) 2013 Robin Dong <sanbai@taobao.com>
 */
#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/jiffies.h>
#include <linux/rbtree.h>
#include <linux/ioprio.h>
#include <linux/blktrace_api.h>
#include "blk-cgroup.h"
#include "blk.h"

static struct kmem_cache *tpps_pool;
static struct kmem_cache *tpps_ioc_pool;

static DEFINE_PER_CPU(unsigned long, tpps_ioc_count);
static struct completion *ioc_gone;
static DEFINE_SPINLOCK(ioc_gone_lock);

struct tpps_queue {
	/* reference count */
	int ref;
	/* parent tpps_data */
	struct tpps_data *tppd;
	/* tpps_group member */
	struct list_head tppg_node;
	/* sorted list of pending requests */
	struct list_head sort_list;
	struct tpps_group *tppg;
	pid_t pid;
	int online;
	int rq_queued;
};

struct tpps_group {
	/* tpps_data member */
	struct list_head tppd_node;
	struct list_head *cur_dispatcher;

	unsigned int weight;
	unsigned int new_weight;
	bool needs_update;

	/*
	 * lists of queues with requests.
	 */
	struct list_head queue_list;
	struct blkio_group blkg;
	int ref;
	int nr_tppq;
	int rq_queued;
	int rq_in_driver;
};

struct tpps_data {
	struct request_queue *queue;
	struct tpps_group root_group;

	/* List of tpps groups being managed on this device*/
	struct list_head group_list;

	struct list_head tic_list;

	unsigned int busy_queues;
	int dispatched;
	int rq_in_driver;

	struct work_struct unplug_work;

	/* Number of groups which are on blkcg->blkg_list */
	unsigned int nr_blkcg_linked_grps;

	unsigned total_weight;
};

#define tpps_log_tppq(tppd, tppq, fmt, args...)	\
	blk_add_trace_msg((tppd)->queue, "tpps%d %s " fmt, (tppq)->pid, \
			blkg_path(&(tppq)->tppg->blkg), ##args);
#define tpps_log_tppg(tppd, tppg, fmt, args...)				\
	blk_add_trace_msg((tppd)->queue, "%s " fmt,			\
				blkg_path(&(tppg)->blkg), ##args);
#define tpps_log(tppd, fmt, args...)	\
	blk_add_trace_msg((tppd)->queue, "tpps " fmt, ##args)

#define RQ_TIC(rq)		\
	((struct tpps_io_context *) (rq)->elevator_private[0])
#define RQ_TPPQ(rq)	(struct tpps_queue *) ((rq)->elevator_private[1])
#define RQ_TPPG(rq)	(struct tpps_group *) ((rq)->elevator_private[2])

#define MIN_DISPATCH_RQ (64)

static void tpps_tic_free_rcu(struct rcu_head *head)
{
	struct tpps_io_context *tic;

	tic = container_of(head, struct tpps_io_context, rcu_head);

	kmem_cache_free(tpps_ioc_pool, tic);
	elv_ioc_count_dec(tpps_ioc_count);

	if (ioc_gone) {
		/*
		 * TPPs is exiting, grab exit lock and check
		 * the pending io context count. If it hits zero,
		 * complete ioc_gone and set it back to NULL
		 */
		spin_lock(&ioc_gone_lock);
		if (ioc_gone && !elv_ioc_count_read(tpps_ioc_count)) {
			complete(ioc_gone);
			ioc_gone = NULL;
		}
		spin_unlock(&ioc_gone_lock);
	}
}

static void tpps_tic_free(struct tpps_io_context *tic)
{
	call_rcu(&tic->rcu_head, tpps_tic_free_rcu);
}

/*
 * We drop tpps io contexts lazily, so we may find a dead one.
 */
static void
tpps_drop_dead_tic(struct tpps_data *tppd, struct io_context *ioc,
		  struct tpps_io_context *tic)
{
	unsigned long flags;

	WARN_ON(!list_empty(&tic->queue_list));

	spin_lock_irqsave(&ioc->lock, flags);

	BUG_ON(ioc->ioc_data == tic);

	radix_tree_delete(&ioc->radix_root, (unsigned long) tppd);
	hlist_del_rcu(&tic->tic_list);
	spin_unlock_irqrestore(&ioc->lock, flags);

	tpps_tic_free(tic);
}

static struct tpps_io_context *
tpps_tic_lookup(struct tpps_data *tppd, struct io_context *ioc)
{
	struct tpps_io_context *tic;
	unsigned long flags;
	void *k;

	if (unlikely(!ioc))
		return NULL;

	rcu_read_lock();

	/*
	 * we maintain a last-hit cache, to avoid browsing over the tree
	 */
	tic = rcu_dereference(ioc->ioc_data);
	if (tic && tic->key == tppd) {
		rcu_read_unlock();
		return tic;
	}

	do {
		tic = radix_tree_lookup(&ioc->radix_root, (unsigned long) tppd);
		rcu_read_unlock();
		if (!tic)
			break;
		/* ->key must be copied to avoid race with tpps_exit_queue() */
		k = tic->key;
		if (unlikely(!k)) {
			tpps_drop_dead_tic(tppd, ioc, tic);
			rcu_read_lock();
			continue;
		}

		spin_lock_irqsave(&ioc->lock, flags);
		rcu_assign_pointer(ioc->ioc_data, tic);
		spin_unlock_irqrestore(&ioc->lock, flags);
		break;
	} while (1);

	return tic;
}

static void tic_free_func(struct io_context *ioc, struct tpps_io_context *tic)
{
	unsigned long flags;

	BUG_ON(!tic->dead_key);

	spin_lock_irqsave(&ioc->lock, flags);
	radix_tree_delete(&ioc->radix_root, tic->dead_key);
	hlist_del_rcu(&tic->tic_list);
	spin_unlock_irqrestore(&ioc->lock, flags);

	tpps_tic_free(tic);
}

/*
 * Must always be called with the rcu_read_lock() held
 */
static void
__call_for_each_tic(struct io_context *ioc,
		    void (*func)(struct io_context *, struct tpps_io_context *))
{
	struct tpps_io_context *tic;
	struct hlist_node *n;

	hlist_for_each_entry_rcu(tic, n, &ioc->tic_list, tic_list)
		func(ioc, tic);
}

/*
 * Call func for each tic attached to this ioc.
 */
static void
call_for_each_tic(struct io_context *ioc,
		  void (*func)(struct io_context *, struct tpps_io_context *))
{
	rcu_read_lock();
	__call_for_each_tic(ioc, func);
	rcu_read_unlock();
}

/*
 * Must be called with rcu_read_lock() held or preemption otherwise disabled.
 * Only two callers of this - ->dtor() which is called with the rcu_read_lock(),
 * and ->trim() which is called with the task lock held
 */
static void tpps_free_io_context(struct io_context *ioc)
{
	/*
	 * ioc->refcount is zero here, or we are called from elv_unregister(),
	 * so no more tic's are allowed to be linked into this ioc.  So it
	 * should be ok to iterate over the known list, we will see all tic's
	 * since no new ones are added.
	 */
	__call_for_each_tic(ioc, tic_free_func);
}

static void tpps_put_tppg(struct tpps_data *tppd, struct tpps_group *tppg)
{
	BUG_ON(tppg->ref <= 0);
	tppg->ref--;
	if (tppg->ref)
		return;
	tpps_log_tppg(tppd, tppg, "del group");
	if (!list_empty(&tppg->tppd_node))
		list_del_init(&tppg->tppd_node);
	blkiocg_update_dequeue_stats(&tppg->blkg, 1);

	BUG_ON(!list_empty(&(tppg->queue_list)));
	free_percpu(tppg->blkg.stats_cpu);
	blk_exit_rl(&tppg->blkg.rl);
	list_del(&tppg->blkg.q_node);
	kfree(tppg);
}

static void tpps_del_queue(struct tpps_queue *tppq)
{
	struct tpps_data *tppd = tppq->tppd;
	struct tpps_group *tppg = tppq->tppg;

	if (!list_empty(&tppq->tppg_node)) {
		list_del_init(&tppq->tppg_node);
		tpps_log_tppq(tppd, tppq, "del queue\n");
		tppg->cur_dispatcher = NULL;
		tppq->tppg = NULL;
	}

	BUG_ON(tppg->nr_tppq < 1);
	tppg->nr_tppq--;
	if (!tppg->nr_tppq)
		tppd->total_weight -= tppg->weight;

	BUG_ON(!tppd->busy_queues);
	tppd->busy_queues--;
}

/*
 * task holds one reference to the queue, dropped when task exits. each rq
 * in-flight on this queue also holds a reference, dropped when rq is freed.
 *
 * Each tpps queue took a reference on the parent group. Drop it now.
 * queue lock must be held here.
 */
static void tpps_put_queue(struct tpps_queue *tppq)
{
	struct tpps_data *tppd = tppq->tppd;
	struct tpps_group *tppg;

	BUG_ON(tppq->ref <= 0);

	tppq->ref--;
	if (tppq->ref)
		return;

	tpps_log_tppq(tppd, tppq, "put_queue");
	BUG_ON(!list_empty(&tppq->sort_list));
	tppg = tppq->tppg;

	tpps_del_queue(tppq);
	kmem_cache_free(tpps_pool, tppq);
	tpps_put_tppg(tppd, tppg);
}

static void __tpps_exit_single_io_context(struct tpps_data *tppd,
					 struct tpps_io_context *tic)
{
	struct io_context *ioc = tic->ioc;

	list_del_init(&tic->queue_list);

	/*
	 * Make sure key == NULL is seen for dead queues
	 */
	smp_wmb();
	tic->dead_key = (unsigned long) tic->key;
	tic->key = NULL;

	if (rcu_dereference(ioc->ioc_data) == tic) {
		spin_lock(&ioc->lock);
		rcu_assign_pointer(ioc->ioc_data, NULL);
		spin_unlock(&ioc->lock);
	}

	if (tic->tppq) {
		tpps_put_queue(tic->tppq);
		tic->tppq = NULL;
	}
}

static void tpps_exit_single_io_context(struct io_context *ioc,
				       struct tpps_io_context *tic)
{
	struct tpps_data *tppd = tic->key;

	if (tppd) {
		struct request_queue *q = tppd->queue;
		unsigned long flags;

		spin_lock_irqsave(q->queue_lock, flags);

		/*
		 * Ensure we get a fresh copy of the ->key to prevent
		 * race between exiting task and queue
		 */
		smp_read_barrier_depends();
		if (tic->key)
			__tpps_exit_single_io_context(tppd, tic);

		spin_unlock_irqrestore(q->queue_lock, flags);
	}
}

/*
 * The process that ioc belongs to has exited, we need to clean up
 * and put the internal structures we have that belongs to that process.
 */
static void tpps_exit_io_context(struct io_context *ioc)
{
	call_for_each_tic(ioc, tpps_exit_single_io_context);
}

static struct tpps_io_context *
tpps_alloc_io_context(struct tpps_data *tppd, gfp_t gfp_mask)
{
	struct tpps_io_context *tic;

	tic = kmem_cache_alloc_node(tpps_ioc_pool, gfp_mask | __GFP_ZERO,
							tppd->queue->node);
	if (tic) {
		INIT_LIST_HEAD(&tic->queue_list);
		INIT_HLIST_NODE(&tic->tic_list);
		tic->dtor = tpps_free_io_context;
		tic->exit = tpps_exit_io_context;
		elv_ioc_count_inc(tpps_ioc_count);
	}

	return tic;
}

/*
 * Add tic into ioc, using ttpd as the search key. This enables us to lookup
 * the process specific tpps io context when entered from the block layer.
 * Also adds the tic to a per-tppd list, used when this queue is removed.
 */
static int tpps_tic_link(struct tpps_data *tppd, struct io_context *ioc,
			struct tpps_io_context *tic, gfp_t gfp_mask)
{
	unsigned long flags;
	int ret;

	ret = radix_tree_preload(gfp_mask);
	if (!ret) {
		tic->ioc = ioc;
		tic->key = tppd;

		spin_lock_irqsave(&ioc->lock, flags);
		ret = radix_tree_insert(&ioc->radix_root,
						(unsigned long) tppd, tic);
		if (!ret)
			hlist_add_head_rcu(&tic->tic_list, &ioc->tic_list);
		spin_unlock_irqrestore(&ioc->lock, flags);

		radix_tree_preload_end();

		if (!ret) {
			spin_lock_irqsave(tppd->queue->queue_lock, flags);
			list_add(&tic->queue_list, &tppd->tic_list);
			spin_unlock_irqrestore(tppd->queue->queue_lock, flags);
		}
	}

	if (ret && ret != -EEXIST)
		printk(KERN_ERR "tppq: tic link failed!\n");

	return ret;
}

static inline struct tpps_queue *tic_to_tppq(struct tpps_io_context *tic)
{
	return tic->tppq;
}

static inline void tic_set_tppq(struct tpps_io_context *tic,
				struct tpps_queue *tppq)
{
	tic->tppq = tppq;
}

static void changed_cgroup(struct io_context *ioc, struct tpps_io_context *tic)
{
	struct tpps_queue *tppq = tic_to_tppq(tic);
	struct tpps_data *tppd = tic->key;
	unsigned long flags;
	struct request_queue *q;

	if (unlikely(!tppd))
		return;

	q = tppd->queue;

	spin_lock_irqsave(q->queue_lock, flags);

	if (tppq) {
		tpps_log_tppq(tppd, tppq, "changed cgroup");
		tic_set_tppq(tic, NULL);
		tpps_put_queue(tppq);
	}

	spin_unlock_irqrestore(q->queue_lock, flags);
}

static void tpps_ioc_set_cgroup(struct io_context *ioc)
{
	call_for_each_tic(ioc, changed_cgroup);
	ioc->cgroup_changed = 0;
}

/*
 * Setup general io context and tpps io context. There can be several tpps
 * io contexts per general io context, if this process is doing io to more
 * than one device managed by tpps.
 */
static struct tpps_io_context *
tpps_get_io_context(struct tpps_data *tppd, gfp_t gfp_mask)
{
	struct io_context *ioc = NULL;
	struct tpps_io_context *tic;
	int ret;

	might_sleep_if(gfp_mask & __GFP_WAIT);

	ioc = get_io_context(gfp_mask, tppd->queue->node);
	if (!ioc)
		return NULL;

retry:
	tic = tpps_tic_lookup(tppd, ioc);
	if (tic)
		goto out;

	tic = tpps_alloc_io_context(tppd, gfp_mask);
	if (tic == NULL)
		goto err;

	ret = tpps_tic_link(tppd, ioc, tic, gfp_mask);
	if (ret == -EEXIST) {
		/* someone has linked tic to ioc already */
		tpps_tic_free(tic);
		goto retry;
	} else if (ret)
		goto err_free;

out:
	smp_read_barrier_depends();
	if (unlikely(ioc->cgroup_changed))
		tpps_ioc_set_cgroup(ioc);
	return tic;
err_free:
	tpps_tic_free(tic);
err:
	put_io_context(ioc);
	return NULL;
}

static inline struct tpps_group *tppg_of_blkg(struct blkio_group *blkg)
{
	if (blkg)
		return container_of(blkg, struct tpps_group, blkg);
	return NULL;
}

static struct tpps_group *
tpps_find_tppg(struct tpps_data *tppd, struct blkio_cgroup *blkcg)
{
	struct tpps_group *tppg = NULL;
	struct backing_dev_info *bdi = &tppd->queue->backing_dev_info;
	unsigned int major, minor;

	/*
	 * This is the common case when there are no blkio cgroups.
	 * Avoid lookup in this case
	 */
	if (blkcg == &blkio_root_cgroup)
		tppg = &tppd->root_group;
	else
		tppg = tppg_of_blkg(blkiocg_lookup_group(blkcg, tppd->queue,
							 BLKIO_POLICY_PROP));

	if (tppg && !tppg->blkg.dev && bdi->dev && dev_name(bdi->dev)) {
		sscanf(dev_name(bdi->dev), "%u:%u", &major, &minor);
		tppg->blkg.dev = MKDEV(major, minor);
	}

	return tppg;
}

/*
 * Should be called from sleepable context. No request queue lock as per
 * cpu stats are allocated dynamically and alloc_percpu needs to be called
 * from sleepable context.
 */
static struct tpps_group *tpps_alloc_tppg(struct tpps_data *tppd)
{
	struct tpps_group *tppg = NULL;
	int ret;

	tppg = kzalloc_node(sizeof(*tppg), GFP_ATOMIC, tppd->queue->node);
	if (!tppg)
		return NULL;

	INIT_LIST_HEAD(&tppg->queue_list);
	INIT_LIST_HEAD(&tppg->tppd_node);

	/*
	 * Take the initial reference that will be released on destroy
	 * This can be thought of a joint reference by cgroup and
	 * elevator which will be dropped by either elevator exit
	 * or cgroup deletion path depending on who is exiting first.
	 */
	tppg->ref = 1;

	ret = blkio_alloc_blkg_stats(&tppg->blkg);
	if (ret) {
		kfree(tppg);
		return NULL;
	}

	return tppg;
}

static void tpps_init_add_tppg_lists(struct tpps_data *tppd,
			struct tpps_group *tppg, struct blkio_cgroup *blkcg)
{
	struct backing_dev_info *bdi = &tppd->queue->backing_dev_info;
	unsigned int major, minor;

	/*
	 * Add group onto cgroup list. It might happen that bdi->dev is
	 * not initialized yet. Initialize this new group without major
	 * and minor info and this info will be filled in once a new thread
	 * comes for IO.
	 */
	if (bdi->dev) {
		sscanf(dev_name(bdi->dev), "%u:%u", &major, &minor);
		blkiocg_add_blkio_group(blkcg, &tppg->blkg,
					tppd->queue, MKDEV(major, minor),
					BLKIO_POLICY_PROP);
	} else
		blkiocg_add_blkio_group(blkcg, &tppg->blkg,
					tppd->queue, 0, BLKIO_POLICY_PROP);

	tppd->nr_blkcg_linked_grps++;
	tppg->weight = blkcg_get_weight(blkcg, tppg->blkg.dev);

	/* Add group on tppd list */
	list_add(&tppg->tppd_node, &tppd->group_list);
}

/*
 * Search for the tpps group current task belongs to. request_queue lock must
 * be held.
 */
static struct tpps_group *tpps_get_tppg(struct tpps_data *tppd)
{
	struct blkio_cgroup *blkcg;
	struct tpps_group *tppg = NULL, *__tppg = NULL;
	struct request_queue *q = tppd->queue;

	rcu_read_lock();
	blkcg = task_blkio_cgroup(current);
	tppg = tpps_find_tppg(tppd, blkcg);
	if (tppg) {
		rcu_read_unlock();
		return tppg;
	}

	/*
	 * Need to allocate a group. Allocation of group also needs allocation
	 * of per cpu stats which in-turn takes a mutex() and can block. Hence
	 * we need to drop rcu lock and queue_lock before we call alloc.
	 *
	 * Not taking any queue reference here and assuming that queue is
	 * around by the time we return. TPPS queue allocation code does
	 * the same. It might be racy though.
	 */

	rcu_read_unlock();
	spin_unlock_irq(q->queue_lock);

	tppg = tpps_alloc_tppg(tppd);

	spin_lock_irq(q->queue_lock);

	rcu_read_lock();
	blkcg = task_blkio_cgroup(current);

	/*
	 * If some other thread already allocated the group while we were
	 * not holding queue lock, free up the group
	 */
	__tppg = tpps_find_tppg(tppd, blkcg);

	if (__tppg) {
		kfree(tppg);
		rcu_read_unlock();
		return __tppg;
	}

	if (!tppg)
		tppg = &tppd->root_group;
	else if (blkcg != &blkio_root_cgroup) {
		if (blk_init_rl(&tppg->blkg.rl, q, GFP_ATOMIC)) {
			kfree(tppg);
			rcu_read_unlock();
			return NULL;
		}
		tppg->blkg.rl.blkg = &tppg->blkg;
		INIT_LIST_HEAD(&tppg->blkg.q_node);
		list_add(&tppg->blkg.q_node, &q->blkg_list);
	}

	tpps_init_add_tppg_lists(tppd, tppg, blkcg);
	rcu_read_unlock();
	return tppg;
}

static void tpps_init_tppq(struct tpps_data *tppd, struct tpps_queue *tppq,
			  pid_t pid)
{
	INIT_LIST_HEAD(&tppq->tppg_node);
	INIT_LIST_HEAD(&tppq->sort_list);

	tppq->ref = 0;
	tppq->tppd = tppd;
	tppq->pid = pid;

}

static void tpps_link_tppq_tppg(struct tpps_queue *tppq,
		struct tpps_group *tppg)
{
	tppq->tppg = tppg;
	/* tppq reference on tppg */
	tppq->tppg->ref++;
}

static struct tpps_queue *
tpps_find_alloc_queue(struct tpps_data *tppd, struct io_context *ioc,
		gfp_t gfp_mask)
{
	struct tpps_queue *tppq, *new_tppq = NULL;
	struct tpps_io_context *tic;
	struct tpps_group *tppg;

retry:
	tppg = tpps_get_tppg(tppd);
	tic = tpps_tic_lookup(tppd, ioc);
	/* tic always exists here */
	tppq = tic_to_tppq(tic);

	if (!tppq) {
		if (new_tppq) {
			tppq = new_tppq;
			new_tppq = NULL;
		} else if (gfp_mask & __GFP_WAIT) {
			spin_unlock_irq(tppd->queue->queue_lock);
			new_tppq = kmem_cache_alloc_node(tpps_pool,
					gfp_mask | __GFP_ZERO,
					tppd->queue->node);
			spin_lock_irq(tppd->queue->queue_lock);
			if (new_tppq)
				goto retry;
		} else
			tppq = kmem_cache_alloc_node(tpps_pool,
					gfp_mask | __GFP_ZERO,
					tppd->queue->node);

		if (tppq) {
			tpps_init_tppq(tppd, tppq, current->pid);
			tpps_link_tppq_tppg(tppq, tppg);
			tpps_log_tppq(tppd, tppq, "alloced");
		}
	}

	if (new_tppq)
		kmem_cache_free(tpps_pool, new_tppq);

	return tppq;
}

static struct tpps_queue *
tpps_get_queue(struct tpps_data *tppd, struct io_context *ioc, gfp_t gfp_mask)
{
	struct tpps_queue *tppq;

	tppq = tpps_find_alloc_queue(tppd, ioc, gfp_mask);
	tppq->ref++;
	return tppq;
}

static inline struct tpps_group *tpps_ref_get_tppg(struct tpps_group *tppg)
{
	tppg->ref++;
	return tppg;
}

/*
 * scheduler run of queue, if there are requests pending and no one in the
 * driver that will restart queueing
 */
static inline void tpps_schedule_dispatch(struct tpps_data *tppd)
{
	if (tppd->busy_queues) {
		tpps_log(tppd, "schedule dispatch");
		kblockd_schedule_work(tppd->queue, &tppd->unplug_work);
	}
}

static int
tpps_set_request(struct request_queue *q, struct request *rq, gfp_t gfp_mask)
{
	struct tpps_data *tppd = q->elevator->elevator_data;
	struct tpps_io_context *tic;
	struct tpps_queue *tppq;
	unsigned long flags;

	tic = tpps_get_io_context(tppd, gfp_mask);

	spin_lock_irqsave(q->queue_lock, flags);
	if (!tic)
		goto queue_fail;

	tppq = tic_to_tppq(tic);
	if (!tppq) {
		tppq = tpps_get_queue(tppd, tic->ioc, gfp_mask);
		tic_set_tppq(tic, tppq);
	}

	tppq->ref++;
	rq->elevator_private[0] = tic;
	rq->elevator_private[1] = tppq;
	rq->elevator_private[2] = tpps_ref_get_tppg(tppq->tppg);

	spin_unlock_irqrestore(q->queue_lock, flags);
	return 0;

queue_fail:
	if (tic)
		put_io_context(tic->ioc);

	tpps_schedule_dispatch(tppd);
	spin_unlock_irqrestore(q->queue_lock, flags);
	tpps_log(tppd, "set_request fail");
	return 1;
}

/*
 * queue lock held here
 */
static void tpps_put_request(struct request *rq)
{
	struct tpps_queue *tppq = RQ_TPPQ(rq);

	if (tppq) {
		WARN_ON(tppq->tppg != RQ_TPPG(rq));

		put_io_context(RQ_TIC(rq)->ioc);

		rq->elevator_private[0] = NULL;
		rq->elevator_private[1] = NULL;

		/* Put down rq reference on tppg */
		tpps_put_tppg(tppq->tppd, RQ_TPPG(rq));
		rq->elevator_private[2] = NULL;

		tpps_put_queue(tppq);
	}
}

static void
tpps_update_group_weight(struct tpps_group *tppg)
{
	if (tppg->needs_update) {
		tppg->weight = tppg->new_weight;
		tppg->needs_update = false;
	}
}

static void tpps_add_queue(struct tpps_data *tppd, struct tpps_queue *tppq)
{
	struct tpps_group *tppg;

	if (!tppq->online) {
		tppq->online = 1;
		tppg = tppq->tppg;
		tpps_log_tppq(tppd, tppq, "add queue");
		tppg->nr_tppq++;
		tppd->busy_queues++;
		list_add(&tppq->tppg_node, &tppg->queue_list);
		tpps_update_group_weight(tppg);
		if (tppg->nr_tppq <= 1)
			tppd->total_weight += tppg->weight;
	}
}

static void tpps_insert_request(struct request_queue *q, struct request *rq)
{
	struct tpps_data *tppd = q->elevator->elevator_data;
	struct tpps_queue *tppq = RQ_TPPQ(rq);

	tpps_log_tppq(tppd, tppq, "insert_request");

	list_add_tail(&rq->queuelist, &tppq->sort_list);
	tppq->rq_queued++;
	tppq->tppg->rq_queued++;
	tppd->dispatched++;
	tpps_add_queue(tppd, tppq);
	blkiocg_update_io_add_stats(&(RQ_TPPG(rq))->blkg, &tppq->tppg->blkg,
			rq_data_dir(rq), rq_is_sync(rq));
}

static void tpps_remove_request(struct request *rq)
{
	struct tpps_queue *tppq = RQ_TPPQ(rq);

	list_del_init(&rq->queuelist);
	tppq->rq_queued--;
	tppq->tppg->rq_queued--;
	blkiocg_update_io_remove_stats(&(RQ_TPPG(rq))->blkg,
			rq_data_dir(rq), rq_is_sync(rq));
}

/*
 * Move request from internal lists to the request queue dispatch list.
 */
static int tpps_dispatch_insert(struct request_queue *q,
				struct tpps_queue *tppq)
{
	struct list_head *rbnext = tppq->sort_list.next;
	struct request *rq;

	if (rbnext == &tppq->sort_list)
		return 0;

	rq = rq_entry_fifo(rbnext);
	tpps_remove_request(rq);
	elv_dispatch_sort(q, rq);
	blkiocg_update_dispatch_stats(&tppq->tppg->blkg, blk_rq_bytes(rq),
					rq_data_dir(rq), rq_is_sync(rq));
	return 1;
}

static int tpps_dispatch_requests_nr(struct tpps_data *tppd,
				struct tpps_queue *tppq, int count)
{
	int cnt = 0, ret;

	if (!tppq->rq_queued)
		return cnt;

	do {
		ret = tpps_dispatch_insert(tppd->queue, tppq);
		if (ret) {
			cnt++;
			tppd->dispatched--;
		}
	} while (ret && cnt < count);

	return cnt;
}

static int tpps_forced_dispatch(struct tpps_data *tppd)
{
	struct tpps_group *tppg, *group_n;
	struct tpps_queue *tppq;
	struct list_head *next;
	int total = 0, ret;

	list_for_each_entry_safe(tppg, group_n, &tppd->group_list, tppd_node) {
		if (!tppg->nr_tppq)
			continue;
		tpps_log_tppg(tppd, tppg, "(force) nr:%d, wt:%u total_wt:%u",
				tppg->nr_tppq, tppg->weight, tppd->total_weight)
		BUG_ON(tppg->queue_list.next == &tppg->queue_list);
		if (!tppg->cur_dispatcher)
			tppg->cur_dispatcher = tppg->queue_list.next;
		next = tppg->cur_dispatcher;
		do {
			tppq = list_entry(next, struct tpps_queue, tppg_node);
			ret = tpps_dispatch_requests_nr(tppd, tppq, -1);
			total += ret;
			next = next->next;
			if (next == &tppg->queue_list)
				next = tppg->queue_list.next;
			BUG_ON(tppg->cur_dispatcher == &tppg->queue_list);
		} while (next != tppg->cur_dispatcher);
	}
	return total > 0;
}

static int tpps_dispatch_requests(struct request_queue *q, int force)
{
	struct tpps_data *tppd = q->elevator->elevator_data;
	struct tpps_group *tppg, *group_n;
	struct tpps_queue *tppq;
	struct list_head *next;
	int count = 0, total = 0, ret;
	int quota, grp_quota;

	if (unlikely(force))
		return tpps_forced_dispatch(tppd);

	if (!tppd->total_weight)
		return 0;

	quota = q->nr_requests - tppd->rq_in_driver;
	if (quota < MIN_DISPATCH_RQ)
		return 0;

	list_for_each_entry_safe(tppg, group_n, &tppd->group_list, tppd_node) {
		if (!tppg->nr_tppq)
			continue;
		tpps_update_group_weight(tppg);
		grp_quota = (quota * tppg->weight / tppd->total_weight) -
						tppg->rq_in_driver;
		if (grp_quota <= 0)
			continue;
		tpps_log_tppg(tppd, tppg,
			"nr:%d, wt:%u total_wt:%u quota:%d "
			"gp_quota:%d in_drv:%d queued:%d",
			tppg->nr_tppq, tppg->weight, tppd->total_weight,
			quota, grp_quota, tppg->rq_in_driver, tppg->rq_queued);
		BUG_ON(tppg->queue_list.next == &tppg->queue_list);
		if (!tppg->cur_dispatcher)
			tppg->cur_dispatcher = tppg->queue_list.next;
		next = tppg->cur_dispatcher;
		count = 0;
		do {
			tppq = list_entry(next, struct tpps_queue, tppg_node);
			ret = tpps_dispatch_requests_nr(tppd, tppq, 1);
			count += ret;
			total += ret;
			next = next->next;
			if (next == &tppg->queue_list)
				next = tppg->queue_list.next;
			if (count >= grp_quota) {
				tppg->cur_dispatcher = next;
				break;
			}
			BUG_ON(tppg->cur_dispatcher == &tppg->queue_list);
		} while (next != tppg->cur_dispatcher);
	}
	return total > 0;
}

static void tpps_kick_queue(struct work_struct *work)
{
	struct tpps_data *tppd =
		container_of(work, struct tpps_data, unplug_work);
	struct request_queue *q = tppd->queue;

	spin_lock_irq(q->queue_lock);
	__blk_run_queue(q);
	spin_unlock_irq(q->queue_lock);
}

static void *tpps_init_queue(struct request_queue *q)
{
	struct tpps_data *tppd;
	struct tpps_group *tppg;

	tppd = kmalloc_node(sizeof(*tppd), GFP_KERNEL | __GFP_ZERO, q->node);
	if (!tppd)
		return NULL;

	INIT_LIST_HEAD(&tppd->group_list);
	INIT_LIST_HEAD(&tppd->tic_list);

	/* Init root group */
	tppg = &tppd->root_group;
	INIT_LIST_HEAD(&tppg->queue_list);
	INIT_LIST_HEAD(&tppg->tppd_node);

	/* Give preference to root group over other groups */
	tppg->weight = 2 * BLKIO_WEIGHT_DEFAULT;
	tppg->ref = 2;

	if (blkio_alloc_blkg_stats(&tppg->blkg)) {
		kfree(tppd);
		return NULL;
	}

	rcu_read_lock();

	blkiocg_add_blkio_group(&blkio_root_cgroup, &tppg->blkg,
					tppd->queue, 0, BLKIO_POLICY_PROP);
	rcu_read_unlock();
	tppd->nr_blkcg_linked_grps++;

	/* Add group on tppd->group_list */
	list_add(&tppg->tppd_node, &tppd->group_list);

	INIT_LIST_HEAD(&tppd->tic_list);
	tppd->queue = q;

	INIT_WORK(&tppd->unplug_work, tpps_kick_queue);

	return tppd;
}

static void tpps_destroy_tppg(struct tpps_data *tppd, struct tpps_group *tppg)
{
	/* Something wrong if we are trying to remove same group twice */
	BUG_ON(list_empty(&tppg->tppd_node));

	list_del_init(&tppg->tppd_node);

	BUG_ON(tppd->nr_blkcg_linked_grps <= 0);
	tppd->nr_blkcg_linked_grps--;

	/*
	 * Put the reference taken at the time of creation so that when all
	 * queues are gone, group can be destroyed.
	 */
	tpps_put_tppg(tppd, tppg);
}

static void tpps_release_tpps_groups(struct tpps_data *tppd)
{
	struct tpps_group *tppg, *n;

	list_for_each_entry_safe(tppg, n, &tppd->group_list, tppd_node) {
		/*
		 * If cgroup removal path got to blk_group first and removed
		 * it from cgroup list, then it will take care of destroying
		 * tppg also.
		 */
		if (!blkiocg_del_blkio_group(&tppg->blkg))
			tpps_destroy_tppg(tppd, tppg);
	}
}

static void tpps_exit_queue(struct elevator_queue *e)
{
	struct tpps_data *tppd = e->elevator_data;
	struct request_queue *q = tppd->queue;
	bool wait = false;

	cancel_work_sync(&tppd->unplug_work);
	spin_lock_irq(q->queue_lock);

	while (!list_empty(&tppd->tic_list)) {
		struct tpps_io_context *tic = list_entry(tppd->tic_list.next,
							struct tpps_io_context,
							queue_list);

		__tpps_exit_single_io_context(tppd, tic);
	}

	tpps_release_tpps_groups(tppd);

	/*
	 * If there are groups which we could not unlink from blkcg list,
	 * wait for a rcu period for them to be freed.
	 */
	if (tppd->nr_blkcg_linked_grps)
		wait = true;

	spin_unlock_irq(q->queue_lock);

	/*
	 * Wait for tppg->blkg->key accessors to exit their grace periods.
	 * Do this wait only if there are other unlinked groups out
	 * there. This can happen if cgroup deletion path claimed the
	 * responsibility of cleaning up a group before queue cleanup code
	 * get to the group.
	 *
	 * Do not call synchronize_rcu() unconditionally as there are drivers
	 * which create/delete request queue hundreds of times during scan/boot
	 * and synchronize_rcu() can take significant time and slow down boot.
	 */
	if (wait)
		synchronize_rcu();

	/* Free up per cpu stats for root group */
	free_percpu(tppd->root_group.blkg.stats_cpu);
	kfree(tppd);
}

static void tpps_activate_request(struct request_queue *q, struct request *rq)
{
	struct tpps_queue *tppq = RQ_TPPQ(rq);
	struct tpps_data *tppd = q->elevator->elevator_data;
	tppd->rq_in_driver++;
	tppq->tppg->rq_in_driver++;
	tpps_log_tppq(tppd, RQ_TPPQ(rq), "activate rq, drv=%d",
						tppd->rq_in_driver);
}

static void tpps_deactivate_request(struct request_queue *q, struct request *rq)
{
	struct tpps_queue *tppq = RQ_TPPQ(rq);
	struct tpps_data *tppd = q->elevator->elevator_data;

	WARN_ON(!tppd->rq_in_driver);
	tppd->rq_in_driver--;
	tppq->tppg->rq_in_driver--;
	tpps_log_tppq(tppd, RQ_TPPQ(rq), "deactivate rq, drv=%d",
						tppd->rq_in_driver);
}

static void tpps_completed_request(struct request_queue *q, struct request *rq)
{
	struct tpps_queue *tppq = RQ_TPPQ(rq);
	struct tpps_data *tppd = tppq->tppd;

	WARN_ON(!tppq);
	WARN_ON(tppq->tppg != RQ_TPPG(rq));

	tpps_log_tppq(tppd, tppq, "complete rqnoidle %d",
			!!(rq->cmd_flags & REQ_NOIDLE));
	WARN_ON(!tppd->rq_in_driver);
	tppd->rq_in_driver--;
	tppq->tppg->rq_in_driver--;
	blkiocg_update_completion_stats(&tppq->tppg->blkg,
			rq_start_time_ns(rq), rq_io_start_time_ns(rq),
			rq_data_dir(rq), rq_is_sync(rq));

	if (!tppd->rq_in_driver)
		tpps_schedule_dispatch(tppd);
}

static int tpps_queue_empty(struct request_queue *q)
{
	struct tpps_data *tppd = q->elevator->elevator_data;

	return !tppd->dispatched;
}

static void
tpps_merged_request(struct request_queue *q, struct request *rq, int type)
{
	if (type == ELEVATOR_FRONT_MERGE) {
		struct tpps_queue *tppq = RQ_TPPQ(rq);
		list_del_init(&rq->queuelist);
		tppq->rq_queued--;
		blkiocg_update_io_remove_stats(&(RQ_TPPG(rq))->blkg,
			rq_data_dir(rq), rq_is_sync(rq));
		list_add_tail(&rq->queuelist, &tppq->sort_list);
		tppq->rq_queued++;
		blkiocg_update_io_add_stats(&(RQ_TPPG(rq))->blkg,
			&tppq->tppg->blkg, rq_data_dir(rq),
			rq_is_sync(rq));
	}
}

static void
tpps_merged_requests(struct request_queue *q, struct request *rq,
			struct request *next)
{
	tpps_remove_request(next);
	blkiocg_update_io_merged_stats(&(RQ_TPPG(rq))->blkg,
			rq_data_dir(next), rq_is_sync(next));
}

static struct elevator_type iosched_tpps = {
	.ops = {
		.elevator_merged_fn =		tpps_merged_request,
		.elevator_merge_req_fn =	tpps_merged_requests,
		.elevator_dispatch_fn =		tpps_dispatch_requests,
		.elevator_add_req_fn =		tpps_insert_request,
		.elevator_queue_empty_fn =	tpps_queue_empty,
		.elevator_activate_req_fn = 	tpps_activate_request,
		.elevator_deactivate_req_fn = 	tpps_deactivate_request,
		.elevator_completed_req_fn =	tpps_completed_request,
		.elevator_set_req_fn =		tpps_set_request,
		.elevator_put_req_fn =		tpps_put_request,
		.elevator_init_fn =		tpps_init_queue,
		.elevator_exit_fn =		tpps_exit_queue,
		.trim =				tpps_free_io_context,
	},
	.elevator_name =	"tpps",
	.elevator_owner =	THIS_MODULE,
};

void tpps_unlink_blkio_group(struct request_queue *q, struct blkio_group *blkg)
{
	struct tpps_data *tppd = q->elevator->elevator_data;
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	tpps_destroy_tppg(tppd, tppg_of_blkg(blkg));
	spin_unlock_irqrestore(q->queue_lock, flags);
}

void tpps_update_blkio_group_weight(struct request_queue *q,
					struct blkio_group *blkg,
					unsigned int weight)
{
	struct tpps_group *tppg = tppg_of_blkg(blkg);
	tppg->new_weight = weight;
	tppg->needs_update = true;
}

static struct blkio_policy_type blkio_policy_tpps = {
	.ops = {
		.blkio_unlink_group_fn = tpps_unlink_blkio_group,
		.blkio_update_group_weight_fn =	tpps_update_blkio_group_weight,
	},
	.plid = BLKIO_POLICY_PROP,
};

static void tpps_slab_kill(void)
{
	/*
	 * Caller already ensured that pending RCU callbacks are completed,
	 * so we should have no busy allocations at this point.
	 */
	if (tpps_pool)
		kmem_cache_destroy(tpps_pool);
	if (tpps_ioc_pool)
		kmem_cache_destroy(tpps_ioc_pool);
}

static int __init tpps_slab_setup(void)
{
	tpps_pool = KMEM_CACHE(tpps_queue, 0);
	if (!tpps_pool)
		goto fail;

	tpps_ioc_pool = KMEM_CACHE(tpps_io_context, 0);
	if (!tpps_ioc_pool)
		goto fail;

	return 0;
fail:
	tpps_slab_kill();
	return -ENOMEM;
}

static int __init tpps_init(void)
{
	if (tpps_slab_setup())
		return -ENOMEM;

	elv_register(&iosched_tpps);
	blkio_policy_register(&blkio_policy_tpps);
	return 0;
}

static void __exit tpps_exit(void)
{
	DECLARE_COMPLETION_ONSTACK(all_gone);
	blkio_policy_unregister(&blkio_policy_tpps);
	elv_unregister(&iosched_tpps);
	ioc_gone = &all_gone;
	/* ioc_gone's update must be visible before reading ioc_count */
	smp_wmb();

	/*
	 * this also protects us from entering tpps_slab_kill() with
	 * pending RCU callbacks
	 */
	if (elv_ioc_count_read(tpps_ioc_count))
		wait_for_completion(&all_gone);
	tpps_slab_kill();
}

module_init(tpps_init);
module_exit(tpps_exit);

MODULE_AUTHOR("Robin Dong");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Taobao Parallel Proportion io Scheduler");
