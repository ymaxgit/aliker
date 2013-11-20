/*
 * linux/fs/ext4/subtree.c
 *
 * Copyright (C) 2012 Parallels Inc
 * Dmitry Monakhov <dmonakhov@openvz.org>
 */

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/quotaops.h>
#include <linux/xattr.h>
#include <linux/pid_namespace.h>

#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "subtree.h"

/*
 * Subtree assumptions:
 * (1) Each inode has subtree id. This id is persistently stored inside
 *     inode's xattr, usually inside ibody
 * (2) Subtree id is inherent from parent directory
 */

/*
 * Read subtree id from inode's xattr
 * Locking: none
 */
int ext4_subtree_xattr_read(struct inode *inode, unsigned int *subtree)
{
	__le32 dsk_subtree;
	int ret;

	dsk_subtree = 0;
	ret = ext4_xattr_get(inode, EXT4_XATTR_INDEX_SUBTREE, "",
			     &dsk_subtree, sizeof(dsk_subtree));
	if (ret < 0)
		return ret;
	if (ret != sizeof(dsk_subtree))
		return -EIO;

	*subtree = le32_to_cpu(dsk_subtree);
	return 0;
}

/*
 * Save subtree id to inode's xattr
 * Locking: none
 */
int ext4_subtree_xattr_write(handle_t *handle, struct inode *inode,
			     unsigned int subtree, int xflags)
{
	__le32 dsk_subtree = cpu_to_le32(subtree);
	int ret;

	ret = ext4_xattr_set_handle(handle, inode,
				    EXT4_XATTR_INDEX_SUBTREE, "",
				    &dsk_subtree, sizeof(dsk_subtree), xflags);
	return ret;
}

/*
 * Change subtree id
 * Called under inode->i_mutex
 */
int ext4_subtree_change(struct inode *inode, unsigned int new)
{
	handle_t *handle;
	struct dquot *new_dquot[MAXQUOTAS] = {};
	struct dquot *old_dquot[MAXQUOTAS] = {};
	unsigned credits, retries = 0;
	int old, new_dq_id;
	int ret = 0, ret2 = 0;

	if (!sb_has_quota_active(inode->i_sb, GRPQUOTA))
		return -EOPNOTSUPP;

	BUG_ON(!IS_SBTR_ID(new));

	/*
	 * If dir_subtree_id == 0 before, this inode is accounted in its
	 * standard group quota
	 */
	old = ext4_get_subtree(inode);

	/*
	 * To set dir_subtree_id == 0 means we want to cancel the dir quota
	 * accouting, so we shall give it back to the original owner.
	 */
	if (!new)
		new_dq_id = inode->i_gid;
	else
		new_dq_id = new;

	/*
	 * One data_trans_blocks chunk for xattr update.
	 * One quota_trans_blocks chunk for quota transfer, and one
	 * quota_trans_blocks chunk for emergency quota rollback transfer,
	 * because quota rollback may result new quota blocks allocation.
	 */
	credits = EXT4_DATA_TRANS_BLOCKS(inode->i_sb) +
		  EXT4_QUOTA_TRANS_BLOCKS(inode->i_sb) * 2;

	vfs_dq_init(inode);

	old_dquot[GRPQUOTA] = inode->i_dquot[GRPQUOTA];
	new_dquot[GRPQUOTA] = dqget(inode->i_sb, new_dq_id, GRPQUOTA);

	if (unlikely(!new_dquot[GRPQUOTA]))
		return -EFAULT;
	if (unlikely(!old_dquot[GRPQUOTA] ||
		     old_dquot[GRPQUOTA] == new_dquot[GRPQUOTA]))
		goto out_drop_dquot;

retry:
	handle = ext4_journal_start(inode, credits);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		ext4_std_error(inode->i_sb, ret);
		goto out_drop_dquot;
	}
	/* Inode may not have subtree xattr yet. Create it explicitly */
	ret = ext4_subtree_xattr_write(handle, inode, old, XATTR_CREATE);
	if (ret == -EEXIST)
		return 0;
	if (ret < 0) {
		ret2 = ext4_journal_stop(handle);
		if (ret2) {
			ret = ret2;
			goto out_drop_dquot;
		}
		if (ret == -ENOSPC &&
		    ext4_should_retry_alloc(inode->i_sb, &retries))
			goto retry;
		else
			goto out_drop_dquot;
	}

	ret = __dquot_transfer(inode, new_dquot);
	/*
	 * If __dquot_transfer() fails, new_dquot[] keeps untouched. Just
	 * release it and quit.
	 * 
	 * If __dquot_transfer() success, new_dquot[] is assigned to
	 * old_dquot[]. Because it might need fall back later, we don't
	 * release new_dquot now. This 'new_dquot[]' should be released
	 * after the xattr is also corrected.
	 * N.B. In the later case new_dquot[] has been lost.
	 */
	if (ret) {
		ret = -EDQUOT;
		goto out_journal;
	}

	ret = ext4_subtree_xattr_write(handle, inode, new, XATTR_REPLACE);
	if (ret) {
		/*
		 * Function may fail only due to fatal error, nor than less
		 * we have tried to rollback quota changes.
		 */
		/* This 'new_dquot' is the same with 'old_dquot' */
		__dquot_transfer(inode, new_dquot);
		ext4_std_error(inode->i_sb, ret);
	} else {
		ext4_set_subtree(inode, new);
	}

out_journal:
	ret2 = ext4_journal_stop(handle);
	if (ret2)
		ret = ret2;
out_drop_dquot:
	dqput(new_dquot[GRPQUOTA]);
	return ret;
}

int ext4_subtree_read(struct inode *inode)
{
	int ret;
	int subtree = 0;

	ret = ext4_subtree_xattr_read(inode, &subtree);
	if (ret == -ENODATA)
		ret = 0;
	if (!ret)
		ext4_set_subtree(inode, subtree);
	return ret;
}

/*
 * Initialize the subtree xattr of a new inode. Called from ext4_new_inode.
 *
 * dir->i_mutex: down
 * inode->i_mutex: up (access to inode is still exclusive)
 * Note: caller must assign correct subtree id to inode before.
 */
int ext4_subtree_init(handle_t *handle, struct inode *inode)
{
	return ext4_subtree_xattr_write(handle, inode,
					EXT4_I(inode)->i_subtree,
					XATTR_CREATE);
}

static size_t
ext4_xattr_subtree_list(struct inode *inode, char *list, size_t list_size,
			const char *name, size_t name_len)
{
	/* try to make the users believe there are not such xattr at all */
	if (in_noninit_pid_ns(current->nsproxy->pid_ns))
		return 0;

	if (list && XATTR_SUBTREE_LEN <= list_size)
		memcpy(list, XATTR_SUBTREE, XATTR_SUBTREE_LEN);
	return XATTR_SUBTREE_LEN;
}

static int
ext4_xattr_subtree_get(struct inode *inode, const char *name,
		       void *buffer, size_t size)
{
	int ret;
	int subtree;
	char buf[32];

	if (strcmp(name, "") != 0)
		return -EINVAL;

	/* try to make the users believe there are not such xattr at all */
	if (in_noninit_pid_ns(current->nsproxy->pid_ns))
		return -EOPNOTSUPP;

	ret = ext4_subtree_xattr_read(inode, &subtree);
	if (ret)
		return ret;
	snprintf(buf, sizeof(buf) - 1, "%u", subtree);
	buf[31] = '\0';
	strncpy(buffer, buf, size);
	return strlen(buf);
}

static int
ext4_xattr_subtree_set(struct inode *inode, const char *name,
		       const void *value, size_t size, int flags)
{
	unsigned long new;
	char buf[11];

	if (strcmp(name, "") != 0 || size + 1 > sizeof(buf))
		return -EINVAL;

	/* try to make the users believe there are not such xattr at all */
	if (in_noninit_pid_ns(current->nsproxy->pid_ns))
		return -EOPNOTSUPP;

	memcpy(buf, (char *)value, size);
	buf[size] = '\0';
	if (strict_strtoul(buf, 10, &new))
		return -EINVAL;
	if (!IS_SBTR_ID(new)) {
		ext4_warning(inode->i_sb,
			     "the min valid subtree id is 0x%x, or 0\n",
			     SBTR_MIN_ID);
		return -EINVAL;
	}
	return ext4_subtree_change(inode, new);
}

struct xattr_handler ext4_xattr_subtree_handler = {
	.prefix	= XATTR_SUBTREE,
	.list	= ext4_xattr_subtree_list,
	.get	= ext4_xattr_subtree_get,
	.set	= ext4_xattr_subtree_set,
};
