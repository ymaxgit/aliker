#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/quotaops.h>
#include <linux/quota.h>
#include <linux/pid_namespace.h>

static int flags_by_mnt(int mnt_flags)
{
	int flags = 0;

	if (mnt_flags & MNT_READONLY)
		flags |= ST_RDONLY;
	if (mnt_flags & MNT_NOSUID)
		flags |= ST_NOSUID;
	if (mnt_flags & MNT_NODEV)
		flags |= ST_NODEV;
	if (mnt_flags & MNT_NOEXEC)
		flags |= ST_NOEXEC;
	if (mnt_flags & MNT_NOATIME)
		flags |= ST_NOATIME;
	if (mnt_flags & MNT_NODIRATIME)
		flags |= ST_NODIRATIME;
	if (mnt_flags & MNT_RELATIME)
		flags |= ST_RELATIME;
	return flags;
}

static int flags_by_sb(int s_flags)
{
	int flags = 0;
	if (s_flags & MS_SYNCHRONOUS)
		flags |= ST_SYNCHRONOUS;
	if (s_flags & MS_MANDLOCK)
		flags |= ST_MANDLOCK;
	return flags;
}

static int calculate_f_flags(struct vfsmount *mnt)
{
	return ST_VALID | flags_by_mnt(mnt->mnt_flags) |
		flags_by_sb(mnt->mnt_sb->s_flags);
}

int statfs_by_dentry(struct dentry *dentry, struct kstatfs *buf)
{
	int retval;

	if (!dentry->d_sb->s_op->statfs)
		return -ENOSYS;

	memset(buf, 0, sizeof(*buf));
	retval = security_sb_statfs(dentry);
	if (retval)
		return retval;
	retval = dentry->d_sb->s_op->statfs(dentry, buf);
	if (retval == 0 && buf->f_frsize == 0)
		buf->f_frsize = buf->f_bsize;
	return retval;
}

#ifdef CONFIG_SUBTREE
static int do_check_quota_valid(struct super_block *sb)
{
	/* this is much simpler than generic_quotactl_valid() since we skip
	 * security check intentionally and only check if Q_GETQUOTA is valid.
	 */
	if (!sb)
		return -ENODEV;
	if (!sb->s_qcop)
		return -ENOSYS;
	if (!sb->s_qcop->get_dqblk)
		return -ENOSYS;
	if (!sb_has_quota_active(sb, GRPQUOTA))
		return -ESRCH;
	return 0;
}

static int do_getquota(struct if_dqblk *idq, unsigned long id, struct path *path)
{
	struct super_block *sb = NULL;
	int ret;
	sb = path->dentry->d_sb;
	ret = do_check_quota_valid(sb);
	if (ret)
		return ret;
	ret = sb->s_qcop->get_dqblk(sb, GRPQUOTA, id, idq);

	return ret;
}

static s64 get_dquota_id(void)
{
	struct nameidata nd;
	struct inode *inode;
	s64 ret = -1;
	ret = path_lookup("/", LOOKUP_FOLLOW, &nd);
	if (!ret) {
		inode = nd.path.dentry->d_inode;
		if (inode->i_sb->s_op->get_subtree)
			ret = inode->i_sb->s_op->get_subtree(inode);
		path_put(&nd.path);
	}
	return ret;
}

static void fixup_kstatfs(struct if_dqblk *idq, struct kstatfs *st)
{
	if (idq->dqb_bhardlimit) {
		st->f_blocks = DIV_ROUND_UP(
				idq->dqb_bhardlimit << QIF_DQBLKSIZE_BITS,
				st->f_bsize);
		st->f_bfree = st->f_bavail =
			st->f_blocks - DIV_ROUND_UP(idq->dqb_curspace, st->f_bsize);
	}
	if (idq->dqb_ihardlimit) {
		st->f_files = idq->dqb_curinodes;
		st->f_ffree = idq->dqb_ihardlimit - idq->dqb_curinodes;
	}
	return;
}
#endif

int vfs_statfs(struct path *path, struct kstatfs *buf)
{
	int error;
#ifdef CONFIG_SUBTREE
	int error1;
	s64 subtree = 0;
#endif

	error = statfs_by_dentry(path->dentry, buf);
	if (!error) {
		buf->f_flags = calculate_f_flags(path->mnt);
#ifdef CONFIG_SUBTREE
		subtree = get_dquota_id();
		if (in_noninit_pid_ns(current->nsproxy->pid_ns) && subtree > 0) {
			struct if_dqblk idq;
			memset(&idq, 0, sizeof(idq));
			error1 = do_getquota(&idq, (unsigned long)subtree, path);
			if (!error1)
				fixup_kstatfs(&idq, buf);
		}
#endif
	}
	return error;
}
EXPORT_SYMBOL(vfs_statfs);

static int do_statfs_native(struct path *path, struct statfs *buf)
{
	struct kstatfs st;
	int retval;

	retval = vfs_statfs(path, &st);
	if (retval)
		return retval;

	if (sizeof(*buf) == sizeof(st))
		memcpy(buf, &st, sizeof(st));
	else {
		if (sizeof buf->f_blocks == 4) {
			if ((st.f_blocks | st.f_bfree | st.f_bavail |
			     st.f_bsize | st.f_frsize) &
			    0xffffffff00000000ULL)
				return -EOVERFLOW;
			/*
			 * f_files and f_ffree may be -1; it's okay to stuff
			 * that into 32 bits
			 */
			if (st.f_files != -1 &&
			    (st.f_files & 0xffffffff00000000ULL))
				return -EOVERFLOW;
			if (st.f_ffree != -1 &&
			    (st.f_ffree & 0xffffffff00000000ULL))
				return -EOVERFLOW;
		}

		buf->f_type = st.f_type;
		buf->f_bsize = st.f_bsize;
		buf->f_blocks = st.f_blocks;
		buf->f_bfree = st.f_bfree;
		buf->f_bavail = st.f_bavail;
		buf->f_files = st.f_files;
		buf->f_ffree = st.f_ffree;
		buf->f_fsid = st.f_fsid;
		buf->f_namelen = st.f_namelen;
		buf->f_frsize = st.f_frsize;
		buf->f_flags = st.f_flags;
		memset(buf->f_spare, 0, sizeof(buf->f_spare));
	}
	return 0;
}

static int do_statfs64(struct path *path, struct statfs64 *buf)
{
	struct kstatfs st;
	int retval;

	retval = vfs_statfs(path, &st);
	if (retval)
		return retval;

	if (sizeof(*buf) == sizeof(st))
		memcpy(buf, &st, sizeof(st));
	else {
		buf->f_type = st.f_type;
		buf->f_bsize = st.f_bsize;
		buf->f_blocks = st.f_blocks;
		buf->f_bfree = st.f_bfree;
		buf->f_bavail = st.f_bavail;
		buf->f_files = st.f_files;
		buf->f_ffree = st.f_ffree;
		buf->f_fsid = st.f_fsid;
		buf->f_namelen = st.f_namelen;
		buf->f_frsize = st.f_frsize;
		buf->f_flags = st.f_flags;
		memset(buf->f_spare, 0, sizeof(buf->f_spare));
	}
	return 0;
}

SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
{
	struct path path;
	int error;

	error = user_path(pathname, &path);
	if (!error) {
		struct statfs tmp;
		error = do_statfs_native(&path, &tmp);
		if (!error && copy_to_user(buf, &tmp, sizeof(tmp)))
			error = -EFAULT;
		path_put(&path);
	}
	return error;
}

SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
{
	struct path path;
	long error;

	if (sz != sizeof(*buf))
		return -EINVAL;
	error = user_path(pathname, &path);
	if (!error) {
		struct statfs64 tmp;
		error = do_statfs64(&path, &tmp);
		if (!error && copy_to_user(buf, &tmp, sizeof(tmp)))
			error = -EFAULT;
		path_put(&path);
	}
	return error;
}

SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
{
	struct file *file;
	struct statfs tmp;
	int error;

	error = -EBADF;
	file = fget(fd);
	if (!file)
		goto out;
	error = do_statfs_native(&file->f_path, &tmp);
	if (!error && copy_to_user(buf, &tmp, sizeof(tmp)))
		error = -EFAULT;
	fput(file);
out:
	return error;
}

SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf)
{
	struct file *file;
	struct statfs64 tmp;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = -EBADF;
	file = fget(fd);
	if (!file)
		goto out;
	error = do_statfs64(&file->f_path, &tmp);
	if (!error && copy_to_user(buf, &tmp, sizeof(tmp)))
		error = -EFAULT;
	fput(file);
out:
	return error;
}

SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf)
{
	struct super_block *s;
	struct ustat tmp;
	struct kstatfs sbuf;
	int err;

	s = user_get_super(new_decode_dev(dev));
	if (!s)
		return -EINVAL;

	err = statfs_by_dentry(s->s_root, &sbuf);
	drop_super(s);
	if (err)
		return err;

	memset(&tmp,0,sizeof(struct ustat));
	tmp.f_tfree = sbuf.f_bfree;
	tmp.f_tinode = sbuf.f_ffree;

	return copy_to_user(ubuf, &tmp, sizeof(struct ustat)) ? -EFAULT : 0;
}
