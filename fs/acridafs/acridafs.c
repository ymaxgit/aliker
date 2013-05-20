/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *                        2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/backing-dev.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#include "acridafs.h"
#include "kuafu_info.h"

/* some random number */
#define RAMFS_MAGIC    0x858458f6
#define MAX_NOFILE     32768
#define printk(...)

struct semaphore inode_mutex = __SEMAPHORE_INITIALIZER(inode_mutex, 1);

static struct super_operations acridafs_ops;
static struct address_space_operations acridafs_aops;
static struct inode_operations acridafs_file_inode_operations;
static struct inode_operations acridafs_dir_inode_operations;

static struct backing_dev_info acridafs_backing_dev_info = {
	.name           = "acridafs",
	.ra_pages       = 0,    /* No readahead */
	.capabilities   = BDI_CAP_NO_ACCT_AND_WRITEBACK |
					 BDI_CAP_MAP_DIRECT | BDI_CAP_MAP_COPY |
					 BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP |
					 BDI_CAP_EXEC_MAP,
};

const struct file_operations acridafs_file_operations;

struct dentry *g_root_dentry;
static int g_in_flush;

struct acrida_bdev {
	struct list_head        list;
	wait_queue_head_t       rwait;
	wait_queue_head_t       wwait;
	int                     nr_open;
	/* for lock */
	wait_queue_head_t       lockq;
	spinlock_t              spin;
	char                    *buff;
};

struct acrida_center_dev {
	struct miscdevice       misc;
	wait_queue_head_t       wait;
};

static DEFINE_RWLOCK(g_alive_lock);

static struct acrida_center_dev ac_dev;
static struct miscdevice ka_dev;
static int g_file_count;

static unsigned int acrida_center_poll(struct file *file, poll_table *wait);
static long acrida_center_ioctl(struct file *file, unsigned int cmd,
		unsigned long data);
static int acrida_center_open(struct inode *inode, struct file *file);
static int acrida_center_release(struct inode *inode, struct file *file);

static ssize_t kuafu_alive_read(struct file *file, char __user *user,
		size_t count, loff_t *off);
static ssize_t kuafu_alive_write(struct file *file, const char __user *user,
		size_t count, loff_t *off);
static int kuafu_alive_flush(struct file *file, fl_owner_t id);

struct inode *acridafs_get_inode(struct super_block *sb, int mode, dev_t dev)
{
	struct inode *inode = new_inode(sb);
	struct acrida_bdev *ab = NULL;

	if (inode) {
		inode->i_mode = mode;
		inode->i_uid = current_fsuid();
		inode->i_gid = current_fsgid();
		inode->i_blocks = 0;
		inode->i_mapping->a_ops = &acridafs_aops;
		inode->i_mapping->backing_dev_info = &acridafs_backing_dev_info;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_op = &acridafs_file_inode_operations;
			inode->i_fop = &acridafs_file_operations;

			ab = kmalloc(sizeof(struct acrida_bdev), GFP_KERNEL);
			if (ab) {
				init_waitqueue_head(&ab->rwait);
				init_waitqueue_head(&ab->wwait);
				init_waitqueue_head(&ab->lockq);
				spin_lock_init(&ab->spin);
				ab->nr_open = 0;
				inode->i_bdev = (struct block_device *)ab;
				ab->buff = NULL;
			}
			break;
		case S_IFDIR:
			inode->i_op = &acridafs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2
					* (for "." entry) */
			inode->i_nlink++;
			break;
		case S_IFLNK:
			inode->i_op = &page_symlink_inode_operations;
			break;
		}
	}
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
acridafs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	struct inode *inode = acridafs_get_inode(dir->i_sb, mode, dev);
	int error = -ENOSPC;

	if (inode) {
		if (dir->i_mode & S_ISGID) {
			inode->i_gid = dir->i_gid;
			if (S_ISDIR(mode))
				inode->i_mode |= S_ISGID;
		}
		d_instantiate(dentry, inode);
		dget(dentry);   /* Extra count - pin the dentry in core */
		error = 0;
	}
	return error;
}

static int acridafs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int retval = acridafs_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		dir->i_nlink++;
	return retval;
}

static int acridafs_create(struct inode *dir, struct dentry *dentry,
		int mode, struct nameidata *nd)
{
	return acridafs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int acridafs_symlink(struct inode *dir, struct dentry *dentry,
		const char *symname)
{
	struct inode *inode;
	int error = -ENOSPC;

	inode = acridafs_get_inode(dir->i_sb, S_IFLNK|S_IRWXUGO, 0);
	if (inode) {
		int l = strlen(symname)+1;
		error = page_symlink(inode, symname, l);
		if (!error) {
			if (dir->i_mode & S_ISGID)
				inode->i_gid = dir->i_gid;
			d_instantiate(dentry, inode);
			dget(dentry);
		} else
			iput(inode);
	}
	return error;
}

/* check the queue in the share memory */
unsigned int acridafs_file_poll(struct file *file, poll_table *wait)
{
	struct acrida_bdev *ab = NULL;
	unsigned int mask = 0;
	unsigned long begin = 0;
	unsigned long kfc_live = 0;
	struct page *page;
	int ret = -1;

	printk(KERN_ERR "------ poll ------\n");

	if (file && file->f_mapping && file->f_dentry &&
				file->f_dentry->d_inode &&
				file->f_dentry->d_inode->i_nlink) {
		ab = (struct acrida_bdev *)(file->f_dentry->d_inode->i_bdev);
		if (ab) {
			poll_wait(file, &ab->rwait, wait);
			poll_wait(file, &ab->wwait, wait);

			if (!ab->buff) {
				page = find_get_page(file->f_mapping, 0);
				if (page)
					ab->buff = page_address(page);
			}

			if (ab->buff) {
				begin = ((unsigned long *)(ab->buff))[0];
				kfc_live = ((unsigned long *)(ab->buff))[5];
				ret = 0;
			}
		}
	}

	printk(KERN_ERR "begin %lu, ret %d, kfc_live:%d\n",
				begin, ret, kfc_live);

	if (begin)
		mask |= POLLIN;
	else
		mask |= POLLOUT;

	if (ret || kfc_live == KFC_FAIL)
		mask |= POLLHUP | POLLERR;

	return mask;
}

/* when add msg or fetch msg from the queue, it will notify apps */
long acridafs_file_ioctl(struct file *file, unsigned int cmd,
		unsigned long data)
{
	struct page *page = NULL;
	struct inode *inode = NULL;
	struct acrida_bdev *ab = NULL;
	size_t *lock = NULL;
	int ret = 0;

	if (file->f_dentry && file->f_dentry->d_inode) {
		inode = file->f_dentry->d_inode;
		if (inode->i_nlink)
				ab = (struct acrida_bdev *)(inode->i_bdev);
	}

	if (!ab)
		goto out;

	if (cmd == COULD_READ) {
		wake_up_interruptible(&ab->rwait);
		goto out;
	}

	if (cmd == COULD_WRITE) {
		wake_up_interruptible(&ab->wwait);
		goto out;
	}

	if (!ab->buff) {
		page = find_get_page(file->f_mapping, 0);
		if (page)
				ab->buff = page_address(page);
	}
	if (ab->buff)
		lock = (size_t *)(ab->buff) + 6;

	if (cmd == ALOCK) {
retry:
		spin_lock(&ab->spin);
		if (*lock == 0) {
			*lock = current->tgid;
			printk(KERN_ERR "LOCK %d,%d\n", *lock, current->tgid);
		} else if (*lock != current->tgid) {
			spin_unlock(&ab->spin);

			printk(KERN_ERR "2LOCK %d,%d\n", *lock, current->tgid);
			/* unlock may wake up process before it sleep,
			 * so use wait_event_interruptible_timeout to
			 * check after a short time */
			ret = wait_event_interruptible_timeout(
				ab->lockq, (*lock == 0), HZ/10);
			/* if user use ctrl+c to kill a kuafu's app, the
			 * app should exit directly */
			if (ret == -ERESTARTSYS)
				goto out;

			printk(KERN_ERR "wake %d\n", *lock);
			goto retry;
		}
		spin_unlock(&ab->spin);
		goto out;
	}

	if (cmd == AUNLOCK) {
		spin_lock(&ab->spin);
		if (*lock == current->tgid) {
			printk(KERN_ERR "UNLOCK %d,%d\n", *lock, current->tgid);
			*lock = 0;
		}
		spin_unlock(&ab->spin);
		wake_up_interruptible(&ab->lockq);
		goto out;
	}

	if (cmd == AUNLOCK_WAKE) {
		spin_lock(&ab->spin);
		if (*lock == current->tgid) {
			printk(KERN_ERR "UNLOCK %d,%d\n", *lock, current->tgid);
			*lock = 0;
		}
		spin_unlock(&ab->spin);
		wake_up_interruptible(&ab->rwait);
		wake_up_interruptible(&ab->wwait);
		wake_up_interruptible(&ab->lockq);
		goto out;
	}
out:
	return 0;
}

/* when app exit (include coredump), this driver will delete
 * the file which create by this app */
int acridafs_file_flush(struct file *file, fl_owner_t id)
{
	struct inode *node;
	struct dentry *parent;
	struct page *page;
	struct acrida_bdev *ab = NULL;
	size_t *buff = NULL;
	unsigned long pid = 0;
	size_t *lock = NULL;
	int should_wake = 0;

	down(&inode_mutex);

	if (!file)
		goto out;

	atomic_long_inc(&file->f_count);

	if (!file->f_dentry) {
		atomic_long_dec(&file->f_count);
		goto out;
	}

	dget(file->f_dentry);

	node = file->f_dentry->d_inode;
	if (node) {
		atomic_inc(&node->i_count);

		printk(KERN_ERR "mapping:%x\n", file->f_mapping);
		if (file->f_mapping && file->f_mapping->page_tree.rnode) {
			spin_lock(&file->f_mapping->tree_lock);
			page = radix_tree_lookup(&file->f_mapping->page_tree,
					0);
			if (!page)
				goto page_out;
			printk(KERN_ERR "page:%x\n", page);
			buff = page_address(page);
			if (!buff)
				goto page_out;
			printk(KERN_ERR "buff:%x\n", buff);
			pid = buff[4];
			lock = buff + 6;

			ab = (struct acrida_bdev *)(node->i_bdev);
			if (!ab)
				goto page_out;
			printk(KERN_ERR "ab ok %d, %d\n", *lock, current->tgid);
			spin_lock(&ab->spin);
			if (*lock == current->tgid) {
				printk(KERN_ERR "flush lock %d\n", *lock);
				*lock = 0;
				should_wake = 1;
			}
			spin_unlock(&ab->spin);

			if (should_wake)
				wake_up_interruptible(&ab->lockq);
page_out:
			spin_unlock(&file->f_mapping->tree_lock);
		}

		printk(KERN_ERR "current:%u, owner:%lu, i_nlink:%lu\n",
				current->tgid, pid, node->i_nlink);

		if (current->tgid == pid && node->i_nlink &&
				!IS_ERR(file->f_dentry)) {
			parent = file->f_dentry->d_parent;
			if (parent->d_inode) {
				g_in_flush = 1;
				vfs_unlink(parent->d_inode, file->f_dentry);
				g_in_flush = 0;
			}
		}
		iput(node);
	}

	dput(file->f_dentry);
	atomic_long_dec(&file->f_count);
out:
	up(&inode_mutex);

	write_lock(&g_alive_lock);
	kuafu_info_clear_pid_app(current->tgid);
	write_unlock(&g_alive_lock);

	return 0;
}

int acridafs_file_open(struct inode *inode, struct file* file)
{
	struct acrida_bdev *ab;
	struct page *page;

	if (inode->i_bdev) {
		ab = (struct acrida_bdev *)(inode->i_bdev);
		ab->nr_open++;
		if (!ab->buff) {
			page = find_get_page(file->f_mapping, 0);
			if (page)
				ab->buff = page_address(page);
		}
		printk(KERN_ERR "open:%d\n", ab->nr_open);
	}
	return 0;
}

int acridafs_file_release(struct inode *inode, struct file *file)
{
	struct acrida_bdev *ab;

	if (inode->i_bdev) {
		printk(KERN_ERR "release in file: kfree bdev\n");
		ab = (struct acrida_bdev *)(inode->i_bdev);
		wake_up_interruptible(&ab->rwait);
		wake_up_interruptible(&ab->wwait);
		ab->nr_open--;
		printk(KERN_ERR "release:%d\n", ab->nr_open);

		if (!(ab->nr_open)) {
			kfree(ab);
			inode->i_bdev = NULL;
		}
	}
	return 0;
}

int acridafs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct acrida_bdev *ab = NULL;
	int res = 0;

	if (!g_in_flush)
		down(&inode_mutex);

	if (dentry && dentry->d_inode &&
				dentry->d_inode->i_bdev) {
		printk(KERN_ERR "release in unlink: kfree bdev\n");
		ab = (struct acrida_bdev *)(dentry->d_inode->i_bdev);
		wake_up_interruptible(&ab->rwait);
		wake_up_interruptible(&ab->wwait);
	}

	if (dentry && dentry->d_inode &&
				dentry->d_inode->i_nlink)
		res = simple_unlink(dir, dentry);

	if (!g_in_flush)
		up(&inode_mutex);

	return res;
}

int set_page_dirty_no_writeback(struct page *page)
{
	if (!PageDirty(page))
		SetPageDirty(page);
	return 0;
}

static struct address_space_operations acridafs_aops = {
	.readpage       = simple_readpage,
	.write_begin    = simple_write_begin,
	.write_end      = simple_write_end,
	.set_page_dirty = set_page_dirty_no_writeback,
};

const struct file_operations acridafs_file_operations = {
	.read           = do_sync_read,
	.aio_read       = generic_file_aio_read,
	.write          = do_sync_write,
	.aio_write      = generic_file_aio_write,
	.poll           = acridafs_file_poll,
	.unlocked_ioctl = acridafs_file_ioctl,
	.mmap           = generic_file_mmap,
	.open           = acridafs_file_open,
	.flush          = acridafs_file_flush,
	.release        = acridafs_file_release,
	.fsync          = simple_sync_file,
	.splice_read    = generic_file_splice_read,
	.splice_write   = generic_file_splice_write,
	.llseek         = generic_file_llseek,
};

static struct inode_operations acridafs_file_inode_operations = {
	.getattr        = simple_getattr,
};

static struct inode_operations acridafs_dir_inode_operations = {
	.create         = acridafs_create,
	.lookup         = simple_lookup,
	.link           = simple_link,
	.unlink         = acridafs_unlink,
	.symlink        = acridafs_symlink,
	.mkdir          = acridafs_mkdir,
	.rmdir          = simple_rmdir,
	.mknod          = acridafs_mknod,
	.rename         = simple_rename,
};

static struct super_operations acridafs_ops = {
	.statfs  = simple_statfs,
	.drop_inode = generic_delete_inode,
};

static int acridafs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;
	struct dentry *root;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = RAMFS_MAGIC;
	sb->s_op = &acridafs_ops;
	inode = acridafs_get_inode(sb, S_IFDIR | 0755, 0);
	if (!inode)
		return -ENOMEM;

	root = d_alloc_root(inode);
	if (!root) {
		iput(inode);
		return -ENOMEM;
	}
	sb->s_root = root;
	g_root_dentry = root;
	return 0;
}

int acridafs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_nodev(fs_type, flags, data, acridafs_fill_super, mnt);
}

static int rootfs_get_sb(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_nodev(fs_type, flags|MS_NOUSER, data,
				acridafs_fill_super, mnt);
}

static struct file_system_type acridafs_fs_type = {
	.owner          = THIS_MODULE,
	.name           = "acridafs",
	.get_sb         = acridafs_get_sb,
	.kill_sb        = kill_litter_super,
};

static struct file_system_type rootfs_fs_type = {
	.name           = "rootfs",
	.get_sb         = rootfs_get_sb,
	.kill_sb        = kill_litter_super,
};

const struct file_operations acrida_center_fops = {
	.owner          = THIS_MODULE,
	.poll           = acrida_center_poll,
	.unlocked_ioctl = acrida_center_ioctl,
	.open           = acrida_center_open,
	.release        = acrida_center_release,
};

int acrida_center_release(struct inode *inode, struct file *file)
{
	if (file && file->private_data) {
		kfree(file->private_data);
		file->private_data = NULL;
	}
	return 0;
}

int acrida_center_open(struct inode *inode, struct file *file)
{
	if (file) {
		atomic_long_inc(&file->f_count);
		file->private_data = kmalloc(sizeof(int), GFP_KERNEL);
		*(int *)(file->private_data) = 0;
		atomic_long_dec(&file->f_count);
	}
	return 0;
}

/* kuafu daemon use epoll on /tmp/rfs/ to know that
 * new apps join now */
unsigned int acrida_center_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(file, &ac_dev.wait, wait);

	if (file) {
		int old_file_count = *(int *)(file->private_data);
		if (old_file_count > g_file_count)
				mask |= POLLOUT;
		else if (old_file_count < g_file_count)
				mask |= POLLIN;
		*(int *)(file->private_data) = g_file_count;
	}
	return mask;
}

/* when apps create share-memory, kuafu daemon will
 * know it by epoll*/
long acrida_center_ioctl(struct file *file, unsigned int cmd,
		unsigned long data)
{
	if (cmd == ADD_FILE) {
		g_file_count++;
		wake_up_interruptible(&ac_dev.wait);
	}
	return 0;
}

const struct file_operations kuafu_alive_fops = {
	.owner  = THIS_MODULE,
	.read   = kuafu_alive_read,
	.write  = kuafu_alive_write,
	.flush  = kuafu_alive_flush,
};

/* user will write information like:
 * "groupname:apple_group"
 * "groupname:ban_group"
 * "msgsize:1048576" */
ssize_t kuafu_alive_write(struct file *file, const char __user *user,
		size_t count, loff_t *off)
{
	struct rlimit *old_rlim = NULL;
	int i = 0;
	int res;
	char *buff = NULL;
	char *pos = NULL;

	if (count < 0 || count >= 1024)
		return 0;

	buff = kmalloc(count, GFP_KERNEL);

	if (!buff)
		return ENOMEM;

	res = copy_from_user(buff, user, count);

	write_lock(&g_alive_lock);

	/* clear the current kfc information */
	if (count == 5 && !strncmp(buff, "clear", 5)) {
		kuafu_info_clear_group(current->tgid);
		kuafu_info_clear_msgsize(current->tgid);
		goto err;
	}

	for (; i < count; i++) {
		pos = buff + i;
		if (*pos == ':')
				break;
	}

	/* no ':' in user string */
	if (i >= count) {
		count = 0;
		goto err;
	}

	if (pos - buff == strlen("groupname") &&
				!strncmp(buff, "groupname", 9)) {
		count = kuafu_info_store_group(current->tgid, pos+1, count-10);

		if (count < 0)
				goto err;
		/*
		* set RLIMIT_NOFILE of the kfc daemon
		* only kfc daemon will write "groupname"
		*/
		old_rlim = current->signal->rlim + RLIMIT_NOFILE;
		if (old_rlim) {
				task_lock(current->group_leader);
				old_rlim->rlim_cur = MAX_NOFILE;
				old_rlim->rlim_max = MAX_NOFILE;
				task_unlock(current->group_leader);
		}
	} else if (pos - buff == strlen("msgsize") &&
				!strncmp(buff, "msgsize", 7))
		kuafu_info_store_msgsize(current->tgid, *(int *)(pos+1));
	else if (pos - buff == strlen("app") &&
				!strncmp(buff, "app", 3))
		kuafu_info_store_app(current->tgid, pos+1, count-4);
	else if (pos - buff == strlen("clearapp") &&
				!strncmp(buff, "clearapp", 8))
		kuafu_info_remove_app(current->tgid, pos+1, count-9);
err:
	write_unlock(&g_alive_lock);
	kfree(buff);
	return count;
}

ssize_t kuafu_alive_read(struct file *file, char __user *user,
		size_t count, loff_t *off)
{
	int len;
	int min;
	int res;
	char *buff = vmalloc(BUFFER_SIZE);
	if (!buff)
		return 0;

	read_lock(&g_alive_lock);
	kuafu_info_traverse(buff, &len);
	read_unlock(&g_alive_lock);

	if (*off >= len) {
		min = 0;
		goto ret;
	}

	if (count + *off > len)
		min = len - *off;
	else
		min = count;

	res = copy_to_user(user, buff + *off, min);

	*off += min;
ret:
	vfree(buff);
	return min;
}

/* when kuafu daemon exit (include coredump), this will set flag
 * on share-memory, apps will know this flag */
int kuafu_alive_flush(struct file *file, fl_owner_t id)
{
	struct list_head *next;
	struct dentry *dentry;
	struct page *page;
	unsigned long *buff;
	struct acrida_bdev *ab;
	const unsigned char *pos = NULL;
	const unsigned char *begin = NULL;
	const unsigned char *end = NULL;
	int len = 0;
	int res = 0;
	int i = 0;

	read_lock(&g_alive_lock);
	res = kuafu_info_exists_pid(current->tgid);
	read_unlock(&g_alive_lock);

	printk(KERN_ERR "res:%d,%d\n", res, current->tgid);

	if (!res)
		return 0;

	down(&inode_mutex);
	spin_lock(&dcache_lock);

	next = g_root_dentry->d_subdirs.next;

	while (next && next != &g_root_dentry->d_subdirs) {
		dentry = list_entry(next, struct dentry, d_u.d_child);

		begin = dentry->d_name.name;
		end = begin + dentry->d_name.len - 1;
		for (i = 0; i < 4; ++i) {
			while (end > begin && *end != '_')
				--end;
			if (end > begin && i != 3)
				--end;
			else
				break;
		}
		if (end <= begin || i != 3)
			continue;

		pos = end;
		len = pos - begin;

		read_lock(&g_alive_lock);
		res = kuafu_info_exists_group(current->tgid, begin, len);
		read_unlock(&g_alive_lock);

		if (dentry->d_inode && dentry->d_inode->i_nlink &&
				dentry->d_inode->i_mapping && pos && res) {

			page = find_get_page(dentry->d_inode->i_mapping, 0);
			if (!page)
				goto page_out;
			buff = page_address(page);
			if (!buff)
				goto page_out;
			buff[5] = KFC_FAIL;
			ab = (struct acrida_bdev *)(dentry->d_inode->i_bdev);
			if (ab) {
				wake_up_interruptible(&ab->rwait);
				wake_up_interruptible(&ab->wwait);
			}
			printk(KERN_ERR "center flush:%d\n", buff[4]);
		}
page_out:
		next = next->next;
	}

	spin_unlock(&dcache_lock);

	up(&inode_mutex);

	write_lock(&g_alive_lock);
	kuafu_info_remove_pid(current->tgid);
	write_unlock(&g_alive_lock);

	return 0;
}

static int __init init_acridafs_fs(void)
{
	int res = init_kuafu_info();
	if (res)
		return res;

	/* acrida_center device used to notify ADD_FILE */
	ac_dev.misc.minor = MISC_DYNAMIC_MINOR;
	ac_dev.misc.name = "acrida_center";
	ac_dev.misc.fops = &acrida_center_fops;
	init_waitqueue_head(&ac_dev.wait);
	misc_register(&ac_dev.misc);

	/* kuafu_alive device used to check kuafu daemon */
	ka_dev.minor = MISC_DYNAMIC_MINOR;
	ka_dev.name = "kuafu_alive";
	ka_dev.fops = &kuafu_alive_fops;
	misc_register(&ka_dev);

	return register_filesystem(&acridafs_fs_type);
}

static void __exit exit_acridafs_fs(void)
{
	exit_kuafu_info();

	unregister_filesystem(&acridafs_fs_type);
	misc_deregister(&ac_dev.misc);
	misc_deregister(&ka_dev);
}

module_init(init_acridafs_fs)
module_exit(exit_acridafs_fs)

int __init init_rootfs(void)
{
	return register_filesystem(&rootfs_fs_type);
}

MODULE_LICENSE("GPL");
