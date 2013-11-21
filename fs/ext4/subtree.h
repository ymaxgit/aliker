#ifdef CONFIG_EXT4_FS_SUBTREE

#include <linux/xattr.h>
#include <linux/fs.h>

extern int ext4_subtree_xattr_read(struct inode *inode, unsigned int *subtree);
extern int ext4_subtree_xattr_write(handle_t *handle, struct inode *inode,
				    unsigned int subtree, int xflags);
extern int ext4_subtree_init(handle_t *handle, struct inode *inode);
extern int ext4_subtree_read(struct inode *inode);
extern int ext4_subtree_change(struct inode *inode, unsigned int new);
static inline u32 ext4_get_subtree(struct inode *inode)
{
	return EXT4_I(inode)->i_subtree;
}
static inline void ext4_set_subtree(struct inode *inode, u32 id)
{
	EXT4_I(inode)->i_subtree = id;
}
#else
#define ext4_set_subtree(inode, id) do {} while (0)
static inline u32 ext4_get_subtree(struct inode *inode)
{
	return 0;
}
static inline int ext4_subtree_xattr_read(struct inode *inode, unsigned int *id)
{
	return -ENOTSUPP;
}
static inline int ext4_subtree_init(handle_t *handle, struct inode *inode)
{
	return 0;
}
static inline int ext4_subtree_read(struct inode *inode)
{
	return 0;
}
static inline int ext4_subtree_changle(struct inode *inode, unsigned int id)
{
	return -ENOTSUPP;
}
#endif /* CONFIG_EXT4_FS_SUBTREE */
