/*
 * Copyright (c) 2011 Taobao.
 * Written by Tao Ma <boyu.mt@taobao.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "ext4_jbd2.h"
#include "ext4.h"
#include "xattr.h"
#include <linux/fiemap.h>

#define EXT4_XATTR_SYSTEM_DATA_NAME	"data"
#define EXT4_MIN_INLINE_DATA_SIZE	((sizeof(__le32) * EXT4_N_BLOCKS))

int ext4_get_inline_size(struct inode *inode)
{
	if (EXT4_I(inode)->i_inline_off)
		return EXT4_I(inode)->i_inline_size;

	return 0;
}

static int get_max_inline_xattr_value_size(struct inode *inode,
					   struct ext4_iloc *iloc)
{
	struct ext4_xattr_ibody_header *header;
	struct ext4_xattr_entry *entry;
	struct ext4_inode *raw_inode;
	int free, min_offs;

	if (!ext4_test_inode_state(inode, EXT4_STATE_XATTR))
		return EXT4_XATTR_SIZE(EXT4_SB(inode->i_sb)->s_inode_size -
			EXT4_GOOD_OLD_INODE_SIZE -
			EXT4_I(inode)->i_extra_isize -
			sizeof(struct ext4_xattr_ibody_header) -
			EXT4_XATTR_LEN(strlen(EXT4_XATTR_SYSTEM_DATA_NAME)) -
			EXT4_XATTR_ROUND - sizeof(__u32));

	down_read(&EXT4_I(inode)->xattr_sem);
	raw_inode = ext4_raw_inode(iloc);
	header = IHDR(inode, raw_inode);
	entry = IFIRST(header);
	min_offs = EXT4_SB(inode->i_sb)->s_inode_size -
			EXT4_GOOD_OLD_INODE_SIZE -
			EXT4_I(inode)->i_extra_isize -
			sizeof(struct ext4_xattr_ibody_header);

	/* Compute min_offs. */
	for (; !IS_LAST_ENTRY(entry); entry = EXT4_XATTR_NEXT(entry)) {
		if (!entry->e_value_block && entry->e_value_size) {
			size_t offs = le16_to_cpu(entry->e_value_offs);
			if (offs < min_offs)
				min_offs = offs;
		}
	}
	free = min_offs -
		((void *)entry - (void *)IFIRST(header)) - sizeof(__u32);

	if (EXT4_I(inode)->i_inline_off) {
		entry = (struct ext4_xattr_entry *)
			((void *)raw_inode + EXT4_I(inode)->i_inline_off);

		free += le32_to_cpu(entry->e_value_size);
		goto out;
	}

	free -= EXT4_XATTR_LEN(strlen(EXT4_XATTR_SYSTEM_DATA_NAME));

	if (free > EXT4_XATTR_ROUND)
		free = EXT4_XATTR_SIZE(free - EXT4_XATTR_ROUND);
	else
		free = 0;

out:
	up_read(&EXT4_I(inode)->xattr_sem);
	return free;
}

/*
 * Get the maximum size we now can store in an inode.
 * If we can't find the space for a xattr entry, don't use the space
 * of the extents since we have no space to indicate the inline data.
 */
int ext4_get_max_inline_size(struct inode *inode)
{
	int error, max_inline_size;
	struct ext4_iloc iloc;

	if (EXT4_I(inode)->i_extra_isize == 0)
		return 0;

	error = ext4_get_inode_loc(inode, &iloc);
	if (error) {
		ext4_error_inode(__func__, inode,
				 "can't get inode location %lu",
				 inode->i_ino);
		return 0;
	}

	max_inline_size = get_max_inline_xattr_value_size(inode, &iloc);

	brelse(iloc.bh);

	if (!max_inline_size)
		return 0;

	return max_inline_size + EXT4_MIN_INLINE_DATA_SIZE;
}

int ext4_has_inline_data(struct inode *inode)
{
	return ext4_test_inode_flag(inode, EXT4_INODE_INLINE_DATA) &&
	       EXT4_I(inode)->i_inline_off;
}

int ext4_find_inline_data(struct inode *inode)
{
	struct ext4_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ext4_xattr_info i = {
		.name_index = EXT4_XATTR_INDEX_SYSTEM_DATA,
		.name = EXT4_XATTR_SYSTEM_DATA_NAME,
	};
	int error;

	if (EXT4_I(inode)->i_extra_isize == 0)
		return 0;

	error = ext4_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ext4_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	if (!is.s.not_found) {
		EXT4_I(inode)->i_inline_off = (u16)((void *)is.s.here -
					(void *)ext4_raw_inode(&is.iloc));
		EXT4_I(inode)->i_inline_size = EXT4_MIN_INLINE_DATA_SIZE +
				le32_to_cpu(is.s.here->e_value_size);
		ext4_set_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
	}
out:
	brelse(is.iloc.bh);
	return error;
}

static int ext4_read_inline_data(struct inode *inode, void *buffer, unsigned int len,
				 struct ext4_iloc *iloc)
{
	struct ext4_xattr_entry *entry;
	struct ext4_xattr_ibody_header *header;
	int cp_len = 0;
	struct ext4_inode *raw_inode;

	if (!len)
		return 0;

	BUG_ON(len > EXT4_I(inode)->i_inline_size);

	cp_len = len < EXT4_MIN_INLINE_DATA_SIZE ?
			len : EXT4_MIN_INLINE_DATA_SIZE;

	raw_inode = ext4_raw_inode(iloc);
	memcpy(buffer, (void *)(raw_inode->i_block), cp_len);

	len -= cp_len;
	buffer += cp_len;

	if (!len)
		goto out;

	header = IHDR(inode, raw_inode);
	entry = (struct ext4_xattr_entry *)((void *)raw_inode +
					    EXT4_I(inode)->i_inline_off);

	len = min_t(unsigned int, len,
			(unsigned int)le32_to_cpu(entry->e_value_size));

	memcpy(buffer,
	       (void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs), len);
	cp_len += len;

out:
	return cp_len;
}

/*
 * write the buffer to the inline inode.
 * If 'create' is set, we don't need to do the extra copy in the xattr
 * value since it is already handled by ext4_xattr_ibody_inline_set. That saves
 * us one memcpy.
 */
void ext4_write_inline_data(struct inode *inode, struct ext4_iloc *iloc,
			    void *buffer, loff_t pos, unsigned int len)
{
	struct ext4_xattr_entry *entry;
	struct ext4_xattr_ibody_header *header;
	struct ext4_inode *raw_inode;
	int cp_len = 0;

	BUG_ON(!EXT4_I(inode)->i_inline_off);
	BUG_ON(pos + len > EXT4_I(inode)->i_inline_size);

	raw_inode = ext4_raw_inode(iloc);
	buffer += pos;

	if (pos < EXT4_MIN_INLINE_DATA_SIZE) {
		cp_len = pos + len > EXT4_MIN_INLINE_DATA_SIZE ?
			 EXT4_MIN_INLINE_DATA_SIZE - pos : len;
		memcpy((void *)raw_inode->i_block + pos, buffer, cp_len);

		len -= cp_len;
		buffer += cp_len;
		pos += cp_len;
	}

	if (!len)
		return;

	pos -= EXT4_MIN_INLINE_DATA_SIZE;
	header = IHDR(inode, raw_inode);
	entry = (struct ext4_xattr_entry *)((void *)raw_inode +
					    EXT4_I(inode)->i_inline_off);

	memcpy((void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs) + pos,
	       buffer, len);
}

static int ext4_create_inline_data(handle_t *handle,
				   struct inode *inode, unsigned len)
{
	int error;
	void *value = NULL;
	struct ext4_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ext4_xattr_info i = {
		.name_index = EXT4_XATTR_INDEX_SYSTEM_DATA,
		.name = EXT4_XATTR_SYSTEM_DATA_NAME,
	};

	error = ext4_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ext4_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto out;

	if (len > EXT4_MIN_INLINE_DATA_SIZE) {
		value = (void *)empty_zero_page;
		len -= EXT4_MIN_INLINE_DATA_SIZE;
	} else {
		value = "";
		len = 0;
	}

	/* Insert the the xttr entry. */
	i.value = value;
	i.value_len = len;

	error = ext4_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	BUG_ON(!is.s.not_found);

	error = ext4_xattr_ibody_inline_set(handle, inode, &i, &is);
	if (error) {
		if (error == -ENOSPC)
			ext4_clear_inode_state(inode,
					       EXT4_STATE_MAY_INLINE_DATA);
		goto out;
	}

	memset((void *)ext4_raw_inode(&is.iloc)->i_block,
		0, EXT4_MIN_INLINE_DATA_SIZE);

	EXT4_I(inode)->i_inline_off = (u16)((void *)is.s.here -
				      (void *)ext4_raw_inode(&is.iloc));
	EXT4_I(inode)->i_inline_size = len + EXT4_MIN_INLINE_DATA_SIZE;
	ext4_clear_inode_flag(inode, EXT4_INODE_EXTENTS);
	ext4_set_inode_flag(inode, EXT4_INODE_INLINE_DATA);
	get_bh(is.iloc.bh);
	error = ext4_mark_iloc_dirty(handle, inode, &is.iloc);

out:
	brelse(is.iloc.bh);
	return error;
}

static int ext4_update_inline_data(handle_t *handle, struct inode *inode,
				   unsigned int len)
{
	int error;
	void *value = NULL;
	struct ext4_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ext4_xattr_info i = {
		.name_index = EXT4_XATTR_INDEX_SYSTEM_DATA,
		.name = EXT4_XATTR_SYSTEM_DATA_NAME,
	};

	/* If the old space is ok, write the data directly. */
	if (len <= EXT4_I(inode)->i_inline_size)
		return 0;

	error = ext4_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ext4_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	BUG_ON(is.s.not_found);

	len -= EXT4_MIN_INLINE_DATA_SIZE;
	value = kzalloc(len, GFP_NOFS);
	if (!value)
		goto out;

	error = ext4_xattr_ibody_get(inode, i.name_index, i.name,
				     value, len);
	if (error == -ENODATA)
		goto out;

	error = ext4_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto out;

	/* Update the xttr entry. */
	i.value = value;
	i.value_len = len;

	error = ext4_xattr_ibody_inline_set(handle, inode, &i, &is);
	if (error)
		goto out;

	EXT4_I(inode)->i_inline_off = (u16)((void *)is.s.here -
				      (void *)ext4_raw_inode(&is.iloc));
	EXT4_I(inode)->i_inline_size = EXT4_MIN_INLINE_DATA_SIZE +
				le32_to_cpu(is.s.here->e_value_size);
	ext4_set_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
	get_bh(is.iloc.bh);
	error = ext4_mark_iloc_dirty(handle, inode, &is.iloc);

out:
	kfree(value);
	brelse(is.iloc.bh);
	return error;
}

int ext4_prepare_inline_data(handle_t *handle, struct inode *inode,
			     unsigned int len)
{
	int ret, size;
	struct ext4_inode_info *ei = EXT4_I(inode);

	if (!ext4_test_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA))
		return -ENOSPC;

	size = ext4_get_max_inline_size(inode);
	if (size < len)
		return -ENOSPC;

	down_write(&EXT4_I(inode)->xattr_sem);

	if (ei->i_inline_off)
		ret = ext4_update_inline_data(handle, inode, len);
	else
		ret = ext4_create_inline_data(handle, inode, len);

	up_write(&EXT4_I(inode)->xattr_sem);

	return ret;
}

static int ext4_destroy_inline_data_nolock(handle_t *handle, struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_xattr_ibody_find is = {
		.s = { .not_found = 0, },
	};
	struct ext4_xattr_info i = {
		.name_index = EXT4_XATTR_INDEX_SYSTEM_DATA,
		.name = EXT4_XATTR_SYSTEM_DATA_NAME,
		.value = NULL,
		.value_len = 0,
	};
	int error;

	if (!ei->i_inline_off)
		return 0;

	error = ext4_get_inode_loc(inode, &is.iloc);
	if (error)
		return error;

	error = ext4_xattr_ibody_find(inode, &i, &is);
	if (error)
		goto out;

	error = ext4_journal_get_write_access(handle, is.iloc.bh);
	if (error)
		goto out;

	error = ext4_xattr_ibody_inline_set(handle, inode, &i, &is);
	if (error)
		goto out;

	memset((void *)ext4_raw_inode(&is.iloc)->i_block,
		0, EXT4_MIN_INLINE_DATA_SIZE);

	if (EXT4_HAS_INCOMPAT_FEATURE(inode->i_sb,
				      EXT4_FEATURE_INCOMPAT_EXTENTS)) {
		if (S_ISDIR(inode->i_mode) ||
		    S_ISREG(inode->i_mode) || S_ISLNK(inode->i_mode)) {
			ext4_set_inode_flag(inode, EXT4_INODE_EXTENTS);
			ext4_ext_tree_init(handle, inode);
		}
	}
	ext4_clear_inode_flag(inode, EXT4_INODE_INLINE_DATA);

	get_bh(is.iloc.bh);
	error = ext4_mark_iloc_dirty(handle, inode, &is.iloc);

	EXT4_I(inode)->i_inline_off = 0;
	EXT4_I(inode)->i_inline_size = 0;
	ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
out:
	brelse(is.iloc.bh);
	if (error == -ENODATA)
		error = 0;
	return error;
}

static int ext4_read_inline_page(struct inode *inode, struct page *page)
{
	void *kaddr;
	int ret = 0;
	size_t len;
	struct ext4_iloc iloc;

	BUG_ON(!PageLocked(page));
	BUG_ON(!ext4_has_inline_data(inode));
	BUG_ON(page->index);

	if (!EXT4_I(inode)->i_inline_off) {
		ext4_warning(inode->i_sb, "inode %lu doesn't have inline data.",
			     inode->i_ino);
		goto out;
	}

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		goto out;

	len = min_t(size_t, ext4_get_inline_size(inode), i_size_read(inode));
	kaddr = kmap_atomic(page, KM_USER0);
	ret = ext4_read_inline_data(inode, kaddr, len, &iloc);
	flush_dcache_page(page);
	kunmap_atomic(kaddr, KM_USER0);
	zero_user_segment(page, len, PAGE_CACHE_SIZE);
	SetPageUptodate(page);
	brelse(iloc.bh);

out:
	return ret;
}

int ext4_readpage_inline(struct inode *inode, struct page *page)
{
	int ret = 0;

	down_read(&EXT4_I(inode)->xattr_sem);
	if (!ext4_has_inline_data(inode)) {
		up_read(&EXT4_I(inode)->xattr_sem);
		return -EAGAIN;
	}

	/*
	 * Current inline data can only exist in the 1st page,
	 * So for all the other pages, just set them uptodate.
	 */
	if (!page->index)
		ret = ext4_read_inline_page(inode, page);
	else if (!PageUptodate(page)) {
		zero_user_segment(page, 0, PAGE_CACHE_SIZE);
		SetPageUptodate(page);
	}

	up_read(&EXT4_I(inode)->xattr_sem);

	unlock_page(page);
	return ret >= 0 ? 0 : ret;
}

static int ext4_convert_inline_data_to_extent(struct address_space *mapping,
					      struct inode *inode,
					      unsigned flags)
{
	int ret, needed_blocks;
	handle_t *handle = NULL;
	int retries = 0, sem_held = 0;
	struct page *page = NULL;
	unsigned from, to;
	struct ext4_iloc iloc;

	if (!ext4_has_inline_data(inode)) {
		/*
		 * clear the flag so that no new write
		 * will trap here again.
		 */
		ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
		return 0;
	}

	needed_blocks = ext4_writepage_trans_blocks(inode);

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

retry:
	handle = ext4_journal_start(inode, needed_blocks);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		handle = NULL;
		goto out;
	}

	/* We cannot recurse into the filesystem as the transaction is already
	 * started */
	flags |= AOP_FLAG_NOFS;

	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	down_write(&EXT4_I(inode)->xattr_sem);
	sem_held = 1;
	/* If some one has already done this for us, just exit. */
	if (!ext4_has_inline_data(inode)) {
		ret = 0;
		goto out;
	}

	from = 0;
	to = ext4_get_inline_size(inode);
	if (!PageUptodate(page)) {
		ret = ext4_read_inline_page(inode, page);
		if (ret < 0)
			goto out;
	}

	ret = ext4_destroy_inline_data_nolock(handle, inode);
	if (ret)
		goto out;

	ret = block_prepare_write(page, from & (PAGE_CACHE_SIZE - 1), to, ext4_get_block);
	if (!ret && ext4_should_journal_data(inode)) {
		ret = walk_page_buffers(handle, page_buffers(page),
				from, to, NULL, do_journal_get_write_access);
	}

	if (ret) {
		unlock_page(page);
		page_cache_release(page);
		ext4_orphan_add(handle, inode);
		up_write(&EXT4_I(inode)->xattr_sem);
		sem_held = 0;
		ext4_journal_stop(handle);
		handle = NULL;
		ext4_truncate_failed_write(inode);
		/*
		 * If truncate failed early the inode might
		 * still be on the orphan list; we need to
		 * make sure the inode is removed from the
		 * orphan list in that case.
		 */
		if (inode->i_nlink)
			ext4_orphan_del(NULL, inode);
	}

	if (ret == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
		goto retry;

	block_commit_write(page, from, to);
out:
	if (page) {
		unlock_page(page);
		page_cache_release(page);
	}
	if (sem_held)
		up_write(&EXT4_I(inode)->xattr_sem);
	if (handle)
		ext4_journal_stop(handle);
	brelse(iloc.bh);
	return ret;
}

/*
 * Try to write data in the inode.
 * If the inode has inline data, check whether the new write can be
 * in the inode also. If not, create the page the handle, move the data
 * to the page make it update and let the later codes create extent for it.
 */
int ext4_try_to_write_inline_data(struct address_space *mapping,
				  struct inode *inode,
				  loff_t pos, unsigned len,
				  unsigned flags,
				  struct page **pagep)
{
	int ret;
	handle_t *handle;
	struct page *page;
	struct ext4_iloc iloc;

	if (pos + len > ext4_get_max_inline_size(inode))
		goto convert;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	/*
	 * The possible write could happen in the inode,
	 * so try to reserve the space in inode first.
	 */
	handle = ext4_journal_start(inode, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		handle = NULL;
		goto out;
	}

	ret = ext4_prepare_inline_data(handle, inode, pos + len);
	if (ret && ret != -ENOSPC)
		goto out;

	/* We don't have space in inline inode, so convert it to extent. */
	if (ret == -ENOSPC) {
		ext4_journal_stop(handle);
		brelse(iloc.bh);
		goto convert;
	}

	flags |= AOP_FLAG_NOFS;

	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	*pagep = page;
	down_read(&EXT4_I(inode)->xattr_sem);
	if (!ext4_has_inline_data(inode)) {
		ret = 0;
		unlock_page(page);
		page_cache_release(page);
		goto out_up_read;
	}

	if (!PageUptodate(page)) {
		ret = ext4_read_inline_page(inode, page);
		if (ret < 0)
			goto out_up_read;
	}

	ret = 1;
	handle = NULL;
out_up_read:
	up_read(&EXT4_I(inode)->xattr_sem);
out:
	if (handle)
		ext4_journal_stop(handle);
	brelse(iloc.bh);
	return ret;
convert:
	return ext4_convert_inline_data_to_extent(mapping,
						  inode, flags);
}

int ext4_write_inline_data_end(struct inode *inode, loff_t pos, unsigned len,
			       unsigned copied, struct page *page)
{
	int ret;
	void *kaddr;
	struct ext4_iloc iloc;

	if (unlikely(copied < len)) {
		if (!PageUptodate(page)) {
			copied = 0;
			goto out;
		}
	}

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret) {
		ext4_std_error(inode->i_sb, ret);
		copied = 0;
		goto out;
	}

	down_write(&EXT4_I(inode)->xattr_sem);
	BUG_ON(!ext4_has_inline_data(inode));

	kaddr = kmap_atomic(page, KM_USER0);
	ext4_write_inline_data(inode, &iloc, kaddr, pos, len);
	kunmap_atomic(kaddr, KM_USER0);
	SetPageUptodate(page);
	/* clear page dirty so that writepages wouldn't work for us. */
	ClearPageDirty(page);

	up_write(&EXT4_I(inode)->xattr_sem);
	brelse(iloc.bh);
out:
	return copied;
}

struct buffer_head *
ext4_journalled_write_inline_data(struct inode *inode,
				  unsigned len,
				  struct page *page)
{
	int ret;
	void *kaddr;
	struct ext4_iloc iloc;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret) {
		ext4_std_error(inode->i_sb, ret);
		return NULL;
	}

	down_write(&EXT4_I(inode)->xattr_sem);
	kaddr = kmap_atomic(page, KM_USER0);
	ext4_write_inline_data(inode, &iloc, kaddr, 0, len);
	kunmap_atomic(kaddr, KM_USER0);
	up_write(&EXT4_I(inode)->xattr_sem);

	return iloc.bh;
}

/*
 * Try to make the page cache and handle ready for the inline data case.
 * We can call this function in 2 cases:
 * 1. The inode is created and the first write exceeds inline size. We can
 *    clear the inode state safely.
 * 2. The inode has inline data, then we need to read the data, make it
 *    update and dirty so that ext4_da_writepages can handle it. We don't
 *    need to start the journal since the file's metatdata isn't changed now.
 */
static int ext4_da_convert_inline_data_to_extent(struct address_space *mapping,
						 struct inode *inode,
						 unsigned flags,
						 void **fsdata)
{
	int ret = 0, inline_size;
	struct page *page;

	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page)
		return -ENOMEM;

	down_read(&EXT4_I(inode)->xattr_sem);
	if (!ext4_has_inline_data(inode)) {
		ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
		goto out;
	}

	inline_size = ext4_get_inline_size(inode);

	if (!PageUptodate(page)) {
		ret = ext4_read_inline_page(inode, page);
		if (ret < 0)
			goto out;
	}

	ret = block_prepare_write(page, 0, inline_size,
				  ext4_da_get_block_prep);
	if (ret) {
		ext4_truncate_failed_write(inode);
		goto out;
	}

	SetPageDirty(page);
	SetPageUptodate(page);
	ext4_clear_inode_state(inode, EXT4_STATE_MAY_INLINE_DATA);
	*fsdata = (void *)CONVERT_INLINE_DATA;

out:
	up_read(&EXT4_I(inode)->xattr_sem);
	if (page) {
		unlock_page(page);
		page_cache_release(page);
	}
	return ret;
}

/*
 * Prepare the write for the inline data.
 * If the the data can be written into the inode, we just read
 * the page and make it uptodate, and start the journal.
 * Otherwise read the page, makes it dirty so that it can be
 * handle in writepages(the i_disksize update is left to the
 * normal ext4_da_write_end).
 */
int ext4_da_write_inline_data_begin(struct address_space *mapping,
				    struct inode *inode,
				    loff_t pos, unsigned len,
				    unsigned flags,
				    struct page **pagep,
				    void **fsdata)
{
	int ret, inline_size;
	handle_t *handle;
	struct page *page;
	struct ext4_iloc iloc;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	handle = ext4_journal_start(inode, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
		handle = NULL;
		goto out;
	}

	inline_size = ext4_get_max_inline_size(inode);

	ret = -ENOSPC;
	if (inline_size >= pos + len) {
		ret = ext4_prepare_inline_data(handle, inode, pos + len);
		if (ret && ret != -ENOSPC)
			goto out;
	}

	if (ret == -ENOSPC) {
		ret = ext4_da_convert_inline_data_to_extent(mapping,
							    inode,
							    flags,
							    fsdata);
		goto out;
	}

	/*
	 * We cannot recurse into the filesystem as the transaction
	 * is already started.
	 */
	flags |= AOP_FLAG_NOFS;

	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}

	down_read(&EXT4_I(inode)->xattr_sem);
	if (!ext4_has_inline_data(inode)) {
		ret = 0;
		goto out_release_page;
	}

	if (!PageUptodate(page)) {
		ret = ext4_read_inline_page(inode, page);
		if (ret < 0)
			goto out_release_page;
	}

	up_read(&EXT4_I(inode)->xattr_sem);
	*pagep = page;
	handle = NULL;
	brelse(iloc.bh);
	return 1;
out_release_page:
	up_read(&EXT4_I(inode)->xattr_sem);
	unlock_page(page);
	page_cache_release(page);
out:
	if (handle)
		ext4_journal_stop(handle);
	brelse(iloc.bh);
	return ret;
}

int ext4_da_write_inline_data_end(struct inode *inode, loff_t pos,
				  unsigned len, unsigned copied,
				  struct page *page)
{
	int i_size_changed = 0;

	copied = ext4_write_inline_data_end(inode, pos, len, copied, page);

	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold i_mutex.
	 *
	 * But it's important to update i_size while still holding page lock:
	 * page writeout could otherwise come in and zero beyond i_size.
	 */
	if (pos+copied > inode->i_size) {
		i_size_write(inode, pos+copied);
		i_size_changed = 1;
	}
	unlock_page(page);
	page_cache_release(page);

	/*
	 * Don't mark the inode dirty under page lock. First, it unnecessarily
	 * makes the holding time of page lock longer. Second, it forces lock
	 * ordering of page lock and transaction start for journaling
	 * filesystems.
	 */
	if (i_size_changed)
		mark_inode_dirty(inode);

	return copied;
}

#ifdef INLINE_DIR_DEBUG
void ext4_show_inline_dir(struct inode *dir, struct buffer_head *bh,
			  void *inline_start, int inline_size)
{
	int offset;
	unsigned short de_len;
	struct ext4_dir_entry_2 *de = inline_start;
	void *dlimit = inline_start + inline_size;

	trace_printk("inode %lu\n", dir->i_ino);
	offset = 0;
	while ((void *)de < dlimit) {
		de_len = ext4_rec_len_from_disk(de->rec_len, inline_size);
		trace_printk("de: offset %u reclen %u name %*.s "
			     "namelen %u ino %u\n",
			     offset, de_len, de->name_len, de->name,
			     de->name_len, le32_to_cpu(de->inode));
		if (ext4_check_dir_entry(dir, NULL, de, bh,
					 inline_start, inline_size, offset))
			BUG();

		offset += de_len;
		de = (struct ext4_dir_entry_2 *) ((char *) de + de_len);
	}
}
#else
#define ext4_show_inline_dir(dir, bh, inline_start, inline_size)
#endif

/*
 * Add a new entry into a inline dir.
 * It will return -ENOSPC if no space is available, and -EIO
 * and -EEXIST if directory entry already exists.
 */
static int ext4_add_dirent_to_inline(handle_t *handle,
				     struct dentry *dentry,
				     struct inode *inode,
				     struct ext4_iloc *iloc,
				     void *inline_start, int inline_size)
{
	struct inode	*dir = dentry->d_parent->d_inode;
	const char	*name = dentry->d_name.name;
	int		namelen = dentry->d_name.len;
	unsigned short	reclen;
	int		err;
	struct ext4_dir_entry_2 *de;

	reclen = EXT4_DIR_REC_LEN(namelen);
	err = ext4_find_dest_de(dir, inode, iloc->bh,
				inline_start, inline_size,
				name, namelen, &de);
	if (err)
		return err;

	err = ext4_journal_get_write_access(handle, iloc->bh);
	if (err)
		return err;
	ext4_insert_dentry(inode, de, inline_size, name, namelen);

	ext4_show_inline_dir(dir, iloc->bh, inline_start, inline_size);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 *
	 * XXX similarly, too many callers depend on
	 * ext4_new_inode() setting the times, but error
	 * recovery deletes the inode, so the worst that can
	 * happen is that the times are slightly out of date
	 * and/or different from the directory change time.
	 */
	dir->i_mtime = dir->i_ctime = ext4_current_time(dir);
	ext4_update_dx_flag(dir);
	dir->i_version++;
	ext4_mark_inode_dirty(handle, dir);
	return 1;
}

void* ext4_get_inline_xattr_pos(struct inode *inode, struct ext4_iloc *iloc)
{
	struct ext4_xattr_entry *entry;
	struct ext4_xattr_ibody_header *header;

	BUG_ON(!EXT4_I(inode)->i_inline_off);

	header = IHDR(inode, ext4_raw_inode(iloc));
	entry = (struct ext4_xattr_entry *)((void *)ext4_raw_inode(iloc) +
					    EXT4_I(inode)->i_inline_off);

	return (void *)IFIRST(header) + le16_to_cpu(entry->e_value_offs);
}

/* Set the final de to cover the whole block. */
static void ext4_update_final_de(void *de_buf, int old_size, int new_size)
{
	struct ext4_dir_entry_2 *de, *prev_de;
	void *limit;
	int de_len;

	de = (struct ext4_dir_entry_2 *)de_buf;
	if (old_size) {
		limit = de_buf + old_size;
		do {
			prev_de = de;
			de_len = ext4_rec_len_from_disk(de->rec_len, old_size);
			de_buf += de_len;
			de = (struct ext4_dir_entry_2 *)de_buf;
		} while (de_buf < limit);

		prev_de->rec_len = ext4_rec_len_to_disk(de_len + new_size -
							old_size, new_size);
	} else {
		/* this is just created, so create an empty entry. */
		de->inode = 0;
		de->rec_len = ext4_rec_len_to_disk(new_size, new_size);
	}
}

static int ext4_update_inline_dir(handle_t *handle, struct dentry *dentry,
				  struct inode *dir,
				  struct ext4_iloc *iloc)
{
	int ret, reclen = EXT4_DIR_REC_LEN(dentry->d_name.len);
	int old_size = EXT4_I(dir)->i_inline_size - EXT4_MIN_INLINE_DATA_SIZE;

	ret = ext4_update_inline_data(handle, dir,
				EXT4_I(dir)->i_inline_size + reclen);
	if (ret)
		return ret;

	ext4_update_final_de(ext4_get_inline_xattr_pos(dir, iloc), old_size,
			     EXT4_I(dir)->i_inline_size -
						EXT4_MIN_INLINE_DATA_SIZE);
	dir->i_size = EXT4_I(dir)->i_disksize = EXT4_I(dir)->i_inline_size;
	return 0;
}

/*
 * Try to add the new entry to the inline data.
 * If succeeds, return 0. If not, extended the inline dir and copied data to
 * the new created block.
 */
int ext4_try_add_inline_entry(handle_t *handle, struct dentry *dentry,
			      struct inode *inode)
{
	int ret, inline_size;
	void *inline_start, *backup_buf = NULL;
	struct buffer_head *dir_block = NULL;
	struct ext4_iloc iloc;
	int blocksize = inode->i_sb->s_blocksize;
	struct inode *dir = dentry->d_parent->d_inode;

	ret = ext4_get_inode_loc(dir, &iloc);
	if (ret)
		return ret;

	down_write(&EXT4_I(dir)->xattr_sem);
	if (!ext4_has_inline_data(dir))
		goto out;

	inline_start = ext4_raw_inode(&iloc)->i_block;
	inline_size = EXT4_MIN_INLINE_DATA_SIZE;

	ret = ext4_add_dirent_to_inline(handle, dentry, inode, &iloc,
					inline_start, inline_size);
	if (ret != -ENOSPC)
		goto out;

	/* check whether it can be inserted to inline xattr space. */
	inline_size = EXT4_I(dir)->i_inline_size -
			EXT4_MIN_INLINE_DATA_SIZE;
	if (inline_size > 0) {
		inline_start = ext4_get_inline_xattr_pos(dir, &iloc);

		ret = ext4_add_dirent_to_inline(handle, dentry, inode, &iloc,
						inline_start, inline_size);
		if (ret != -ENOSPC)
			goto out;
	}

	/* Try to add more xattr space.*/
	ret = ext4_update_inline_dir(handle, dentry, dir, &iloc);
	if (ret && ret != -ENOSPC)
		goto out;
	else if (!ret) {
		inline_size = EXT4_I(dir)->i_inline_size -
				EXT4_MIN_INLINE_DATA_SIZE;
		inline_start = ext4_get_inline_xattr_pos(dir, &iloc);

		ret = ext4_add_dirent_to_inline(handle, dentry, inode, &iloc,
						inline_start, inline_size);
		if (ret != -ENOSPC)
			goto out;
	}

	/*
	 * The inline space is filled up, so create a new block for it.
	 * As the extent tree will be created, we have to save the inline
	 * dir first.
	 */
	inline_size = EXT4_I(dir)->i_inline_size;
	backup_buf = kmalloc(inline_size, GFP_NOFS);
	if (!backup_buf) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(backup_buf, (void *)ext4_raw_inode(&iloc)->i_block,
	       EXT4_MIN_INLINE_DATA_SIZE);
	if (inline_size > EXT4_MIN_INLINE_DATA_SIZE)
		memcpy(backup_buf + EXT4_MIN_INLINE_DATA_SIZE,
		       ext4_get_inline_xattr_pos(dir, &iloc),
		       inline_size - EXT4_MIN_INLINE_DATA_SIZE);

	/* clear the entry and the flag in dir now. */
	ret = ext4_destroy_inline_data_nolock(handle, dir);
	if (ret)
		goto out;

	dir->i_size = EXT4_I(dir)->i_disksize = blocksize;
	dir_block = ext4_bread(handle, dir, 0, 1, &ret);
	if (!dir_block)
		goto out;

	BUFFER_TRACE(dir_block, "get_write_access");
	ret = ext4_journal_get_write_access(handle, dir_block);
	if (ret)
		goto out;
	memcpy(dir_block->b_data, backup_buf, inline_size);

	/* Set the final de to cover the whole block. */
	ext4_update_final_de(dir_block->b_data, inline_size,
			     blocksize);

	BUFFER_TRACE(dir_block, "call ext4_handle_dirty_metadata");
	ret = ext4_handle_dirty_metadata(handle, dir, dir_block);

out:
	kfree(backup_buf);
	brelse(dir_block);
	if (!ret || ret == 1)
		ext4_mark_inode_dirty(handle, dir);
	up_write(&EXT4_I(dir)->xattr_sem);
	brelse(iloc.bh);
	return ret;
}

/*
 * Get the inline dentry at offset.
 */
static inline struct ext4_dir_entry_2 *
ext4_get_inline_entry(struct inode *inode,
		      struct ext4_iloc *iloc,
		      unsigned int offset,
		      void **inline_start,
		      int *inline_size)
{
	void *inline_pos;

	BUG_ON(offset > ext4_get_inline_size(inode));

	if (offset < EXT4_MIN_INLINE_DATA_SIZE) {
		inline_pos = ext4_raw_inode(iloc)->i_block;
		*inline_size = EXT4_MIN_INLINE_DATA_SIZE;
	} else {
		inline_pos = ext4_get_inline_xattr_pos(inode, iloc);
		offset -= EXT4_MIN_INLINE_DATA_SIZE;
		*inline_size = ext4_get_inline_size(inode) -
				EXT4_MIN_INLINE_DATA_SIZE;
	}

	if (inline_start)
		*inline_start = inline_pos;
	return (struct ext4_dir_entry_2 *)(inline_pos + offset);
}

int ext4_read_inline_dir(struct file *filp,
			 void *dirent, filldir_t filldir)
{
	int error = 0;
	unsigned int offset;
	int i, stored;
	void *inline_pos;
	struct ext4_dir_entry_2 *de;
	struct super_block *sb;
	struct inode *inode = filp->f_path.dentry->d_inode;
	int ret, inline_size = 0;
	struct ext4_iloc iloc;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	down_read(&EXT4_I(inode)->xattr_sem);
	if (!ext4_has_inline_data(inode))
		goto out;

	sb = inode->i_sb;
	stored = 0;
	offset = filp->f_pos & (sb->s_blocksize - 1);

	while (!error && !stored && filp->f_pos < inode->i_size) {
revalidate:
		/* If the version has changed since the last call to
		 * readdir(2), then we might be pointing to an invalid
		 * dirent right now.  Scan from the start of the block
		 * to make sure. */
		if (filp->f_version != inode->i_version) {
			for (i = 0; i < inode->i_size && i < offset; ) {
				de = ext4_get_inline_entry(inode, &iloc, i,
							   NULL, &inline_size);
				/* It's too expensive to do a full
				 * dirent test each time round this
				 * loop, but we do have to test at
				 * least that it is non-zero.  A
				 * failure will be detected in the
				 * dirent test below. */
				if (ext4_rec_len_from_disk(de->rec_len,
					inline_size) < EXT4_DIR_REC_LEN(1))
					break;
				i += ext4_rec_len_from_disk(de->rec_len,
							    inline_size);
			}
			offset = i;
			filp->f_pos = offset;
			filp->f_version = inode->i_version;
		}

		while (!error && filp->f_pos < inode->i_size) {
			de = ext4_get_inline_entry(inode, &iloc, offset,
						   &inline_pos, &inline_size);
			if (ext4_check_dir_entry(__func__, inode, de,
						 iloc.bh, inline_pos,
						 inline_size, offset)) {
				ret = stored;
				goto out;
			}
			offset += ext4_rec_len_from_disk(de->rec_len,
							 inline_size);
			if (le32_to_cpu(de->inode)) {
				/* We might block in the next section
				 * if the data destination is
				 * currently swapped out.  So, use a
				 * version stamp to detect whether or
				 * not the directory has been modified
				 * during the copy operation.
				 */
				u64 version = filp->f_version;

				error = filldir(dirent, de->name,
						de->name_len,
						filp->f_pos,
						le32_to_cpu(de->inode),
						get_dtype(sb, de->file_type));
				if (error)
					break;
				if (version != filp->f_version)
					goto revalidate;
				stored++;
			}
			filp->f_pos += ext4_rec_len_from_disk(de->rec_len,
							      inline_size);
		}
		offset = 0;
	}
out:
	up_read(&EXT4_I(inode)->xattr_sem);
	brelse(iloc.bh);
	return ret;
}

/*
 * Try to create the inline data for the new dir.
 * If it succeeds, return 0, otherwise return the error.
 * In case of ENOSPC, the caller should create the normal disk layout dir.
 */
int ext4_try_create_inline_dir(handle_t *handle, struct inode *parent,
			       struct inode *inode)
{
	int ret, inline_size = EXT4_MIN_INLINE_DATA_SIZE;
	struct ext4_iloc iloc;
	struct ext4_dir_entry_2 *de;

	ret = ext4_get_inode_loc(inode, &iloc);
	if (ret)
		return ret;

	ret = ext4_prepare_inline_data(handle, inode, inline_size);
	if (ret)
		goto out;

	de = (struct ext4_dir_entry_2 *)ext4_raw_inode(&iloc)->i_block;
	ext4_init_dot_dotdot(parent, inode, de, inline_size);
	inode->i_size = EXT4_I(inode)->i_disksize = inline_size;
out:
	brelse(iloc.bh);
	return ret;
}

struct buffer_head *ext4_get_first_inline_block(struct inode *inode,
				void **buf, int *buf_size, int *retval)
{
	struct ext4_iloc iloc;

	*retval = ext4_get_inode_loc(inode, &iloc);
	if (*retval)
		return NULL;

	*buf = ext4_raw_inode(&iloc)->i_block;
	*buf_size = EXT4_MIN_INLINE_DATA_SIZE;

	return iloc.bh;
}

struct buffer_head *ext4_find_inline_entry(struct inode *dir,
					const struct qstr *d_name,
					struct ext4_dir_entry_2 **res_dir,
					int *has_inline_data)
{
	int ret;
	struct ext4_iloc iloc;
	void *inline_start;
	int inline_size;

	if (ext4_get_inode_loc(dir, &iloc))
		return NULL;

	down_read(&EXT4_I(dir)->xattr_sem);
	if (!ext4_has_inline_data(dir)) {
		*has_inline_data = 0;
		goto out;
	}

	inline_start = ext4_raw_inode(&iloc)->i_block;
	inline_size = EXT4_MIN_INLINE_DATA_SIZE;
	ret = search_dir(iloc.bh, inline_start, inline_size,
			 dir, d_name, 0, res_dir);
	if (ret == 1)
		goto out_find;
	if (ret < 0)
		goto out;

	if (ext4_get_inline_size(dir) == EXT4_MIN_INLINE_DATA_SIZE)
		goto out;

	inline_start = ext4_get_inline_xattr_pos(dir, &iloc);
	inline_size = ext4_get_inline_size(dir) - EXT4_MIN_INLINE_DATA_SIZE;

	ret = search_dir(iloc.bh, inline_start, inline_size,
			 dir, d_name, 0, res_dir);
	if (ret == 1)
		goto out_find;

out:
	brelse(iloc.bh);
	iloc.bh = NULL;
out_find:
	up_read(&EXT4_I(dir)->xattr_sem);
	return iloc.bh;
}

int ext4_delete_inline_entry(handle_t *handle,
			     struct inode *dir,
			     struct ext4_dir_entry_2 *de_del,
			     struct buffer_head *bh)
{
	int err, inline_size;
	struct ext4_iloc iloc;
	void *inline_start;

	err = ext4_get_inode_loc(dir, &iloc);
	if (err)
		return err;

	down_write(&EXT4_I(dir)->xattr_sem);
	if (!ext4_has_inline_data(dir))
		goto out;

	if ((void *)de_del - ((void *)ext4_raw_inode(&iloc)->i_block) <
		EXT4_MIN_INLINE_DATA_SIZE) {
		inline_start = ext4_raw_inode(&iloc)->i_block;
		inline_size = EXT4_MIN_INLINE_DATA_SIZE;
	} else {
		inline_start = ext4_get_inline_xattr_pos(dir, &iloc);
		inline_size = ext4_get_inline_size(dir) -
				EXT4_MIN_INLINE_DATA_SIZE;
	}

	err = ext4_journal_get_write_access(handle, bh);
	if (err)
		goto out;

	err = ext4_generic_delete_entry(handle, dir, de_del, bh,
					inline_start, inline_size);
	if (err)
		goto out;

	BUFFER_TRACE(bh, "call ext4_handle_dirty_metadata");
	err = ext4_mark_inode_dirty(handle, dir);
	if (unlikely(err))
		goto out;

	ext4_show_inline_dir(dir, iloc.bh, inline_start, inline_size);
	err = 1;
out:
	up_write(&EXT4_I(dir)->xattr_sem);
	brelse(iloc.bh);
	if (err != 1 && err != -ENOENT)
		ext4_std_error(dir->i_sb, err);
	return err;
}

int empty_inline_dir(struct inode *dir, int *has_inline_data)
{
	int err, inline_size;
	struct ext4_iloc iloc;
	void *inline_pos;
	unsigned int offset;
	struct ext4_dir_entry_2 *de, *de1;
	int ret = 1;

	err = ext4_get_inode_loc(dir, &iloc);
	if (err) {
		EXT4_ERROR_INODE(dir, "error %d getting inode %lu block",
				 err, dir->i_ino);
		return 1;
	}

	down_read(&EXT4_I(dir)->xattr_sem);
	if (!ext4_has_inline_data(dir)) {
		*has_inline_data = 0;
		goto out;
	}

	de = ext4_get_inline_entry(dir, &iloc, 0,
				   &inline_pos, &inline_size);
	de1 = ext4_get_inline_entry(dir, &iloc,
			ext4_rec_len_from_disk(de->rec_len, inline_size),
			&inline_pos, &inline_size);
	if (le32_to_cpu(de->inode) != dir->i_ino ||
			!le32_to_cpu(de1->inode) ||
			strcmp(".", de->name) ||
			strcmp("..", de1->name)) {
		ext4_warning(dir->i_sb,
			     "bad directory (dir #%lu) - no `.' or `..'",
			     dir->i_ino);
		ret = 1;
		goto out;
	}

	offset = ext4_rec_len_from_disk(de->rec_len, inline_size) +
		 ext4_rec_len_from_disk(de1->rec_len, inline_size);
	while (offset < dir->i_size) {
		de = ext4_get_inline_entry(dir, &iloc, offset,
					   &inline_pos, &inline_size);
		if (ext4_check_dir_entry(__func__, dir, de,
					 iloc.bh, inline_pos,
					 inline_size, offset)) {
			ext4_warning(dir->i_sb,
				     "bad inline directory (dir #%lu) - "
				     "inode %u, rec_len %u, name_len %d"
				     "inline size %d\n",
				     dir->i_ino, le32_to_cpu(de->inode),
				     le16_to_cpu(de->rec_len), de->name_len,
				     inline_size);
			ret = 1;
			goto out;
		}
		if (le32_to_cpu(de->inode)) {
			ret = 0;
			goto out;
		}
		offset += ext4_rec_len_from_disk(de->rec_len, inline_size);
	}

out:
	up_read(&EXT4_I(dir)->xattr_sem);
	brelse(iloc.bh);
	return ret;
}

int ext4_destroy_inline_data(handle_t *handle, struct inode *inode)
{
	int ret;

	down_write(&EXT4_I(inode)->xattr_sem);
	ret = ext4_destroy_inline_data_nolock(handle, inode);
	up_write(&EXT4_I(inode)->xattr_sem);

	return ret;
}

int ext4_inline_data_fiemap(struct inode *inode,
			    struct fiemap_extent_info *fieinfo,
			    int *has_inline)
{
	__u64 physical = 0;
	__u64 length;
	__u32 flags = FIEMAP_EXTENT_DATA_INLINE | FIEMAP_EXTENT_LAST;
	int error = 0;
	struct ext4_iloc iloc;

	down_read(&EXT4_I(inode)->xattr_sem);
	if (!ext4_has_inline_data(inode)) {
		*has_inline = 0;
		goto out;
	}

	error = ext4_get_inode_loc(inode, &iloc);
	if (error)
		goto out;

	physical = iloc.bh->b_blocknr << inode->i_sb->s_blocksize_bits;
	physical += (char *)ext4_raw_inode(&iloc) - iloc.bh->b_data;
	physical += offsetof(struct ext4_inode, i_block);
	length = i_size_read(inode);

	if (physical)
		error = fiemap_fill_next_extent(fieinfo, 0, physical,
						length, flags);
	brelse(iloc.bh);
out:
	up_read(&EXT4_I(inode)->xattr_sem);
	return (error < 0 ? error : 0);
}

/*
 * Called during xattr set, and if we can sparse space 'needed',
 * just create the extent tree evict the data to the outer block.
 *
 * We use jbd2 instead of page cache to move data to the 1st block
 * so that the whole transaction can be committed as a whole and
 * the data isn't lost because of the delayed page cache write.
 */
int ext4_try_to_evict_inline_data(handle_t *handle,
				  struct inode *inode,
				  int needed)
{
	int error;
	struct ext4_xattr_entry *entry;
	struct ext4_xattr_ibody_header *header;
	struct ext4_inode *raw_inode;
	struct ext4_iloc iloc;
	void *buf = NULL;
	struct buffer_head *data_bh = NULL, tmp_bh;
	struct ext4_map_blocks map;

	error = ext4_get_inode_loc(inode, &iloc);
	if (error)
		return error;

	raw_inode = ext4_raw_inode(&iloc);
	header = IHDR(inode, raw_inode);
	entry = (struct ext4_xattr_entry *)((void *)raw_inode +
					    EXT4_I(inode)->i_inline_off);
	if (EXT4_XATTR_LEN(entry->e_name_len) +
	    EXT4_XATTR_SIZE(le32_to_cpu(entry->e_value_size)) < needed) {
		error = -ENOSPC;
		goto out;
	}

	buf = kmalloc(ext4_get_inline_size(inode), GFP_NOFS);
	if (!buf) {
		error = -ENOMEM;
		goto out;
	}

	error = ext4_read_inline_data(inode, buf,
				      ext4_get_inline_size(inode), &iloc);
	if (error < 0)
		goto out;

	error = ext4_destroy_inline_data_nolock(handle, inode);
	if (error)
		goto out;

	map.m_lblk = 0;
	map.m_len = 1;
	map.m_flags = 0;
	error = ext4_get_blocks(handle, inode, &map, &tmp_bh, EXT4_GET_BLOCKS_CREATE);
	if (error < 0)
		goto out;
	if (!(map.m_flags & EXT4_MAP_MAPPED)) {
		error = -EIO;
		goto out;
	}

	data_bh = sb_getblk(inode->i_sb, map.m_pblk);
	if (!data_bh) {
		error = -EIO;
		goto out;
	}

	lock_buffer(data_bh);
	error = ext4_journal_get_create_access(handle, data_bh);
	if (error) {
		unlock_buffer(data_bh);
		error = -EIO;
		goto out;
	}
	memcpy(data_bh->b_data, buf, data_bh->b_size);
	set_buffer_uptodate(data_bh);
	unlock_buffer(data_bh);
	error = ext4_handle_dirty_metadata(handle,
					   inode, data_bh);
out:
	brelse(data_bh);
	kfree(buf);
	brelse(iloc.bh);
	return error;
}

void ext4_inline_data_truncate(struct inode *inode)
{
	handle_t *handle;
	int inline_size = ext4_get_inline_size(inode);
	size_t isize = i_size_read(inode);
	int needed_blocks, value_len;
	void *value = NULL;
	struct ext4_xattr_ibody_find is = {
		.s = { .not_found = -ENODATA, },
	};
	struct ext4_xattr_info i = {
		.name_index = EXT4_XATTR_INDEX_SYSTEM_DATA,
		.name = EXT4_XATTR_SYSTEM_DATA_NAME,
	};

	needed_blocks = ext4_writepage_trans_blocks(inode);
	handle = ext4_journal_start(inode, needed_blocks);
	if (IS_ERR(handle))
		return;

	if (ext4_orphan_add(handle, inode))
		goto out;

	EXT4_I(inode)->i_disksize = inode->i_size;

	if (isize < ext4_get_max_inline_size(inode)) {
		if (ext4_get_inode_loc(inode, &is.iloc))
			goto out;

		if (isize < EXT4_MIN_INLINE_DATA_SIZE)
			memset(ext4_raw_inode(&is.iloc)->i_block + isize, 0,
					EXT4_MIN_INLINE_DATA_SIZE - isize);
		if (inline_size > EXT4_MIN_INLINE_DATA_SIZE &&
				isize < inline_size) {
			if (ext4_xattr_ibody_find(inode, &i, &is))
				goto out_bh;

			BUG_ON(is.s.not_found);

			value_len = le32_to_cpu(is.s.here->e_value_size);
			value = kmalloc(value_len, GFP_NOFS);

			if (ext4_xattr_ibody_get(inode, i.name_index, i.name,
						value, value_len))
				goto out_bh;

			i.value = value;
			i.value_len = isize - EXT4_MIN_INLINE_DATA_SIZE;
			if (ext4_xattr_ibody_inline_set(handle, inode, &i, &is))
				goto out_bh;
		}
		if (isize < inline_size)
			EXT4_I(inode)->i_inline_size = isize <
				EXT4_MIN_INLINE_DATA_SIZE ?
				EXT4_MIN_INLINE_DATA_SIZE : isize;
out_bh:
		if (value)
			kfree(value);
		brelse(is.iloc.bh);
	} else
		ext4_convert_inline_data_to_extent(inode->i_mapping, inode, 0);

out:
	if (inode->i_nlink)
		ext4_orphan_del(handle, inode);

	inode->i_mtime = inode->i_ctime = ext4_current_time(inode);
	ext4_mark_inode_dirty(handle, inode);
	if (IS_SYNC(inode))
		ext4_handle_sync(handle);

	ext4_journal_stop(handle);
}
