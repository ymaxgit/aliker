/*
 * linux/drivers/scsi/scsi_proc.c
 *
 * The functions in this file provide an interface between
 * the PROC file system and the SCSI device drivers
 * It is mainly used for debugging, statistics and to pass 
 * information directly to the lowlevel driver.
 *
 * (c) 1995 Michael Neuffer neuffer@goofy.zdv.uni-mainz.de 
 * Version: 0.99.8   last change: 95/09/13
 * 
 * generic command parser provided by: 
 * Andreas Heilwagen <crashcar@informatik.uni-koblenz.de>
 *
 * generic_proc_info() support of xxxx_info() by:
 * Michael A. Griffith <grif@acm.org>
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/blkdev.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <asm/uaccess.h>

#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport.h>

#include "scsi_priv.h"
#include "scsi_logging.h"
#include "sd.h"


/* 4K page size, but our output routines, use some slack for overruns */
#define PROC_BLOCK_SIZE (3*1024)

static struct proc_dir_entry *proc_scsi;

/* for io-latency */
struct proc_entry_name {
	struct proc_dir_entry *entry;
	struct proc_dir_entry *parent;
	char name[64];
};
static struct proc_dir_entry *proc_io_latency;

#define PROC_SHOW(_name, _unit, _nr, _grain, _member)			\
static void _name##_show(struct seq_file *seq,				\
				struct latency_stats __percpu *lstats)	\
{									\
	int slot_base = 0;						\
	int i, cpu;							\
	unsigned long sum;						\
									\
	for (i = 0; i < _nr; i++) {					\
		sum = 0;						\
		for_each_possible_cpu(cpu)				\
			sum += per_cpu_ptr(lstats, cpu)->_member[i];	\
									\
		seq_printf(seq,						\
			"%d-%d(%s):%lu\n",				\
			slot_base,					\
			slot_base + _grain - 1,				\
			_unit,						\
			sum);						\
		slot_base += _grain;					\
	}								\
}

#define PROC_FOPS(_name) 						\
static int _name##_seq_show(struct seq_file *seq, void *v)		\
{									\
	struct request_queue *q = seq->private;				\
	struct request_queue_aux *aux;					\
									\
	if (!q)								\
		seq_puts(seq, "none");					\
	else {								\
		aux = get_aux(q);					\
		_name##_show(seq, aux->lstats);				\
	}								\
	return 0;							\
}									\
									\
static const struct seq_operations _name##_seq_ops = {			\
	.start  = io_latency_seq_start,					\
	.next   = io_latency_seq_next,					\
	.stop   = io_latency_seq_stop,					\
	.show   = _name##_seq_show,					\
};									\
									\
static int proc_##_name##_open(struct inode *inode, struct file *file)	\
{									\
	int res;							\
	res = seq_open(file, &_name##_seq_ops);				\
	if (res == 0) {							\
		struct seq_file *m = file->private_data;		\
		m->private = PDE_DATA(inode);				\
	}								\
	return res;							\
}									\
									\
static const struct file_operations proc_##_name##_fops = {		\
	.owner		= THIS_MODULE,					\
	.open		= proc_##_name##_open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= seq_release,					\
}

static void *PDE_DATA(const struct inode *inode)
{
	return container_of(inode, struct proc_inode, vfs_inode)->pde->data;
}

static void *io_latency_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? NULL : SEQ_START_TOKEN;
}

static void *io_latency_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

static void io_latency_seq_stop(struct seq_file *seq, void *v)
{
}

#define KB (1024)
static void io_size_show(struct seq_file *seq,
				struct latency_stats __percpu *lstats)
{
	int slot_base = 0;
	int i, cpu;
	unsigned long sum;

	for (i = 0; i < IO_SIZE_STATS_NR; i++) {
		sum = 0;
		for_each_possible_cpu(cpu)
			sum += per_cpu_ptr(lstats, cpu)->io_size_stats[i];

		seq_printf(seq,
			"%d-%d(KB):%lu\n",
			(slot_base / KB),
			(slot_base + IO_SIZE_STATS_GRAINSIZE - 1) / KB,
			sum);
		slot_base += IO_SIZE_STATS_GRAINSIZE;
	}
}

static void io_read_size_show(struct seq_file *seq,
				struct latency_stats __percpu *lstats)
{
	int slot_base = 0;
	int i, cpu;
	unsigned long sum;

	for (i = 0; i < IO_SIZE_STATS_NR; i++) {
		sum = 0;
		for_each_possible_cpu(cpu)
			sum += per_cpu_ptr(lstats, cpu)->io_read_size_stats[i];

		seq_printf(seq,
			"%d-%d(KB):%lu\n",
			(slot_base / KB),
			(slot_base + IO_SIZE_STATS_GRAINSIZE - 1) / KB,
			sum);
		slot_base += IO_SIZE_STATS_GRAINSIZE;
	}
}

static void io_write_size_show(struct seq_file *seq,
				struct latency_stats __percpu *lstats)
{
	int slot_base = 0;
	int i, cpu;
	unsigned long sum;

	for (i = 0; i < IO_SIZE_STATS_NR; i++) {
		sum = 0;
		for_each_possible_cpu(cpu)
			sum += per_cpu_ptr(lstats, cpu)->io_write_size_stats[i];

		seq_printf(seq,
			"%d-%d(KB):%lu\n",
			(slot_base / KB),
			(slot_base + IO_SIZE_STATS_GRAINSIZE - 1) / KB,
			sum);
		slot_base += IO_SIZE_STATS_GRAINSIZE;
	}
}

PROC_SHOW(soft_io_latency_us, "us", IO_LATENCY_STATS_US_NR,
		IO_LATENCY_STATS_US_GRAINSIZE, soft_latency_stats_us);
PROC_SHOW(soft_io_latency_ms, "ms", IO_LATENCY_STATS_MS_NR,
		IO_LATENCY_STATS_MS_GRAINSIZE, soft_latency_stats_ms);
PROC_SHOW(soft_io_latency_s, "s", IO_LATENCY_STATS_S_NR,
		IO_LATENCY_STATS_S_GRAINSIZE, soft_latency_stats_s);

PROC_SHOW(soft_read_io_latency_us, "us", IO_LATENCY_STATS_US_NR,
		IO_LATENCY_STATS_US_GRAINSIZE, soft_latency_read_stats_us);
PROC_SHOW(soft_read_io_latency_ms, "ms", IO_LATENCY_STATS_MS_NR,
		IO_LATENCY_STATS_MS_GRAINSIZE, soft_latency_read_stats_ms);
PROC_SHOW(soft_read_io_latency_s, "s", IO_LATENCY_STATS_S_NR,
		IO_LATENCY_STATS_S_GRAINSIZE, soft_latency_read_stats_s);

PROC_SHOW(soft_write_io_latency_us, "us", IO_LATENCY_STATS_US_NR,
		IO_LATENCY_STATS_US_GRAINSIZE, soft_latency_write_stats_us);
PROC_SHOW(soft_write_io_latency_ms, "ms", IO_LATENCY_STATS_MS_NR,
		IO_LATENCY_STATS_MS_GRAINSIZE, soft_latency_write_stats_ms);
PROC_SHOW(soft_write_io_latency_s, "s", IO_LATENCY_STATS_S_NR,
		IO_LATENCY_STATS_S_GRAINSIZE, soft_latency_write_stats_s);

PROC_SHOW(io_latency_us, "us", IO_LATENCY_STATS_US_NR,
		IO_LATENCY_STATS_US_GRAINSIZE, latency_stats_us);
PROC_SHOW(io_latency_ms, "ms", IO_LATENCY_STATS_MS_NR,
		IO_LATENCY_STATS_MS_GRAINSIZE, latency_stats_ms);
PROC_SHOW(io_latency_s, "s", IO_LATENCY_STATS_S_NR,
		IO_LATENCY_STATS_S_GRAINSIZE, latency_stats_s);

PROC_SHOW(read_io_latency_us, "us", IO_LATENCY_STATS_US_NR,
		IO_LATENCY_STATS_US_GRAINSIZE, latency_read_stats_us);
PROC_SHOW(read_io_latency_ms, "ms", IO_LATENCY_STATS_MS_NR,
		IO_LATENCY_STATS_MS_GRAINSIZE, latency_read_stats_ms);
PROC_SHOW(read_io_latency_s, "s", IO_LATENCY_STATS_S_NR,
		IO_LATENCY_STATS_S_GRAINSIZE, latency_read_stats_s);

PROC_SHOW(write_io_latency_us, "us", IO_LATENCY_STATS_US_NR,
		IO_LATENCY_STATS_US_GRAINSIZE, latency_write_stats_us);
PROC_SHOW(write_io_latency_ms, "ms", IO_LATENCY_STATS_MS_NR,
		IO_LATENCY_STATS_MS_GRAINSIZE, latency_write_stats_ms);
PROC_SHOW(write_io_latency_s, "s", IO_LATENCY_STATS_S_NR,
		IO_LATENCY_STATS_S_GRAINSIZE, latency_write_stats_s);

PROC_FOPS(io_size);
PROC_FOPS(io_read_size);
PROC_FOPS(io_write_size);

PROC_FOPS(soft_io_latency_us);
PROC_FOPS(soft_io_latency_ms);
PROC_FOPS(soft_io_latency_s);
PROC_FOPS(soft_read_io_latency_us);
PROC_FOPS(soft_read_io_latency_ms);
PROC_FOPS(soft_read_io_latency_s);
PROC_FOPS(soft_write_io_latency_us);
PROC_FOPS(soft_write_io_latency_ms);
PROC_FOPS(soft_write_io_latency_s);

PROC_FOPS(io_latency_us);
PROC_FOPS(io_latency_ms);
PROC_FOPS(io_latency_s);
PROC_FOPS(read_io_latency_us);
PROC_FOPS(read_io_latency_ms);
PROC_FOPS(read_io_latency_s);
PROC_FOPS(write_io_latency_us);
PROC_FOPS(write_io_latency_ms);
PROC_FOPS(write_io_latency_s);

#define ENABLE_ATTR_SHOW(_name)						\
static int show_##_name(char *page, char **start, off_t offset,		\
					int count, int *eof, void *data)\
{									\
	struct request_queue_aux *aux;					\
	int res = 0;							\
									\
	if (!data)							\
		goto out;						\
	aux = get_aux(data);						\
	if (!aux)							\
		goto out;						\
	if (aux->_name)							\
		res = snprintf(page, count, "1\n");			\
	else								\
		res = snprintf(page, count, "0\n");			\
out:									\
	return res;							\
}

#define ENABLE_ATTR_STORE(_name)					\
static int store_##_name(struct file *file, const char __user *buffer,	\
					unsigned long count, void *data)\
{									\
	struct request_queue_aux *aux;					\
	char *page = NULL;						\
									\
	if (count <= 0 || count > PAGE_SIZE)				\
		goto out;						\
	if (!data)							\
		goto out;						\
	aux = get_aux(data);						\
	if (!aux)							\
		goto out;						\
	page = (char *)__get_free_page(GFP_KERNEL);			\
	if (!page)							\
		goto out;						\
	if (copy_from_user(page, buffer, count))			\
		goto out;						\
	if (page[0] == '1')						\
		aux->_name = 1;						\
	else if (page[0] == '0')					\
		aux->_name = 0;						\
out:									\
	if (page)							\
		free_page((unsigned long)page);				\
	return count;							\
}

static int store_enable_use_us(struct file *file, const char __user *buffer,
					unsigned long count, void *data)
{
	struct request_queue_aux *aux;
	char *page = NULL;
	int ret = count;

	if (count <= 0 || count > PAGE_SIZE)
		goto out;
	if (!data)
		goto out;
	aux = get_aux(data);
	if (!aux)
		goto out;
	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		goto out;
	if (copy_from_user(page, buffer, count))
		goto out;
	if (aux->enable_latency || aux->enable_soft_latency) {
		ret = -EINVAL;
		goto out;
	}
	if (page[0] == '1')
		aux->enable_use_us = 1;
	else if (page[0] == '0')
		aux->enable_use_us = 0;
out:
	if (page)
		free_page((unsigned long)page);
	return ret;
}

ENABLE_ATTR_SHOW(enable_latency);
ENABLE_ATTR_STORE(enable_latency);
ENABLE_ATTR_SHOW(enable_soft_latency);
ENABLE_ATTR_STORE(enable_soft_latency);
ENABLE_ATTR_SHOW(enable_use_us);

static int show_io_stats_reset(char *page, char **start, off_t offset,
					int count, int *eof, void *data)
{
	return snprintf(page, count, "0\n");
}

static int store_io_stats_reset(struct file *file, const char __user *buffer,
					unsigned long count, void *data)
{
	struct request_queue_aux *aux;

	if (count <= 0)
		goto out;

	aux = get_aux(data);
	if (!aux)
		goto out;

	reset_latency_stats(aux->lstats);

out:
	return count;
}

struct io_latency_proc_node {
	char *name;
	const struct file_operations *fops;
};

static const struct io_latency_proc_node proc_node_list[] = {
	{ "io_latency_ms", &proc_io_latency_ms_fops},
	{ "io_latency_s", &proc_io_latency_s_fops},

	{ "read_io_latency_ms", &proc_read_io_latency_ms_fops},
	{ "read_io_latency_s", &proc_read_io_latency_s_fops},

	{ "write_io_latency_ms", &proc_write_io_latency_ms_fops},
	{ "write_io_latency_s", &proc_write_io_latency_s_fops},

	{ "soft_io_latency_ms", &proc_soft_io_latency_ms_fops},
	{ "soft_io_latency_s", &proc_soft_io_latency_s_fops},

	{ "soft_read_io_latency_ms", &proc_soft_read_io_latency_ms_fops},
	{ "soft_read_io_latency_s", &proc_soft_read_io_latency_s_fops},

	{ "soft_write_io_latency_ms", &proc_soft_write_io_latency_ms_fops},
	{ "soft_write_io_latency_s", &proc_soft_write_io_latency_s_fops},

	{ "io_size", &proc_io_size_fops},
	{ "io_read_size", &proc_io_read_size_fops},
	{ "io_write_size", &proc_io_write_size_fops},

	{ "io_latency_us", &proc_io_latency_us_fops},
	{ "read_io_latency_us", &proc_read_io_latency_us_fops},
	{ "write_io_latency_us", &proc_write_io_latency_us_fops},
	{ "soft_io_latency_us", &proc_soft_io_latency_us_fops},
	{ "soft_read_io_latency_us", &proc_soft_read_io_latency_us_fops},
	{ "soft_write_io_latency_us", &proc_soft_write_io_latency_us_fops},
};

#define MAX_REQUESTS		9973
#define PROC_NUM (sizeof(proc_node_list) / sizeof(struct io_latency_proc_node))

void delete_iolatency_procfs(struct scsi_disk *sd)
{
	int i;
	char name[128];

	for (i = 0; i < PROC_NUM; i++) {
		sprintf(name,"%s/%s", sd->disk->disk_name, proc_node_list[i].name);
		remove_proc_entry(name, proc_io_latency);
	}

	sprintf(name,"%s/io_stats_reset", sd->disk->disk_name);
	remove_proc_entry(name, proc_io_latency);

	sprintf(name,"%s/enable_latency", sd->disk->disk_name);
	remove_proc_entry(name, proc_io_latency);

	sprintf(name,"%s/enable_soft_latency", sd->disk->disk_name);
	remove_proc_entry(name, proc_io_latency);

	sprintf(name,"%s/enable_use_us", sd->disk->disk_name);
	remove_proc_entry(name, proc_io_latency);

	remove_proc_entry(sd->disk->disk_name, proc_io_latency);
}
EXPORT_SYMBOL(delete_iolatency_procfs);

void insert_iolatency_procfs(struct scsi_disk *sd)
{
	struct proc_dir_entry *proc_node, *proc_dir;
	int i;

	proc_dir = proc_mkdir(sd->disk->disk_name, proc_io_latency);
	if (!proc_dir)
		goto err;

	for (i = 0; i < PROC_NUM; i++) {
		proc_node = proc_create_data(proc_node_list[i].name,
					S_IFREG, proc_dir,
					proc_node_list[i].fops,
					sd->device->request_queue);
		if (!proc_node)
			goto err;
	}
	/* create io_stats_reset */
	proc_node = proc_create_data("io_stats_reset", S_IFREG,
				proc_dir, NULL,
				sd->device->request_queue);
	if (!proc_node)
		goto err;
	proc_node->read_proc = show_io_stats_reset;
	proc_node->write_proc = store_io_stats_reset;

	/* create enable_latency */
	proc_node = proc_create_data("enable_latency", S_IFREG,
				proc_dir, NULL,
				sd->device->request_queue);
	if (!proc_node)
		goto err;
	proc_node->read_proc = show_enable_latency;
	proc_node->write_proc = store_enable_latency;

	/* create enable_soft_latency */
	proc_node = proc_create_data("enable_soft_latency", S_IFREG,
				proc_dir, NULL,
				sd->device->request_queue);
	if (!proc_node)
		goto err;
	proc_node->read_proc = show_enable_soft_latency;
	proc_node->write_proc = store_enable_soft_latency;

	/* create enable_use_us */
	proc_node = proc_create_data("enable_use_us", S_IFREG,
				proc_dir, NULL,
				sd->device->request_queue);
	if (!proc_node)
		goto err;
	proc_node->read_proc = show_enable_use_us;
	proc_node->write_proc = store_enable_use_us;
	return;
err:
	delete_iolatency_procfs(sd);
}
EXPORT_SYMBOL(insert_iolatency_procfs);

/* Protect sht->present and sht->proc_dir */
static DEFINE_MUTEX(global_host_template_mutex);

/**
 * proc_scsi_read - handle read from /proc by calling host's proc_info() command
 * @buffer: passed to proc_info
 * @start: passed to proc_info
 * @offset: passed to proc_info
 * @length: passed to proc_info
 * @eof: returns whether length read was less than requested
 * @data: pointer to a &struct Scsi_Host
 */

static int proc_scsi_read(char *buffer, char **start, off_t offset,
			  int length, int *eof, void *data)
{
	struct Scsi_Host *shost = data;
	int n;

	n = shost->hostt->proc_info(shost, buffer, start, offset, length, 0);
	*eof = (n < length);

	return n;
}

/**
 * proc_scsi_write_proc - Handle write to /proc by calling host's proc_info()
 * @file: not used
 * @buf: source of data to write.
 * @count: number of bytes (at most PROC_BLOCK_SIZE) to write.
 * @data: pointer to &struct Scsi_Host
 */
static int proc_scsi_write_proc(struct file *file, const char __user *buf,
                           unsigned long count, void *data)
{
	struct Scsi_Host *shost = data;
	ssize_t ret = -ENOMEM;
	char *page;
	char *start;
    
	if (count > PROC_BLOCK_SIZE)
		return -EOVERFLOW;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (page) {
		ret = -EFAULT;
		if (copy_from_user(page, buf, count))
			goto out;
		ret = shost->hostt->proc_info(shost, page, &start, 0, count, 1);
	}
out:
	free_page((unsigned long)page);
	return ret;
}

/**
 * scsi_proc_hostdir_add - Create directory in /proc for a scsi host
 * @sht: owner of this directory
 *
 * Sets sht->proc_dir to the new directory.
 */

void scsi_proc_hostdir_add(struct scsi_host_template *sht)
{
	if (!sht->proc_info)
		return;

	mutex_lock(&global_host_template_mutex);
	if (!sht->present++) {
		sht->proc_dir = proc_mkdir(sht->proc_name, proc_scsi);
        	if (!sht->proc_dir)
			printk(KERN_ERR "%s: proc_mkdir failed for %s\n",
			       __func__, sht->proc_name);
	}
	mutex_unlock(&global_host_template_mutex);
}

/**
 * scsi_proc_hostdir_rm - remove directory in /proc for a scsi host
 * @sht: owner of directory
 */
void scsi_proc_hostdir_rm(struct scsi_host_template *sht)
{
	if (!sht->proc_info)
		return;

	mutex_lock(&global_host_template_mutex);
	if (!--sht->present && sht->proc_dir) {
		remove_proc_entry(sht->proc_name, proc_scsi);
		sht->proc_dir = NULL;
	}
	mutex_unlock(&global_host_template_mutex);
}


/**
 * scsi_proc_host_add - Add entry for this host to appropriate /proc dir
 * @shost: host to add
 */
void scsi_proc_host_add(struct Scsi_Host *shost)
{
	struct scsi_host_template *sht = shost->hostt;
	struct proc_dir_entry *p;
	char name[10];

	if (!sht->proc_dir)
		return;

	sprintf(name,"%d", shost->host_no);
	p = create_proc_read_entry(name, S_IFREG | S_IRUGO | S_IWUSR,
			sht->proc_dir, proc_scsi_read, shost);
	if (!p) {
		printk(KERN_ERR "%s: Failed to register host %d in"
		       "%s\n", __func__, shost->host_no,
		       sht->proc_name);
		return;
	} 

	p->write_proc = proc_scsi_write_proc;
}

/**
 * scsi_proc_host_rm - remove this host's entry from /proc
 * @shost: which host
 */
void scsi_proc_host_rm(struct Scsi_Host *shost)
{
	char name[10];

	if (!shost->hostt->proc_dir)
		return;

	sprintf(name,"%d", shost->host_no);
	remove_proc_entry(name, shost->hostt->proc_dir);
}
/**
 * proc_print_scsidevice - return data about this host
 * @dev: A scsi device
 * @data: &struct seq_file to output to.
 *
 * Description: prints Host, Channel, Id, Lun, Vendor, Model, Rev, Type,
 * and revision.
 */
static int proc_print_scsidevice(struct device *dev, void *data)
{
	struct scsi_device *sdev;
	struct seq_file *s = data;
	int i;

	if (!scsi_is_sdev_device(dev))
		goto out;

	sdev = to_scsi_device(dev);
	seq_printf(s,
		"Host: scsi%d Channel: %02d Id: %02d Lun: %02d\n  Vendor: ",
		sdev->host->host_no, sdev->channel, sdev->id, sdev->lun);
	for (i = 0; i < 8; i++) {
		if (sdev->vendor[i] >= 0x20)
			seq_printf(s, "%c", sdev->vendor[i]);
		else
			seq_printf(s, " ");
	}

	seq_printf(s, " Model: ");
	for (i = 0; i < 16; i++) {
		if (sdev->model[i] >= 0x20)
			seq_printf(s, "%c", sdev->model[i]);
		else
			seq_printf(s, " ");
	}

	seq_printf(s, " Rev: ");
	for (i = 0; i < 4; i++) {
		if (sdev->rev[i] >= 0x20)
			seq_printf(s, "%c", sdev->rev[i]);
		else
			seq_printf(s, " ");
	}

	seq_printf(s, "\n");

	seq_printf(s, "  Type:   %s ", scsi_device_type(sdev->type));
	seq_printf(s, "               ANSI  SCSI revision: %02x",
			sdev->scsi_level - (sdev->scsi_level > 1));
	if (sdev->scsi_level == 2)
		seq_printf(s, " CCS\n");
	else
		seq_printf(s, "\n");

out:
	return 0;
}

/**
 * scsi_add_single_device - Respond to user request to probe for/add device
 * @host: user-supplied decimal integer
 * @channel: user-supplied decimal integer
 * @id: user-supplied decimal integer
 * @lun: user-supplied decimal integer
 *
 * Description: called by writing "scsi add-single-device" to /proc/scsi/scsi.
 *
 * does scsi_host_lookup() and either user_scan() if that transport
 * type supports it, or else scsi_scan_host_selected()
 *
 * Note: this seems to be aimed exclusively at SCSI parallel busses.
 */

static int scsi_add_single_device(uint host, uint channel, uint id, uint lun)
{
	struct Scsi_Host *shost;
	int error = -ENXIO;

	shost = scsi_host_lookup(host);
	if (!shost)
		return error;

	if (shost->transportt->user_scan)
		error = shost->transportt->user_scan(shost, channel, id, lun);
	else
		error = scsi_scan_host_selected(shost, channel, id, lun, 1);
	scsi_host_put(shost);
	return error;
}

/**
 * scsi_remove_single_device - Respond to user request to remove a device
 * @host: user-supplied decimal integer
 * @channel: user-supplied decimal integer
 * @id: user-supplied decimal integer
 * @lun: user-supplied decimal integer
 *
 * Description: called by writing "scsi remove-single-device" to
 * /proc/scsi/scsi.  Does a scsi_device_lookup() and scsi_remove_device()
 */
static int scsi_remove_single_device(uint host, uint channel, uint id, uint lun)
{
	struct scsi_device *sdev;
	struct Scsi_Host *shost;
	int error = -ENXIO;

	shost = scsi_host_lookup(host);
	if (!shost)
		return error;
	sdev = scsi_device_lookup(shost, channel, id, lun);
	if (sdev) {
		scsi_remove_device(sdev);
		scsi_device_put(sdev);
		error = 0;
	}

	scsi_host_put(shost);
	return error;
}

/**
 * proc_scsi_write - handle writes to /proc/scsi/scsi
 * @file: not used
 * @buf: buffer to write
 * @length: length of buf, at most PAGE_SIZE
 * @ppos: not used
 *
 * Description: this provides a legacy mechanism to add or remove devices by
 * Host, Channel, ID, and Lun.  To use,
 * "echo 'scsi add-single-device 0 1 2 3' > /proc/scsi/scsi" or
 * "echo 'scsi remove-single-device 0 1 2 3' > /proc/scsi/scsi" with
 * "0 1 2 3" replaced by the Host, Channel, Id, and Lun.
 *
 * Note: this seems to be aimed at parallel SCSI. Most modern busses (USB,
 * SATA, Firewire, Fibre Channel, etc) dynamically assign these values to
 * provide a unique identifier and nothing more.
 */


static ssize_t proc_scsi_write(struct file *file, const char __user *buf,
			       size_t length, loff_t *ppos)
{
	int host, channel, id, lun;
	char *buffer, *p;
	int err;

	if (!buf || length > PAGE_SIZE)
		return -EINVAL;

	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	err = -EFAULT;
	if (copy_from_user(buffer, buf, length))
		goto out;

	err = -EINVAL;
	if (length < PAGE_SIZE)
		buffer[length] = '\0';
	else if (buffer[PAGE_SIZE-1])
		goto out;

	/*
	 * Usage: echo "scsi add-single-device 0 1 2 3" >/proc/scsi/scsi
	 * with  "0 1 2 3" replaced by your "Host Channel Id Lun".
	 */
	if (!strncmp("scsi add-single-device", buffer, 22)) {
		p = buffer + 23;

		host = simple_strtoul(p, &p, 0);
		channel = simple_strtoul(p + 1, &p, 0);
		id = simple_strtoul(p + 1, &p, 0);
		lun = simple_strtoul(p + 1, &p, 0);

		err = scsi_add_single_device(host, channel, id, lun);

	/*
	 * Usage: echo "scsi remove-single-device 0 1 2 3" >/proc/scsi/scsi
	 * with  "0 1 2 3" replaced by your "Host Channel Id Lun".
	 */
	} else if (!strncmp("scsi remove-single-device", buffer, 25)) {
		p = buffer + 26;

		host = simple_strtoul(p, &p, 0);
		channel = simple_strtoul(p + 1, &p, 0);
		id = simple_strtoul(p + 1, &p, 0);
		lun = simple_strtoul(p + 1, &p, 0);

		err = scsi_remove_single_device(host, channel, id, lun);
	}

	/*
	 * convert success returns so that we return the 
	 * number of bytes consumed.
	 */
	if (!err)
		err = length;

 out:
	free_page((unsigned long)buffer);
	return err;
}

/**
 * proc_scsi_show - show contents of /proc/scsi/scsi (attached devices)
 * @s: output goes here
 * @p: not used
 */
static int proc_scsi_show(struct seq_file *s, void *p)
{
	seq_printf(s, "Attached devices:\n");
	bus_for_each_dev(&scsi_bus_type, NULL, s, proc_print_scsidevice);
	return 0;
}

/**
 * proc_scsi_open - glue function
 * @inode: not used
 * @file: passed to single_open()
 *
 * Associates proc_scsi_show with this file
 */
static int proc_scsi_open(struct inode *inode, struct file *file)
{
	/*
	 * We don't really need this for the write case but it doesn't
	 * harm either.
	 */
	return single_open(file, proc_scsi_show, NULL);
}

static const struct file_operations proc_scsi_operations = {
	.owner		= THIS_MODULE,
	.open		= proc_scsi_open,
	.read		= seq_read,
	.write		= proc_scsi_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void create_iolatency_procfs(void)
{
	proc_io_latency = proc_mkdir("io-latency", NULL);
}

static void destory_iolatency_procfs(void)
{
	if (proc_io_latency) {
		remove_proc_entry("io-latency", NULL);
		proc_io_latency = NULL;
	}
}

/**
 * scsi_init_procfs - create scsi and scsi/scsi in procfs
 */
int __init scsi_init_procfs(void)
{
	struct proc_dir_entry *pde;

	proc_scsi = proc_mkdir("scsi", NULL);
	if (!proc_scsi)
		goto err1;

	pde = proc_create("scsi/scsi", 0, NULL, &proc_scsi_operations);
	if (!pde)
		goto err2;

	create_iolatency_procfs();

	return 0;

err2:
	remove_proc_entry("scsi", NULL);
err1:
	return -ENOMEM;
}

/**
 * scsi_exit_procfs - Remove scsi/scsi and scsi from procfs
 */
void scsi_exit_procfs(void)
{
	remove_proc_entry("scsi/scsi", NULL);
	remove_proc_entry("scsi", NULL);
	destory_iolatency_procfs();
}
