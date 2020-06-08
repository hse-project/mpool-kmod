// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/debugfs.h>

#include <mpcore/evc.h>
#include <mpcore/mpool_printk.h>

static struct {
	spinlock_t      lock;
	struct evc     *head;

	____cacheline_aligned
	struct dentry  *debug_root;
} evc_root;


void evc_count(struct evc *evc)
{
	if (likely(atomic64_inc_return(&evc->evc_odometer) != 1u))
		return;

	spin_lock(&evc_root.lock);
	if (!evc->evc_next) {
		evc->evc_next = evc_root.head;
		evc_root.head = evc;
	}
	spin_unlock(&evc_root.lock);
}


static ssize_t mpool_debug_emit(char *evstr, ssize_t len)
{
	char       *pos;
	const char *file;
	struct evc *evc;
	int         cc;

	pos = evstr;

	spin_lock(&evc_root.lock);
	evc = evc_root.head;
	spin_unlock(&evc_root.lock);
	if (!evc)
		return scnprintf(pos, len, "%s", "No Events\n");

	cc = scnprintf(pos, len, "%14s %6s %12s  %s\n", "FILE", "LINE", "ODOMETER", "FUNC");

	for (pos += cc, len -= cc; evc && len > 1;
	     evc = evc->evc_next, pos += cc, len -= cc) {
		file = strrchr(evc->evc_file, '/');
		file = file ? file + 1 : evc->evc_file;

		cc = scnprintf(pos, len, "%14s %6d %12lu  %s\n", file, evc->evc_line,
			      (ulong)atomic64_read(&evc->evc_odometer), evc->evc_func);
		if (cc == len - 1)
			pos[cc++] = '\n';
	}

	if (evc)
		mp_pr_info("Insufficient buffer space to dump all events");

	return pos - evstr;
}


static int mpool_debug_open(struct inode *inode, struct file *file)
{
	char   *evstr;
	size_t  sz;

	evstr = (char *)get_zeroed_page(GFP_KERNEL);
	if (!evstr)
		return -ENOMEM;

	sz = mpool_debug_emit(evstr, PAGE_SIZE - 1);

	i_size_write(inode, sz);

	file->private_data = evstr;

	return 0;
}

static int mpool_debug_release(struct inode *inode, struct file *file)
{
	free_page((unsigned long)file->private_data);
	return 0;
}

static ssize_t mpool_debug_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	return simple_read_from_buffer(buf, nbytes, ppos, file->private_data,
				       i_size_read(file->f_mapping->host));
}

static const struct file_operations mpool_debug_fops = {
	.owner   = THIS_MODULE,
	.open    = mpool_debug_open,
	.release = mpool_debug_release,
	.read    = mpool_debug_read,
};


void evc_init(void)
{
	struct dentry  *d;

	spin_lock_init(&evc_root.lock);
	evc_root.head = NULL;

	d = debugfs_create_dir("mpool", NULL);
	if (IS_ERR_OR_NULL(d))
		return;
	evc_root.debug_root = d;

	d = debugfs_create_file("events", 0444, d, NULL, &mpool_debug_fops);
	if (IS_ERR_OR_NULL(d)) {
		debugfs_remove(evc_root.debug_root);
		evc_root.debug_root = NULL;
		return;
	}
}

void evc_fini(void)
{
	const char *modname = "mpool";
	const char *file;
	struct evc *evc;

	spin_lock(&evc_root.lock);
	evc = evc_root.head;
	spin_unlock(&evc_root.lock);

	debugfs_remove_recursive(evc_root.debug_root);

	if (!evc)
		return;

	pr_info("\n%s: %14s %6s %12s  %s\n", modname, "FILE", "LINE", "ODOMETER", "FUNC");

	while (evc) {
		file = strrchr(evc->evc_file, '/');
		file = file ? file + 1 : evc->evc_file;

		pr_info("%s: %14s %6d %12lu  %s\n", modname, file, evc->evc_line,
			(ulong)atomic64_read(&evc->evc_odometer), evc->evc_func);

		evc = evc->evc_next;
	}
}
