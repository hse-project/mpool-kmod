// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/version.h>
#include <linux/gfp.h>
#include <linux/slab.h>

#include <mpcore/evc.h>
#include <mpcore/merr.h>
#include <mpcore/mpcore_printk.h>
#include "mpctl_params.h"

static struct {
	spinlock_t                  lock;
	struct evc                 *head;

	____cacheline_aligned
	struct ctl_table_header    *hdr;
	struct ctl_table           *tab;
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

int
evc_proc_handler(
	struct ctl_table   *tab,
	int                 write,
	void        __user *buffer,
	size_t             *lenp,
	loff_t             *ppos)
{
	char       *data, *evstr = NULL, *pos;
	const char *file;
	struct evc *evc;
	int         cc, rc, maxlen;

	if (write)
		return 0;

	data = tab->data;
	maxlen = tab->maxlen;

	spin_lock(&evc_root.lock);
	evc = evc_root.head;
	spin_unlock(&evc_root.lock);
	if (!evc)
		goto exit;

	evstr = (char *)get_zeroed_page(GFP_KERNEL);
	if (!evstr)
		return -ENOMEM;

	pos = evstr;
	cc = snprintf(pos, PAGE_SIZE, "%14s %6s %12s  %s",
		      "FILE", "LINE", "ODOMETER", "FUNC");
	pos += cc;
	while (evc && ((pos - evstr) < PAGE_SIZE - 1)) {
		file = strrchr(evc->evc_file, '/');
		file = file ? file + 1 : evc->evc_file;

		cc = snprintf(pos, PAGE_SIZE - (pos - evstr),
			      "\n%14s %6d %12lu  %s",
			      file, evc->evc_line,
			      (ulong)atomic64_read(&evc->evc_odometer),
			      evc->evc_func);

		evc = evc->evc_next;
		pos += cc;
	}

	if (evc)
		mp_pr_info("Insufficient buffer space to dump all events");

	tab->data = evstr;
	tab->maxlen = PAGE_SIZE;

exit:
	rc = proc_dostring(tab, write, buffer, lenp, ppos);

	tab->data = data;
	tab->maxlen = maxlen;

	if (evstr)
		free_page((unsigned long)evstr);

	return rc;
}

void evc_init(void)
{
	struct ctl_table   *tab, *oid;
	int                 compc, tabc, oidc;
	merr_t              err;
	static char        *noev = "No Events";

	spin_lock_init(&evc_root.lock);
	evc_root.head = NULL;

	compc = MPC_SYSCTL_RCNT + MPC_SYSCTL_DCNT;
	oidc  = 2;
	tabc  = compc + oidc;

	tab = kcalloc(tabc, sizeof(*tab), GFP_KERNEL);
	if (!tab)
		return;

	oid = tab + compc;

	err = mpc_sysctl_path(tab, tab + MPC_SYSCTL_RCNT, NULL, oid, NULL,
			      MPC_SYSCTL_DMODE);
	if (err)
		goto errout;

	mpc_sysctl_oid(oid, "events", 0444, noev, strlen(noev),
		       evc_proc_handler);

	evc_root.hdr = mpc_sysctl_register(tab);
	if (!evc_root.hdr)
		goto errout;

	evc_root.tab = tab;

	return;

errout:
	kfree(tab);
}

void evc_fini(void)
{
	const char *modname = "mpool";
	const char *file;
	struct evc *evc;

	spin_lock(&evc_root.lock);
	evc = evc_root.head;
	spin_unlock(&evc_root.lock);

	if (!evc)
		goto exit;

	printk("\n%s: %14s %6s %12s  %s\n",
	       modname, "FILE", "LINE", "ODOMETER", "FUNC");

	while (evc) {
		file = strrchr(evc->evc_file, '/');
		file = file ? file + 1 : evc->evc_file;

		printk("%s: %14s %6d %12lu  %s\n",
		       modname, file, evc->evc_line,
		       (ulong)atomic64_read(&evc->evc_odometer),
		       evc->evc_func);

		evc = evc->evc_next;
	}

exit:
	mpc_sysctl_unregister(evc_root.hdr);
	kfree(evc_root.tab);
}
