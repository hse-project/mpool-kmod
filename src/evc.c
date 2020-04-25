// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/version.h>

#include <mpcore/evc.h>

static struct {
	spinlock_t  lock;
	struct evc *head;
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

void evc_init(void)
{
	spin_lock_init(&evc_root.lock);
	evc_root.head = NULL;
}

/* TODO: Wire this up to a sysctl proc rather than module unload...
 */
void evc_fini(void)
{
	const char *modname = "mpool";
	const char *file;
	struct evc *evc;

	spin_lock(&evc_root.lock);
	evc = evc_root.head;
	spin_unlock(&evc_root.lock);

	if (!evc)
		return;

	printk("\n%s: %16s %6s %16s %10s\n",
	       modname, "FILE", "LINE", "FUNC", "ODOMETER");

	while (evc) {
		file = strrchr(evc->evc_file, '/');
		file = file ? file + 1 : evc->evc_file;

		printk("%s: %16s %6d %16s %10lu\n",
		       modname, file, evc->evc_line, evc->evc_func,
		       (ulong)atomic64_read(&evc->evc_odometer));

		evc = evc->evc_next;
	}
}
