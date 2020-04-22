// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>

#include <mpcore/merr.h>
#include <mpcore/evc.h>
#include <mpcore/uuid.h>

#include "mpctl_params.h"


int
mpc_mode_proc_handler(
	struct ctl_table   *tab,
	int                 write,
	void        __user *buffer,
	size_t             *lenp,
	loff_t             *ppos)
{
	char    mode[6] = { };
	void   *data;
	int     maxlen;
	int     rc;

	if (ev(write))
		return 0;

	data   = tab->data;
	maxlen = tab->maxlen;

	snprintf(mode, sizeof(mode), "0%o", *((int *)data));
	tab->data   = mode;
	tab->maxlen = sizeof(mode);

	rc = proc_dostring(tab, write, buffer, lenp, ppos);

	tab->data   = data;
	tab->maxlen = maxlen;

	return rc;
}

int
mpc_uuid_proc_handler(
	struct ctl_table   *tab,
	int                 write,
	void        __user *buffer,
	size_t             *lenp,
	loff_t             *ppos)
{
	struct mpool_uuid  uuid;

	char    uuid_str[MPOOL_UUID_STRING_LEN + 1] = { };
	void   *data;
	int     maxlen;
	int     rc;

	if (ev(write))
		return 0;

	data   = tab->data;
	maxlen = tab->maxlen;

	memcpy(uuid.uuid, (char *)data, MPOOL_UUID_SIZE);
	mpool_unparse_uuid(&uuid, uuid_str);
	tab->data   = uuid_str;
	tab->maxlen = sizeof(uuid_str);

	rc = proc_dostring(tab, write, buffer, lenp, ppos);

	tab->data   = data;
	tab->maxlen = maxlen;

	return rc;
}

struct ctl_table_header *mpc_sysctl_register(struct ctl_table *root)
{
	return register_sysctl_table(root);
}

void mpc_sysctl_unregister(struct ctl_table_header *hdr)
{
	if (ev(!hdr))
		return;
	unregister_sysctl_table(hdr);
}

merr_t
mpc_sysctl_path(
	struct ctl_table   *root,
	struct ctl_table   *comp1,
	struct ctl_table   *comp2,
	struct ctl_table   *oid,
	const char         *c2name,
	umode_t             mode)
{
	if (ev(!root || !comp1 || !oid))
		return merr(EINVAL);

	root->procname = "dev";
	root->mode = mode;
	root->child = comp1;

	comp1->procname = "mpool";
	comp1->mode = mode;
	comp1->child = comp2 ? comp2 : oid;

	if (comp2) {
		comp2->procname = c2name;
		comp2->mode = mode;
		comp2->child = oid;
	}

	return 0;
}

void
mpc_sysctl_oid(
	struct ctl_table   *oid,
	const char         *name,
	umode_t             mode,
	void               *data,
	size_t              sz,
	proc_handler        handler)
{
	oid->procname = name;
	oid->data     = data;
	oid->mode     = mode;
	oid->maxlen   = sz;
	oid->proc_handler = handler;
}

void
mpc_sysctl_oid_minmax(
	struct ctl_table   *oid,
	const char         *name,
	umode_t             mode,
	void               *data,
	size_t              sz,
	proc_handler        handler,
	void               *min,
	void               *max)
{
	mpc_sysctl_oid(oid, name, mode, data, sz, handler);
	oid->extra1 = min;
	oid->extra2 = max;
}
