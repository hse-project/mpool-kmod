/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPCTL_PARAMS_H
#define MPCTL_PARAMS_H

#include <linux/sysctl.h>

#define MPC_SYSCTL_RCNT    2
#define MPC_SYSCTL_DCNT    2

#define MPC_SYSCTL_DMODE   0555

struct ctl_table_header *mpc_sysctl_register(struct ctl_table *root);

void mpc_sysctl_unregister(struct ctl_table_header *hdr);

merr_t
mpc_sysctl_path(
	struct ctl_table   *root,
	struct ctl_table   *comp1,
	struct ctl_table   *comp2,
	struct ctl_table   *oid,
	const char         *c2name,
	umode_t             mode);

void
mpc_sysctl_oid(
	struct ctl_table   *oid,
	const char         *name,
	umode_t             mode,
	void               *data,
	size_t              sz,
	proc_handler        handler);

void
mpc_sysctl_oid_minmax(
	struct ctl_table   *oid,
	const char         *name,
	umode_t             mode,
	void               *data,
	size_t              sz,
	proc_handler        handler,
	void               *min,
	void               *max);

int
mpc_mode_proc_handler(
	struct ctl_table   *tab,
	int                 write,
	void        __user *buffer,
	size_t             *lenp,
	loff_t             *ppos);

int
mpc_uuid_proc_handler(
	struct ctl_table   *tab,
	int                 write,
	void        __user *buffer,
	size_t             *lenp,
	loff_t             *ppos);

#endif /* MPCTL_PARAMS_H */
