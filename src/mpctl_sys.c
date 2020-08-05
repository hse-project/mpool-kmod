// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/slab.h>

#include "evc.h"

#include "mpctl_sys.h"

struct mpc_attr *mpc_attr_create(struct device *dev, const char *name, int acnt)
{
	struct mpc_attr *attr;
	int              i;

	attr = kzalloc(sizeof(*attr) + acnt * sizeof(*attr->a_dattr) +
		       (acnt + 1) * sizeof(*attr->a_attrs), GFP_KERNEL);
	if (ev(!attr))
		return NULL;

	attr->a_kobj = &dev->kobj;

	attr->a_dattr = (void *)(attr + 1);

	attr->a_attrs = (void *)(attr->a_dattr + acnt);
	for (i = 0; i < acnt; i++)
		attr->a_attrs[i] = &attr->a_dattr[i].attr;
	attr->a_attrs[i] = NULL;

	attr->a_group.attrs = attr->a_attrs;
	attr->a_group.name = name;

	return attr;
}

void mpc_attr_destroy(struct mpc_attr *attr)
{
	kfree(attr);
}

int mpc_attr_group_create(struct mpc_attr *attr)
{
	return sysfs_create_group(attr->a_kobj, &attr->a_group);
}

void mpc_attr_group_destroy(struct mpc_attr *attr)
{
	sysfs_remove_group(attr->a_kobj, &attr->a_group);
}
