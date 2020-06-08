/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPCTL_SYS_H
#define MPOOL_MPCTL_SYS_H

#include <linux/device.h>
#include <linux/sysfs.h>


#define MPC_ATTR(_da, _name, _mode)                \
	(_da)->attr.name = __stringify(_name);     \
	(_da)->attr.mode = (_mode);                \
	(_da)->show      = mpc_##_name##_show      \

#define MPC_ATTR_RO(_dattr, _name)                 \
	do {                                       \
		__typeof(_dattr) da = (_dattr);    \
		MPC_ATTR(da, _name, 0444);         \
		da->store = NULL;                  \
	} while (0)

#define MPC_ATTR_RW(_dattr, _name)                 \
	do {                                       \
		__typeof(_dattr) da = (_dattr);    \
		MPC_ATTR(da, _name, 0644);         \
		da->store = mpc_##_name##_store;   \
	} while (0)


struct mpc_attr {
	struct attribute_group       a_group;
	struct kobject              *a_kobj;
	struct device_attribute     *a_dattr;
	struct attribute           **a_attrs;
};

struct mpc_attr *mpc_attr_create(struct device *d, const char *name, int acnt);

void mpc_attr_destroy(struct mpc_attr *attr);

int mpc_attr_group_create(struct mpc_attr *attr);

void mpc_attr_group_destroy(struct mpc_attr *attr);

#endif /* MPOOL_MPCTL_SYS_H */
