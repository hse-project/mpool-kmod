/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPCTL_H
#define MPOOL_MPCTL_H

#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/device.h>

#include "mblock.h"
#include "mcache.h"

#define ITERCB_NEXT     (0)
#define ITERCB_DONE     (1)

/* There is one unit object for each device object created by the driver. */
struct mpc_unit {
	struct kref                 un_ref;
	int                         un_open_cnt;    /* Unit open count */
	struct semaphore            un_open_lock;   /* Protects un_open_* */
	bool                        un_open_excl;   /* Unit exclusively open */
	uid_t                       un_uid;
	gid_t                       un_gid;
	mode_t                      un_mode;
	struct mpc_rgnmap           un_rgnmap;
	dev_t                       un_devno;
	const struct mpc_uinfo     *un_uinfo;
	struct mpc_mpool           *un_mpool;
	struct address_space       *un_mapping;
	struct mpc_reap            *un_ds_reap;
	struct device              *un_device;
	struct backing_dev_info    *un_saved_bdi;
	struct mpc_attr            *un_attr;
	uint                        un_rawio;       /* log2(max_mblock_size) */
	u64                         un_ds_oidv[2];
	u32                         un_ra_pages_max;
	u64                         un_mdc_captgt;
	uuid_le                     un_utype;
	u8                          un_label[MPOOL_LABELSZ_MAX];
	char                        un_name[];
};

static inline struct mpc_unit *dev_to_unit(struct device *dev)
{
	return dev_get_drvdata(dev);
}

struct mpc_reap *dev_to_reap(struct device *dev);

merr_t mpctl_init(void);

void mpctl_exit(void);

#endif /* MPOOL_MPCTL_H */
