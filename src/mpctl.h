/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPCTL_H
#define MPOOL_MPCTL_H

#include <linux/rbtree.h>
#include <linux/kref.h>

#include "mblock.h"

struct mpc_unit;
struct mpc_rgnmap;

extern uint mpc_chunker_size;

struct mpc_mbinfo {
	struct mblock_descriptor   *mbdesc;
	u32                         mblen;
	u32                         mbmult;
	atomic64_t                  mbatime;
} __aligned(32);

struct mpc_xvm {
	size_t                      xvm_bktsz;
	uint                        xvm_mbinfoc;
	uint                        xvm_rgn;
	struct kref                 xvm_ref;
	u32                         xvm_magic;
	struct mpool_descriptor    *xvm_mpdesc;

	atomic64_t                 *xvm_hcpagesp;
	struct address_space       *xvm_mapping;
	struct mpc_rgnmap          *xvm_rgnmap;
	struct mpc_reap            *xvm_reap;

	enum mpc_vma_advice         xvm_advice;
	atomic_t                    xvm_opened;
	struct kmem_cache          *xvm_cache;
	struct mpc_xvm             *xvm_next;

	____cacheline_aligned
	struct list_head            xvm_list;
	atomic_t                    xvm_evicting;
	atomic_t                    xvm_reapref;
	atomic_t                   *xvm_freedp;

	____cacheline_aligned
	atomic64_t                  xvm_nrpages;
	atomic_t                    xvm_rabusy;
	struct work_struct          xvm_work;

	____cacheline_aligned
	struct mpc_mbinfo           xvm_mbinfov[];
};

extern unsigned int mpc_xvm_size_max;

static inline pgoff_t mpc_xvm_pgoff(struct mpc_xvm *xvm)
{
	return ((ulong)xvm->xvm_rgn << mpc_xvm_size_max) >> PAGE_SHIFT;
}

static inline size_t mpc_xvm_pglen(struct mpc_xvm *xvm)
{
	return (xvm->xvm_bktsz * xvm->xvm_mbinfoc) >> PAGE_SHIFT;
}

void mpc_xvm_free(struct mpc_xvm *xvm);

static inline struct mpc_unit *dev_to_unit(struct device *dev)
{
	return dev_get_drvdata(dev);
}

struct mpc_reap *dev_to_reap(struct device *dev);

#endif /* MPOOL_MPCTL_H */
