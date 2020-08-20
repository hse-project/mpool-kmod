/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MCACHE_H
#define MPOOL_MCACHE_H

#include <linux/kref.h>

#include "init.h"
#include "mblock.h"

struct mpc_unit;

/**
 * struct mpc_rgnmap - xvm region management
 * @rm_lock:    protects rm_root
 * @rm_root:    root of the region map
 * @rm_rgncnt;  number of active regions
 *
 * Note that this is not a ref-counted object, its lifetime
 * is tied to struct mpc_unit.
 */
struct mpc_rgnmap {
	struct mutex    rm_lock;
	struct idr      rm_root;
	atomic_t        rm_rgncnt;
} ____cacheline_aligned;


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

extern struct mpc_reap *mpc_reap;
extern const struct address_space_operations mpc_aops_default;

void mpc_rgnmap_flush(struct mpc_rgnmap *rm);

int mpc_mmap(struct file *fp, struct vm_area_struct *vma);

merr_t mpioc_xvm_create(struct mpc_unit *unit, struct mpool_descriptor *mp, struct mpioc_vma *ioc);

merr_t mpioc_xvm_destroy(struct mpc_unit *unit, struct mpioc_vma *ioc);

merr_t mpioc_xvm_purge(struct mpc_unit *unit, struct mpioc_vma *ioc);

merr_t mpioc_xvm_vrss(struct mpc_unit *unit, struct mpioc_vma *ioc);

merr_t mcache_init(void);

void mcache_exit(void);

static inline pgoff_t mpc_xvm_pgoff(struct mpc_xvm *xvm)
{
	return ((ulong)xvm->xvm_rgn << mpc_xvm_size_max) >> PAGE_SHIFT;
}

static inline size_t mpc_xvm_pglen(struct mpc_xvm *xvm)
{
	return (xvm->xvm_bktsz * xvm->xvm_mbinfoc) >> PAGE_SHIFT;
}

void mpc_xvm_free(struct mpc_xvm *xvm);

#endif /* MPOOL_MCACHE_H */
