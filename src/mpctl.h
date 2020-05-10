/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPCTL_H
#define MPOOL_MPCTL_H

#include <linux/rbtree.h>

#include <mpcore/mblock.h>

struct mpc_unit;
struct mpc_metamap;

struct mpc_mbinfo {
	struct mblock_descriptor   *mbdesc;
	u32                         mblen;
	u32                         mbmult;
	atomic64_t                  mbatime;
} __aligned(32);

struct mpc_vma {
	struct rb_node              mcm_rnode;
	uint                        mcm_rgn;
	u32                         mcm_magic;
	size_t                      mcm_bktsz;
	uint                        mcm_mbinfoc;
	struct mpool_descriptor    *mcm_mpdesc;
	atomic64_t                 *mcm_hcpagesp;

	struct address_space       *mcm_mapping;
	struct mpc_metamap         *mcm_metamap;
	struct mpc_reap            *mcm_reap;
	struct mpc_unit            *mcm_unit;
	enum mpc_vma_advice         mcm_advice;
	int                         mcm_refcnt;
	struct kmem_cache          *mcm_cache;

	____cacheline_aligned
	struct list_head            mcm_list;
	atomic_t                    mcm_evicting;
	atomic_t                    mcm_reapref;
	atomic_t                   *mcm_freedp;

	____cacheline_aligned
	atomic64_t                  mcm_nrpages;
	atomic_t                    mcm_rabusy;
	struct work_struct          mcm_work;

	____cacheline_aligned
	struct mpc_mbinfo           mcm_mbinfov[];
};

extern unsigned int mpc_vma_size_max;

static inline pgoff_t mpc_vma_pgoff(struct mpc_vma *meta)
{
	return ((ulong)meta->mcm_rgn << mpc_vma_size_max) >> PAGE_SHIFT;
}

static inline size_t mpc_vma_pglen(struct mpc_vma *meta)
{
	return (meta->mcm_bktsz * meta->mcm_mbinfoc) >> PAGE_SHIFT;
}

void mpc_vma_free(struct mpc_vma *meta);

#endif /* MPOOL_MPCTL_H */
