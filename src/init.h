/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Mpool init  module.
 *
 * Global initialization for mpool.
 */

#ifndef MPOOL_INIT_PRIV_H
#define MPOOL_INIT_PRIV_H

#include <linux/version.h>
#include <linux/bio.h>

#include <mpcore/init.h>

extern struct crypto_shash *mpool_tfm;

extern struct kmem_cache *ecio_layout_desc_cache;
extern struct kmem_cache *ecio_layout_mlo_cache; /* mlog only */
extern struct kmem_cache *u64_to_u64_rb_cache;
extern struct kmem_cache *pmd_obj_erase_work_cache;

extern unsigned int mpc_rsvd_bios_max;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
extern struct bio_set mpool_bioset;
#else
extern struct bio_set *mpool_bioset;
#endif

#endif
