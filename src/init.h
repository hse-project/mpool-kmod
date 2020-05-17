/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Mpool init  module.
 *
 * Global initialization for mpool.
 */

#ifndef MPOOL_INIT_H
#define MPOOL_INIT_H

#include <linux/bio.h>

#include "mpool_config.h"

extern struct crypto_shash *mpool_tfm;

extern struct kmem_cache *pmd_obj_erase_work_cache;
extern struct kmem_cache *pmd_layout_priv_cache;
extern struct kmem_cache *pmd_layout_cache;
extern struct kmem_cache *smap_zone_cache;

extern unsigned int mpc_rsvd_bios_max;

#if HAVE_BIOSET_INIT
extern struct bio_set mpool_bioset;
#else
extern struct bio_set *mpool_bioset;
#endif

int mpcore_init(void);
void mpcore_fini(void);

#endif /* MPOOL_INIT_H */
