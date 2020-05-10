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

#include <linux/version.h>
#include <linux/bio.h>

extern struct crypto_shash *mpool_tfm;

extern struct kmem_cache *pmd_obj_erase_work_cache;
extern struct kmem_cache *pmd_layout_priv_cache;
extern struct kmem_cache *pmd_layout_cache;
extern struct kmem_cache *smap_zone_cache;

extern unsigned int mpc_rsvd_bios_max;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
extern struct bio_set mpool_bioset;
#else
extern struct bio_set *mpool_bioset;
#endif

/**
 * mpool_mod_init() - mpool module initialization function
 *
 * Return: 0 if successful, -(errno) otherwise
 */
int mpool_mod_init(void);

/**
 * mpool_mod_exit() - mpool module exit function
 *
 */
void mpool_mod_exit(void);

#endif /* MPOOL_INIT_H */
