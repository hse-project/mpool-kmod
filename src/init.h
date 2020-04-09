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

#include <mpcore/init.h>

/* TODO: forward decls */
struct shash_desc;

extern struct kmem_cache *ecio_layout_desc_cache;
extern struct kmem_cache *ecio_layout_mlo_cache; /* mlog only */
extern struct kmem_cache *uuid_to_idx_rb_cache;
extern struct kmem_cache *u64_to_u64_rb_cache;
extern struct kmem_cache *pmd_obj_erase_work_cache;
extern struct kmem_cache *chunker_cache[MPOOL_CHUNKER_CACHE_MAX];

/**
 * shash_desc_get() - Acquire a crc32c crypto descriptor from the pool
 *                    of crypto descriptors.
 *
 * The thread that calls shash_desc_get() must be the exact same thread
 * that calls shash_desc_put() for a given descriptor.
 *
 * Return: Pointer to a locked/referenced descriptor.
 */
struct shash_desc *shash_desc_get(void);

/**
 * shash_desc_put() -
 * @desc:
 *
 */
void shash_desc_put(struct shash_desc *desc);

#endif
