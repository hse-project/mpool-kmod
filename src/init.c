// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <crypto/hash.h>

#include "mpool_config.h"
#include "mpcore_defs.h"

/*
 * Init functions
 */

/* Global contexts */

struct crypto_shash *mpool_tfm;

/* cleared out sb */
struct omf_sb_descriptor SBCLEAR;

/*
 * Slab caches to optimize the allocation/deallocation of
 * high-count objects.
 */
struct kmem_cache  *pmd_obj_erase_work_cache __read_mostly;
struct kmem_cache  *pmd_layout_priv_cache __read_mostly;
struct kmem_cache  *pmd_layout_cache __read_mostly;
struct kmem_cache  *smap_zone_cache __read_mostly;

unsigned int mpc_rsvd_bios_max __read_mostly = 16;

#if HAVE_BIOSET_INIT
struct bio_set mpool_bioset;
#else
struct bio_set *mpool_bioset;
#endif

int mpcore_init(void)
{
	const char *algo = "crc32c";
	merr_t      err;
	int         rc = 0;

	mpool_tfm = crypto_alloc_shash(algo, 0, 0);
	if (!mpool_tfm) {
		err = merr(ENOMEM);
		mp_pr_err("crypto_alloc_shash(%s) failed", err, algo);
		mpcore_fini();
		return -merr_errno(err);
	}

	/* prepare the empty sb struct */
	sbutil_mdc0_clear(&SBCLEAR);

	/* Initialize the slab caches. */
	pmd_layout_cache = kmem_cache_create("mpool_pmd_layout", sizeof(struct pmd_layout),
					     0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!pmd_layout_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(pmd_layout, %zu) failed",
			  err, sizeof(struct pmd_layout));
		mpcore_fini();
		return -merr_errno(err);
	}

	pmd_layout_priv_cache = kmem_cache_create("mpool_pmd_layout_priv",
				sizeof(struct pmd_layout) + sizeof(union pmd_layout_priv),
				0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!pmd_layout_priv_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(pmd priv, %zu) failed",
			  err, sizeof(union pmd_layout_priv));
		mpcore_fini();
		return -merr_errno(err);
	}

	smap_zone_cache = kmem_cache_create("mpool_smap_zone", sizeof(struct smap_zone),
					    0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!smap_zone_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(smap_zone, %zu) failed",
			  err, sizeof(struct smap_zone));
		mpcore_fini();
		return -merr_errno(err);
	}

	pmd_obj_erase_work_cache = kmem_cache_create("mpool_pmd_obj_erase_work",
						     sizeof(struct pmd_obj_erase_work),
						     0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!pmd_obj_erase_work_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(pmd_obj_erase, %zu) failed",
			  err, sizeof(struct pmd_obj_erase_work));
		mpcore_fini();
		return -merr_errno(ENOMEM);
	}

	mpc_rsvd_bios_max = clamp_t(uint, mpc_rsvd_bios_max, 1, 1024);

#if HAVE_BIOSET_INIT
	rc = bioset_init(&mpool_bioset, mpc_rsvd_bios_max, 0, BIOSET_NEED_BVECS);
#elif HAVE_BIOSET_CREATE_3
	mpool_bioset = bioset_create(mpc_rsvd_bios_max, 0, BIOSET_NEED_BVECS);
	if (!mpool_bioset)
		rc = -ENOMEM;
#else
	mpool_bioset = bioset_create(mpc_rsvd_bios_max, 0);
	if (!mpool_bioset)
		rc = -ENOMEM;
#endif
	if (rc) {
		err = merr(rc);
		mp_pr_err("mpool bioset init failed", err);
		mpcore_fini();
		return rc;
	}

	return 0;
}

void mpcore_fini(void)
{
	kmem_cache_destroy(pmd_obj_erase_work_cache);
	kmem_cache_destroy(pmd_layout_priv_cache);
	kmem_cache_destroy(pmd_layout_cache);
	kmem_cache_destroy(smap_zone_cache);

	pmd_obj_erase_work_cache = NULL;
	pmd_layout_priv_cache = NULL;
	pmd_layout_cache = NULL;
	smap_zone_cache = NULL;

	if (mpool_tfm)
		crypto_free_shash(mpool_tfm);

#if HAVE_BIOSET_INIT
	bioset_exit(&mpool_bioset);
#else
	bioset_free(mpool_bioset);
#endif
}
