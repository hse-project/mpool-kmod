// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <crypto/hash.h>

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
struct kmem_cache  *pmd_layout_mlo_cache __read_mostly;
struct kmem_cache  *pmd_layout_cache __read_mostly;
struct kmem_cache  *smap_zone_cache __read_mostly;

unsigned int mpc_rsvd_bios_max __read_mostly = 16;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
struct bio_set mpool_bioset;
#else
struct bio_set *mpool_bioset;
#endif

static atomic_t mpool_mod_refcnt;

int mpool_mod_init(void)
{
	const char *algo = "crc32c";
	merr_t      err;
	int         rc = 0;

	if (atomic_inc_return(&mpool_mod_refcnt) > 1)
		return 0;

	mpool_tfm = crypto_alloc_shash(algo, 0, 0);
	if (!mpool_tfm) {
		err = merr(ENOMEM);
		mp_pr_err("crypto_alloc_shash(%s) failed", err, algo);
		mpool_mod_exit();
		return -merr_errno(err);
	}

	/* prepare the empty sb struct */
	sbutil_mdc0_clear(&SBCLEAR);

	/* Initialize the slab caches. */
	pmd_layout_cache = kmem_cache_create(
		"mpool_pmd_layout",
		sizeof(struct pmd_layout),
		0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!pmd_layout_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(pmd_layout, %zu) failed",
			  err, sizeof(struct pmd_layout));
		mpool_mod_exit();
		return -merr_errno(err);
	}

	/*
	 * mlog only part of the pmd object layout.
	 * Elements can share a cache line because an element is not changed
	 * after the mlog layout is allocated. And an mlog is long lived.
	 */
	pmd_layout_mlo_cache = kmem_cache_create(
		"mpool_pmd_layout_mlo",
		sizeof(struct pmd_layout_mlo),
		0, SLAB_POISON, NULL);

	if (!pmd_layout_mlo_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(pmd mlo, %zu) failed",
			  err, sizeof(struct pmd_layout_mlo));
		mpool_mod_exit();
		return -merr_errno(err);
	}

	smap_zone_cache = kmem_cache_create(
		"mpool_smap_zone",
		sizeof(struct smap_zone),
		0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!smap_zone_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(smap_zone, %zu) failed",
			  err, sizeof(struct smap_zone));
		mpool_mod_exit();
		return -merr_errno(err);
	}

	pmd_obj_erase_work_cache = kmem_cache_create(
		"mpool_pmd_obj_erase_work",
		sizeof(struct pmd_obj_erase_work),
		0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!pmd_obj_erase_work_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(pmd_obj_erase, %zu) failed",
			  err, sizeof(struct pmd_obj_erase_work));
		mpool_mod_exit();
		return -merr_errno(ENOMEM);
	}

	mpc_rsvd_bios_max = clamp_t(uint, mpc_rsvd_bios_max, 1, 1024);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	rc = bioset_init(&mpool_bioset, mpc_rsvd_bios_max, 0,
			 BIOSET_NEED_BVECS);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
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
		mpool_mod_exit();
		return rc;
	}

	return 0;
}

void mpool_mod_exit(void)
{
	assert(atomic_read(&mpool_mod_refcnt) > 0);

	if (atomic_dec_return(&mpool_mod_refcnt) > 0)
		return;

	/* Destroy the slab caches. */
	kmem_cache_destroy(pmd_obj_erase_work_cache);
	kmem_cache_destroy(pmd_layout_mlo_cache);
	kmem_cache_destroy(pmd_layout_cache);
	kmem_cache_destroy(smap_zone_cache);

	pmd_obj_erase_work_cache = NULL;
	pmd_layout_mlo_cache = NULL;
	pmd_layout_cache = NULL;
	smap_zone_cache = NULL;

	if (mpool_tfm)
		crypto_free_shash(mpool_tfm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	bioset_exit(&mpool_bioset);
#else
	bioset_free(mpool_bioset);
#endif

}
