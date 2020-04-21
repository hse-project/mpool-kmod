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

/* TODO: The use of the crypto_* routines is going to eventually
 * be replaced by direct calls to select checksumming functions.
 * For now, we extend the life of what we have by allowing it
 * to run in a multi-threaded environment.
 */
#define shash_desc_max      (nr_cpu_ids)

static struct shash_desc  **shash_desc_crc32c;

/* cleared out sb */
struct omf_sb_descriptor SBCLEAR;

/*
 * Slab caches to optimize the allocation/deallocation of
 * high-count objects.
 */
struct kmem_cache  *ecio_layout_desc_cache;
struct kmem_cache  *ecio_layout_mlo_cache;
struct kmem_cache  *u64_to_u64_rb_cache;
struct kmem_cache  *pmd_obj_erase_work_cache;

unsigned int mpc_rsvd_bios_max __read_mostly = 16;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
struct bio_set mpool_bioset;
#else
struct bio_set *mpool_bioset;
#endif

/**
 * shash_desc_alloc() - Allocate a crypto descriptor.
 * @name:
 * @desc:
 *
 * Return: 0 if successful, -(errno) otherwise
 */
static int shash_desc_alloc(const char *name, struct shash_desc **desc)
{
	struct crypto_shash    *tfm;
	struct shash_desc      *d;

	unsigned int   state_size;
	unsigned int   digest_size;

	tfm = crypto_alloc_shash(name, 0, 0);
	if (!tfm) {
		merr_t err = merr(ENOMEM);

		mp_pr_err("crypto_alloc_shash(%s) failed", err, name);
		return -merr_errno(err);
	}

	state_size = crypto_shash_descsize(tfm);
	digest_size = crypto_shash_digestsize(tfm);

	if (digest_size <= 0) {
		merr_t err = merr(EINVAL);

		mp_pr_err("invalid digest size %u", err, digest_size);
		crypto_free_shash(tfm);
		return -merr_errno(err);
	}

	d = kmalloc(sizeof(*d) + state_size, GFP_KERNEL);
	if (!d) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}

	d->tfm = tfm;
	d->flags = 0;

	*desc = d;

	return 0;
}

/**
 * shash_desc_free() - Free a crypto descriptor.
 * @desc:
 *
 */
static void shash_desc_free(struct shash_desc *desc)
{
	if (desc) {
		crypto_free_shash(desc->tfm);
		kfree(desc);
	}
}

/**
 * shash_desc_freeall() - Free all the crypto descriptors.
 *
 */
static void shash_desc_freeall(void)
{
	int i;

	if (shash_desc_crc32c) {
		for (i = 0; i < shash_desc_max; ++i)
			shash_desc_free(shash_desc_crc32c[i]);

		kfree(shash_desc_crc32c);
	}
}

struct shash_desc *shash_desc_get(void)
{
	struct shash_desc  *desc;
	int                 idx;

	/* Disable preemption of this cpu and then get the index
	 * of this cpu's shash descriptor.
	 */
	idx = get_cpu();

	desc = shash_desc_crc32c[idx];

	return desc;
}

void shash_desc_put(struct shash_desc *desc)
{
	put_cpu();
}

static atomic_t mpool_mod_refcnt;

int mpool_mod_init(void)
{
	struct shash_desc  **msd;

	size_t msdsz;
	merr_t err;
	int    rc = 0, i;

	if (atomic_inc_return(&mpool_mod_refcnt) > 1)
		return 0;

	msdsz = sizeof(*msd) * shash_desc_max;

	msd = kmalloc(msdsz, GFP_KERNEL);
	if (!msd) {
		mpool_mod_exit();
		return -ENOMEM;
	}

	memset(msd, 0, msdsz);

	shash_desc_crc32c = msd;

	for (i = 0; i < shash_desc_max; ++i) {
		rc = shash_desc_alloc("crc32c", shash_desc_crc32c + i);
		if (rc) {
			err = merr(rc);
			mp_pr_err("shash desc crc32c alloc %d failed", err, i);
			break;
		}
	}

	if (i < shash_desc_max) {
		mpool_mod_exit();
		return -EINVAL;
	}

	/* prepare the empty sb struct */
	sbutil_mdc0_clear(&SBCLEAR);

	/* Initialize the slab caches. */

	ecio_layout_desc_cache = kmem_cache_create(
		"mpool_ecio_layout_desc",
		sizeof(struct ecio_layout_descriptor),
		0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!ecio_layout_desc_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(ecio desc, %zu) failed",
			  err, sizeof(struct ecio_layout_descriptor));
		mpool_mod_exit();
		return -merr_errno(err);
	}

	/*
	 * mlog only part of the ecio object layout.
	 * Elements can share a cache line because an element is not changed
	 * after the mlog layout is allocated. And an mlog is long lived.
	 */
	ecio_layout_mlo_cache = kmem_cache_create(
		"mpool_ecio_layout_mlo",
		sizeof(struct ecio_layout_mlo),
		0, SLAB_POISON, NULL);

	if (!ecio_layout_mlo_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(ecio mlo, %zu) failed",
			  err, sizeof(struct ecio_layout_mlo));
		mpool_mod_exit();
		return -merr_errno(err);
	}

	u64_to_u64_rb_cache = kmem_cache_create(
		"mpool_u64_to_u64_rb",
		sizeof(struct u64_to_u64_rb),
		0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);

	if (!u64_to_u64_rb_cache) {
		err = merr(ENOMEM);
		mp_pr_err("kmem_cache_create(u64_to_u64_rb, %zu) failed",
			  err, sizeof(struct u64_to_u64_rb));
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
	kmem_cache_destroy(ecio_layout_desc_cache);
	ecio_layout_desc_cache = NULL;
	kmem_cache_destroy(ecio_layout_mlo_cache);
	ecio_layout_mlo_cache = NULL;
	kmem_cache_destroy(u64_to_u64_rb_cache);
	u64_to_u64_rb_cache = NULL;
	kmem_cache_destroy(pmd_obj_erase_work_cache);
	pmd_obj_erase_work_cache = NULL;

	shash_desc_freeall();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	bioset_exit(&mpool_bioset);
#else
	bioset_free(mpool_bioset);
#endif

}
