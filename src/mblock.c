// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * DOC: Module info.
 *
 * Mblock module.
 *
 * Defines functions for writing, reading, and managing the lifecycle
 * of mblocks.
 *
 */

#include <linux/vmalloc.h>
#include <linux/blk_types.h>
#include <linux/mm.h>

#include "mpool_printk.h"
#include "assert.h"

#include "pd.h"
#include "pmd_obj.h"
#include "mpcore.h"
#include "mblock.h"

/**
 * mblock2layout() - convert opaque mblock handle to pmd_layout
 *
 * This function converts the opaque handle (mblock_descriptor) used by
 * clients to the internal representation (pmd_layout).  The
 * conversion is a simple cast, followed by a sanity check to verify the
 * layout object is an mblock object.  If the validation fails, a NULL
 * pointer is returned.
 */
static struct pmd_layout *mblock2layout(struct mblock_descriptor *mbh)
{
	struct pmd_layout *layout = (void *)mbh;

	if (!layout)
		return NULL;

	WARN_ONCE(layout->eld_objid == 0 || kref_read(&layout->eld_ref) < 2,
		  "%s: %p, objid %lx, state %x, refcnt %ld\n",
		  __func__, layout, (ulong)layout->eld_objid,
		  layout->eld_state, (long)kref_read(&layout->eld_ref));

	return mblock_objid(layout->eld_objid) ? layout : NULL;
}

static u32 mblock_optimal_iosz_get(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct mpool_dev_info *pd = pmd_layout_pd_get(mp, layout);

	return pd->pdi_optiosz;
}

/**
 * layout2mblock() - convert pmd_layout to opaque mblock_descriptor
 *
 * This function converts the internally used pmd_layout to
 * the externally used opaque mblock_descriptor.
 */
static struct mblock_descriptor *layout2mblock(struct pmd_layout *layout)
{
	return (struct mblock_descriptor *)layout;
}

static void
mblock_getprops_cmn(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	struct mblock_props        *prop)
{
	struct mpool_dev_info *pd;

	assert(layout);
	assert(prop);

	pd = pmd_layout_pd_get(mp, layout);

	prop->mpr_objid = layout->eld_objid;
	prop->mpr_alloc_cap = pmd_layout_cap_get(mp, layout);
	prop->mpr_write_len = layout->eld_mblen;
	prop->mpr_optimal_wrsz = mblock_optimal_iosz_get(mp, layout);
	prop->mpr_mclassp = pd->pdi_mclass;
	prop->mpr_iscommitted = layout->eld_state & PMD_LYT_COMMITTED;
}

static int
mblock_alloc_cmn(
	struct mpool_descriptor     *mp,
	u64                          objid,
	enum mp_media_classp         mclassp,
	bool                         spare,
	struct mblock_props         *prop,
	struct mblock_descriptor   **mbh)
{
	struct pmd_layout      *layout = NULL;
	struct pmd_obj_capacity ocap;
	int rc;

	if (!mp)
		return -EINVAL;

	*mbh = NULL;

	ocap.moc_captgt = 0;
	ocap.moc_spare  = spare;

	if (!objid) {
		rc = pmd_obj_alloc(mp, OMF_OBJ_MBLOCK, &ocap, mclassp, &layout);
		if (rc)
			return rc;
	} else {
		rc = pmd_obj_realloc(mp, objid, &ocap, mclassp, &layout);
		if (rc) {
			if (rc != -ENOENT)
				mp_pr_err("mpool %s, re-allocating mblock 0x%lx failed",
					  rc, mp->pds_name, (ulong)objid);
			return rc;
		}
	}

	if (!layout)
		return -ENOTRECOVERABLE;

	if (prop) {
		pmd_obj_rdlock(layout);
		mblock_getprops_cmn(mp, layout, prop);
		pmd_obj_rdunlock(layout);
	}

	*mbh = layout2mblock(layout);

	return 0;
}

int
mblock_alloc(
	struct mpool_descriptor     *mp,
	enum mp_media_classp         mclassp,
	bool                         spare,
	struct mblock_descriptor   **mbh,
	struct mblock_props         *prop)
{
	return mblock_alloc_cmn(mp, 0, mclassp, spare, prop, mbh);
}

int
mblock_find_get(
	struct mpool_descriptor    *mp,
	u64                         objid,
	int                         which,
	struct mblock_props        *prop,
	struct mblock_descriptor  **mbh)
{
	struct pmd_layout *layout;

	*mbh = NULL;

	if (!mblock_objid(objid))
		return -EINVAL;

	layout = pmd_obj_find_get(mp, objid, which);
	if (!layout)
		return -ENOENT;

	if (prop) {
		pmd_obj_rdlock(layout);
		mblock_getprops_cmn(mp, layout, prop);
		pmd_obj_rdunlock(layout);
	}

	*mbh = layout2mblock(layout);

	return 0;
}

void mblock_put(struct mblock_descriptor *mbh)
{
	struct pmd_layout *layout;

	layout = mblock2layout(mbh);
	if (layout)
		pmd_obj_put(layout);
}

/*
 * Helper function to log a message that many functions need to log:
 */
#define mp_pr_layout_not_found(_mp, _mbh)				\
do {									\
	static unsigned long state;					\
	uint dly = msecs_to_jiffies(1000);				\
									\
	if (printk_timed_ratelimit(&state, dly)) {			\
		mp_pr_warn("mpool %s, layout not found: mbh %p",	\
			   (_mp)->pds_name, (_mbh));			\
		dump_stack();						\
	}								\
} while (0)

int mblock_commit(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct pmd_layout     *layout;
	struct mpool_dev_info *pd;
	int rc;

	layout = mblock2layout(mbh);
	if (!layout) {
		mp_pr_layout_not_found(mp, mbh);
		return -EINVAL;
	}

	pd = pmd_layout_pd_get(mp, layout);
	if (!pd->pdi_fua) {
		rc = pd_dev_flush(&pd->pdi_parm);
		if (rc)
			return rc;
	}

	/* Commit will fail with EBUSY if aborting flag set. */
	rc = pmd_obj_commit(mp, layout);
	if (rc) {
		mp_pr_rl("mpool %s, committing mblock 0x%lx failed",
			 rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	return 0;
}

int mblock_abort(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct pmd_layout *layout;
	int rc;

	layout = mblock2layout(mbh);
	if (!layout) {
		mp_pr_layout_not_found(mp, mbh);
		return -EINVAL;
	}

	rc = pmd_obj_abort(mp, layout);
	if (rc) {
		mp_pr_err("mpool %s, aborting mblock 0x%lx failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	return 0;
}

int mblock_delete(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct pmd_layout *layout;

	layout = mblock2layout(mbh);
	if (!layout) {
		mp_pr_layout_not_found(mp, mbh);
		return -EINVAL;
	}

	return pmd_obj_delete(mp, layout);
}

/**
 * mblock_rw_argcheck() -
 * @mp:      - Mpool descriptor
 * @layout:  - Layout of the mblock
 * @iov:     - iovec array
 * @iovcnt:  - iovec count
 * @boff:    - Byte offset into the layout.  Must be equal to layout->eld_mblen
 *             for write
 * @rw:      - MPOOL_OP_READ or MPOOL_OP_WRITE
 * @len:     - number of bytes in iov list
 *
 * Validate mblock_write() and mblock_read()
 *
 * Returns: 0 if successful, -errno otherwise
 *
 * Note: be aware that there are checks in this function that prevent illegal
 * arguments in lower level functions (lower level functions should assert the
 * requirements but not otherwise check them)
 */
static int
mblock_rw_argcheck(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	loff_t                      boff,
	int                         rw,
	size_t                      len)
{
	u64 opt_iosz;
	u32 mblock_cap;
	int rc;

	mblock_cap = pmd_layout_cap_get(mp, layout);
	opt_iosz = mblock_optimal_iosz_get(mp, layout);

	if (rw == MPOOL_OP_READ) {
		/* boff must be a multiple of the OS page size */
		if (!PAGE_ALIGNED(boff)) {
			rc = -EINVAL;
			mp_pr_err("mpool %s, read offset 0x%lx is not multiple of OS page size",
				  rc, mp->pds_name, (ulong) boff);
			return rc;
		}

		/* Check that boff is not past end of mblock capacity. */
		if (mblock_cap <= boff) {
			rc = -EINVAL;
			mp_pr_err("mpool %s, read offset 0x%lx >= mblock capacity 0x%x",
				  rc, mp->pds_name, (ulong)boff, mblock_cap);
			return rc;
		}

		/*
		 * Check that the request does not extend past the data
		 * written.  Don't record an error if this appears to
		 * be an mcache readahead request.
		 *
		 * TODO: Use (len != MCACHE_RA_PAGES_MAX)
		 */
		if (boff + len > layout->eld_mblen)
			return -EINVAL;
	} else {
		/* Write boff required to match eld_mblen */
		if (boff != layout->eld_mblen) {
			rc = -EINVAL;
			mp_pr_err("mpool %s write boff (%ld) != eld_mblen (%d)",
				  rc, mp->pds_name, (ulong)boff, layout->eld_mblen);
			return rc;
		}

		/* Writes must be optimal iosz aligned */
		if (boff % opt_iosz) {
			rc = -EINVAL;
			mp_pr_err("mpool %s, write not optimal iosz aligned, offset 0x%lx",
				  rc, mp->pds_name, (ulong)boff);
			return rc;
		}

		/* Check for write past end of allocated space (!) */
		if ((len + boff) > mblock_cap) {
			rc = -EINVAL;
			mp_pr_err("(write): len %lu + boff %lu > mblock_cap %lu",
				  rc, (ulong)len, (ulong)boff, (ulong)mblock_cap);
			return rc;
		}
	}

	return 0;
}

int mblock_write(struct mpool_descriptor *mp, struct mblock_descriptor *mbh,
		 const struct kvec *iov, int iovcnt, size_t len)
{
	struct pmd_layout *layout;
	loff_t boff;
	u8 state;
	int rc;

	layout = mblock2layout(mbh);
	if (!layout) {
		mp_pr_layout_not_found(mp, mbh);
		return -EINVAL;
	}

	rc = mblock_rw_argcheck(mp, layout, layout->eld_mblen, MPOOL_OP_WRITE, len);
	if (rc) {
		mp_pr_debug("mblock write argcheck failed ", rc);
		return rc;
	}

	if (len == 0)
		return 0;

	boff = layout->eld_mblen;

	assert(PAGE_ALIGNED(len));
	assert(iovcnt == (len >> PAGE_SHIFT));
	assert(PAGE_ALIGNED(boff));

	pmd_obj_wrlock(layout);
	state = layout->eld_state;
	if (!(state & PMD_LYT_COMMITTED)) {
		struct mpool_dev_info *pd = pmd_layout_pd_get(mp, layout);
		int                    flags = 0;

		if (pd->pdi_fua)
			flags = REQ_FUA;

		rc = pmd_layout_rw(mp, layout, iov, iovcnt, boff, flags, MPOOL_OP_WRITE);
		if (!rc)
			layout->eld_mblen += len;
	}
	pmd_obj_wrunlock(layout);

	return !(state & PMD_LYT_COMMITTED) ? rc : -EALREADY;
}

int mblock_read(struct mpool_descriptor *mp, struct mblock_descriptor *mbh,
		const struct kvec *iov, int iovcnt, loff_t boff, size_t len)
{
	struct pmd_layout *layout;
	u8 state;
	int rc;

	assert(mp);

	layout = mblock2layout(mbh);
	if (!layout) {
		mp_pr_layout_not_found(mp, mbh);
		return -EINVAL;
	}

	rc = mblock_rw_argcheck(mp, layout, boff, MPOOL_OP_READ, len);
	if (rc) {
		mp_pr_debug("mblock read argcheck failed ", rc);
		return rc;
	}

	if (len == 0)
		return 0;

	assert(PAGE_ALIGNED(len));
	assert(PAGE_ALIGNED(boff));
	assert(iovcnt == (len >> PAGE_SHIFT));

	/*
	 * Read lock the mblock layout; mblock reads can proceed concurrently;
	 * Mblock writes are serialized but concurrent with reads
	 */
	pmd_obj_rdlock(layout);
	state = layout->eld_state;
	if (state & PMD_LYT_COMMITTED)
		rc = pmd_layout_rw(mp, layout, iov, iovcnt, boff, 0, MPOOL_OP_READ);
	pmd_obj_rdunlock(layout);

	return (state & PMD_LYT_COMMITTED) ? rc : -EAGAIN;
}

int
mblock_get_props_ex(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props_ex     *prop)
{
	struct pmd_layout *layout;

	layout = mblock2layout(mbh);
	if (!layout) {
		mp_pr_layout_not_found(mp, mbh);
		return -EINVAL;
	}

	pmd_obj_rdlock(layout);
	prop->mbx_zonecnt = layout->eld_ld.ol_zcnt;
	mblock_getprops_cmn(mp, layout, &prop->mbx_props);
	pmd_obj_rdunlock(layout);

	return 0;
}

bool mblock_objid(u64 objid)
{
	return objid && (pmd_objid_type(objid) == OMF_OBJ_MBLOCK);
}
