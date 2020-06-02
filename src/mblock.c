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

#include "mpcore_defs.h"

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

	if (ev(!layout))
		return NULL;

	WARN_ONCE(layout->eld_objid == 0 ||
		  kref_read(&layout->eld_ref) < 2,
		  "%s: %px, objid %lx, state %x, refcnt %ld\n",
		  __func__, layout, (ulong)layout->eld_objid,
		  layout->eld_state, (long)kref_read(&layout->eld_ref));

	return mblock_objid(layout->eld_objid) ? layout : NULL;
}

u32 mblock_stripe_size_get(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct mpool_dev_info  *pd;

	pd = &mp->pds_pdv[layout->eld_ld.ol_pdh];

	return pd->pdi_parm.dpr_optiosz;
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
	assert(layout);
	assert(prop);

	prop->mpr_objid      = layout->eld_objid;
	prop->mpr_alloc_cap  = pmd_layout_cap_get(mp, layout);
	prop->mpr_write_len  = layout->eld_mblen;
	prop->mpr_stripe_len = mblock_stripe_size_get(mp, layout);
	prop->mpr_mclassp = mp->pds_pdv[layout->eld_ld.ol_pdh].pdi_mclass;
	prop->mpr_iscommitted = layout->eld_state & PMD_LYT_COMMITTED;
}

static merr_t
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
	merr_t                  err;

	if (!mp)
		return merr(EINVAL);

	*mbh = NULL;

	ocap.moc_captgt = 0;
	ocap.moc_spare  = spare;

	if (!objid) {
		err = pmd_obj_alloc(mp, OMF_OBJ_MBLOCK, &ocap,
				    mclassp, &layout);
		if (err)
			return err;
	} else {
		err = pmd_obj_realloc(mp, objid, &ocap, mclassp, &layout);
		if (err) {
			if (merr_errno(err) != ENOENT)
				mp_pr_err("mpool %s, re-allocating mblock 0x%lx failed",
					  err, mp->pds_name, (ulong)objid);
			return err;
		}
	}

	if (ev(!layout))
		return merr(EBUG);

	if (prop) {
		pmd_obj_rdlock(layout);
		mblock_getprops_cmn(mp, layout, prop);
		pmd_obj_rdunlock(layout);
	}

	*mbh = layout2mblock(layout);

	return 0;
}

merr_t
mblock_alloc(
	struct mpool_descriptor     *mp,
	enum mp_media_classp         mclassp,
	bool                         spare,
	struct mblock_descriptor   **mbh,
	struct mblock_props         *prop)
{
	return mblock_alloc_cmn(mp, 0, mclassp, spare, prop, mbh);
}

merr_t
mblock_realloc(
	struct mpool_descriptor     *mp,
	u64                          objid,
	enum mp_media_classp         mclassp,
	bool                         spare,
	struct mblock_descriptor   **mbh,
	struct mblock_props         *prop)
{
	if (!mblock_objid(objid))
		return merr(EINVAL);

	return mblock_alloc_cmn(mp, objid, mclassp, spare, prop, mbh);
}

merr_t
mblock_find_get(
	struct mpool_descriptor    *mp,
	u64                         objid,
	int                         which,
	struct mblock_props        *prop,
	struct mblock_descriptor  **mbh)
{
	struct pmd_layout *layout;

	*mbh = NULL;

	if (ev(!mblock_objid(objid)))
		return merr(EINVAL);

	layout = pmd_obj_find_get(mp, objid, which);
	if (ev(!layout))
		return merr(ENOENT);

	if (prop) {
		pmd_obj_rdlock(layout);
		mblock_getprops_cmn(mp, layout, prop);
		pmd_obj_rdunlock(layout);
	}

	*mbh = layout2mblock(layout);

	return 0;
}

void mblock_put(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct pmd_layout *layout;

	layout = mblock2layout(mbh);
	if (layout)
		pmd_obj_put(mp, layout);
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
		mp_pr_warn("mpool %s, layout not found: mbh %px",	\
			   (_mp)->pds_name, (_mbh));			\
		dump_stack();						\
	}								\
} while (0)

merr_t mblock_commit(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct pmd_layout  *layout;
	merr_t              err;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	/* Commit will fail with EBUSY if aborting flag set.
	 */
	err = pmd_obj_commit(mp, layout);
	if (ev(err)) {
		mp_pr_rl("mpool %s, committing mblock 0x%lx failed",
			 err, mp->pds_name, (ulong)layout->eld_objid);
		return err;
	}

	return 0;
}

merr_t mblock_abort(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct pmd_layout  *layout;
	merr_t              err;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	err = pmd_obj_abort(mp, layout);
	if (ev(err)) {
		mp_pr_err("mpool %s, aborting mblock 0x%lx failed",
			  err, mp->pds_name, (ulong)layout->eld_objid);
		return err;
	}

	return 0;
}

merr_t mblock_delete(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct pmd_layout *layout;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	return pmd_obj_delete(mp, layout);
}

/**
 * iov_len_and_alignment()
 *
 * Calculate the total data length of an iovec list, and set a flag if there
 * are any non-page-aligned pointers (or non-page-multiple iovecs)
 */
static u64 iov_len_and_alignment(struct iovec *iov, int iovcnt, int *alignment)
{
	u64    len = 0;
	int    i = 0;
	int    align = 0;

	*alignment = 0;

	for (i = 0; i < iovcnt; i++) {
		len += iov[i].iov_len;

		/* Make alignment and length problems distinguishable */
		if (!PAGE_ALIGNED((ulong)iov[i].iov_base))
			align |= 1;
		if (!PAGE_ALIGNED(iov[i].iov_len))
			align |= 2;
	}

	*alignment = align;

	return len;
}

/**
 * mblock_rw_argcheck()
 *
 * @mp:      - Mpool descriptor
 * @layout:  - Layout of the mblock
 * @iov:     - iovec array
 * @iovcnt:  - iovec count
 * @boff:    - Byte offset into the layout.  Must be equal to layout->eld_mblen
 *             for write
 * @rw:      - MPOOL_OP_READ or MPOOL_OP_WRITE
 * @len:     - Output: number of bytes in iov list
 *
 * Validate mblock_write() and mblock_read()
 *
 * Sets *len to total data in iov
 *
 * Returns: 0 if successful, merr_t otherwise
 *
 * Note: be aware that there are checks in this function that prevent illegal
 * arguments in lower level functions (lower level functions should assert the
 * requirements but not otherwise check them)
 */
static merr_t
mblock_rw_argcheck(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	struct iovec               *iov,
	int                         iovcnt,
	loff_t                      boff,
	int                         rw,
	u64                        *len)
{
	u64    data_len = 0;
	u64    stripe_bytes;
	u32    mblock_cap;
	int    alignment;
	merr_t err;

	mblock_cap = pmd_layout_cap_get(mp, layout);
	stripe_bytes = mblock_stripe_size_get(mp, layout);

	data_len = iov_len_and_alignment(iov, iovcnt, &alignment);
	if (alignment) {
		err = merr(EINVAL);
		mp_pr_err("mpool %s, mblock %s IOV not page aligned (%d)",
			  err, mp->pds_name, (rw == MPOOL_OP_READ) ? "read" : "write", alignment);
		return err;
	}

	if (rw == MPOOL_OP_READ) {
		/* boff must be a multiple of the OS page size */
		if (!PAGE_ALIGNED(boff)) {
			err = merr(EINVAL);
			mp_pr_err("mpool %s, read offset 0x%lx is not multiple of OS page size",
				  err, mp->pds_name, (ulong) boff);
			return err;
		}

		/* Check that boff is not past end of mblock capacity.
		 */
		if (mblock_cap <= boff) {
			err = merr(EINVAL);
			mp_pr_err("mpool %s, read offset 0x%lx >= mblock capacity 0x%x",
				  err, mp->pds_name, (ulong)boff, mblock_cap);
			return err;
		}

		/* Check that the request does not extend past the data
		 * written.  Don't record an error if this appears to
		 * be an mcache readahead request.
		 *
		 * TODO: Use (data_len != MCACHE_RA_PAGES_MAX)
		 */
		if (ev(boff + data_len > layout->eld_mblen))
			return merr(EINVAL);
	} else {
		/* Write boff required to match eld_mblen */
		if (boff != layout->eld_mblen) {
			err = merr(EINVAL);
			mp_pr_err("mpool %s write boff (%ld) != eld_mblen (%d)",
				  err, mp->pds_name, (ulong)boff, layout->eld_mblen);
			return err;
		}

		/* Writes must be stripe-aligned */
		if (boff % stripe_bytes) {
			err = merr(EINVAL);
			mp_pr_err("mpool %s, write not stripe-aligned, offset 0x%lx",
				  err, mp->pds_name, (ulong)boff);
			return err;
		}

		/* Check for write past end of allocated space (!) */
		if ((data_len + boff) > mblock_cap) {
			err = merr(EINVAL);
			mp_pr_err("(write): len %lu + boff %lu > mblock_cap %lu",
				  err, (ulong)data_len, (ulong)boff, (ulong)mblock_cap);
			return err;
		}
	}

	/* Set the amount of data to read/write */
	*len = data_len;

	return 0;
}

merr_t
mblock_write(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct iovec               *iov,
	int                         iovcnt)
{
	struct pmd_layout *layout;

	merr_t err;
	u64    len = 0;
	loff_t boff;
	u8     state;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	err = mblock_rw_argcheck(mp, layout, iov, iovcnt, layout->eld_mblen,
				 MPOOL_OP_WRITE, &len);
	if (ev(err)) {
		mp_pr_debug("mblock write argcheck failed ", err);
		return err;
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
		err = pmd_layout_rw(mp, layout, iov, iovcnt, boff,
				    REQ_FUA, MPOOL_OP_WRITE);
		if (!err)
			layout->eld_mblen += len;
	}
	pmd_obj_wrunlock(layout);

	return (!(state & PMD_LYT_COMMITTED)) ? err : merr(EALREADY);
}

merr_t
mblock_read(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct iovec               *iov,
	int                         iovcnt,
	u64                         boff)
{
	struct pmd_layout *layout;

	merr_t err;
	u64    len = 0;
	u8     state;

	assert(mp);

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	err = mblock_rw_argcheck(mp, layout, iov, iovcnt, boff,
				 MPOOL_OP_READ, &len);
	if (ev(err)) {
		mp_pr_debug("mblock read argcheck failed ", err);
		return err;
	}

	if (len == 0)
		return 0;

	assert(PAGE_ALIGNED(len));
	assert(PAGE_ALIGNED(boff));
	assert(iovcnt == (len >> PAGE_SHIFT));

	/*
	 * read lock the mblock layout; mblock reads can proceed
	 * concurrently; Taking the layout rw lock in read protects
	 * against a rebuild.
	 * mblock writes are serialized but concurrent with reads
	 */
	pmd_obj_rdlock(layout);
	state = layout->eld_state;
	if (state & PMD_LYT_COMMITTED)
		err = pmd_layout_rw(mp, layout, iov, iovcnt, boff, 0,
				    MPOOL_OP_READ);
	pmd_obj_rdunlock(layout);

	return (state & PMD_LYT_COMMITTED) ? err : merr(EAGAIN);
}

merr_t
mblock_get_props(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props        *prop)
{
	struct pmd_layout *layout;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	pmd_obj_rdlock(layout);
	mblock_getprops_cmn(mp, layout, prop);
	pmd_obj_rdunlock(layout);

	return 0;
}

merr_t
mblock_get_props_ex(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props_ex     *prop)
{
	struct pmd_layout *layout;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
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
