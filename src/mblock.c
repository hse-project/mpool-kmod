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
 * mblock2layout() - convert opaque mblock handle to ecio_layout
 *
 * This function converts the opaque handle (mblock_descriptor) used by
 * clients to the internal representation (ecio_layout).  The
 * conversion is a simple cast, followed by a sanity check to verify the
 * layout object is an mblock object.  If the validation fails, a NULL
 * pointer is returned.
 */
static struct ecio_layout *
mblock2layout(struct mblock_descriptor *mbh)
{
	struct ecio_layout *layout = (void *)mbh;

	if (ev(!layout))
		return NULL;

	WARN_ONCE(layout->eld_objid == 0 ||
		  kref_read(&layout->eld_ref) < 2,
		  "%s: %px, objid %lx, state %x, refcnt %ld\n",
		  __func__, layout, (ulong)layout->eld_objid,
		  layout->eld_state, (long)kref_read(&layout->eld_ref));

	return mblock_objid(layout->eld_objid) ? layout : NULL;
}

/**
 * layout2mblock() - convert ecio_layout to opaque mblock_descriptor
 *
 * This function converts the internally used ecio_layout to
 * the externally used opaque mblock_descriptor.
 */
static struct mblock_descriptor *
layout2mblock(struct ecio_layout *layout)
{
	return (struct mblock_descriptor *)layout;
}

static void
mblock_getprops_cmn(
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout,
	struct mblock_props        *prop)
{
	assert(layout);
	assert(prop);

	prop->mpr_objid       = layout->eld_objid;
	prop->mpr_alloc_cap   = ecio_obj_get_cap_from_layout(mp, layout);
	prop->mpr_write_len   = layout->eld_mblen;
	prop->mpr_stripe_len  = ecio_mblock_stripe_size(mp, layout);
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
	struct ecio_layout     *layout = NULL;
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
	struct ecio_layout *layout;

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
	struct ecio_layout *layout;

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
	struct ecio_layout *layout;
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
	struct ecio_layout *layout;
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
	struct ecio_layout *layout;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	return pmd_obj_delete(mp, layout);
}

merr_t
mblock_write(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct iovec               *iov,
	int                         iovcnt)
{
	struct ecio_layout     *layout;

	merr_t err = 0;
	u64    tdata = 0;
	u8     state;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	pmd_obj_wrlock(layout);
	state = layout->eld_state;
	if (!(state & PMD_LYT_COMMITTED))
		err = ecio_mblock_write(mp, layout, iov, iovcnt, &tdata);
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
	struct ecio_layout     *layout;

	merr_t  err = 0;
	u8      state;

	assert(mp);

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	/*
	 * read lock the mblock layout; mblock reads can proceed
	 * concurrently; Taking the layout rw lock in read protects
	 * against a rebuild.
	 * mblock writes are serialized but concurrent with reads
	 */
	pmd_obj_rdlock(layout);
	state = layout->eld_state;
	if (state & PMD_LYT_COMMITTED)
		err = ecio_mblock_read(mp, layout, iov, iovcnt, boff);
	pmd_obj_rdunlock(layout);

	return (state & PMD_LYT_COMMITTED) ? err : merr(EAGAIN);
}

merr_t
mblock_get_props(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props        *prop)
{
	struct ecio_layout *layout;

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
	struct ecio_layout *layout;

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
