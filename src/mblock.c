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
 *  struct mblock_write_async_cbobj - structure holding async IO callback
 *  @mp_pctx:
 *  @mp_iov:
 *  @mp_mpd:
 *  @mp_iovcnt:
 *  @mp_pagesv:
 *  @mp_pagesc:
 *  @mp_pagesvz:
 *  @mp_erpt:
 */
struct mblock_write_async_cbobj {
	struct mio_asyncctx         *mp_pctx;
	struct iovec                *mp_iov;
	struct mpool_descriptor     *mp_mpd;
	int                          mp_iovcnt;
	void                       **mp_pagesv;
	int                          mp_pagesc;
	int                          mp_pagesvz;
	struct ecio_err_report       mp_erpt;
};


/**
 * mblock2layout() - convert opaque mblock handle to ecio_layout_descriptor
 *
 * This function converts the opaque handle (mblock_descriptor) used by
 * clients to the internal representation (ecio_layout_descriptor).  The
 * conversion is a simple cast, followed by a sanity check to verify the
 * layout object is an mblock object.  If the validation fails, a NULL
 * pointer is returned.
 */
static struct ecio_layout_descriptor *
mblock2layout(struct mblock_descriptor *mbh)
{
	struct ecio_layout_descriptor  *layout =
		(struct ecio_layout_descriptor *)mbh;

	if (ev(!mbh))
		return NULL;

#ifndef MPOOL_BUILD_RELEASE
	WARN(layout->eld_magic != layout->eld_objid,
	     "%s: %px, magic %lx, objid %lx, refcnt %ld",
	     __func__, layout, layout->eld_magic,
	     (ulong)layout->eld_objid, layout->eld_refcnt);

	assert(layout->eld_magic == layout->eld_objid);
#endif

	return mblock_objid(layout->eld_objid) ? layout : NULL;
}

/**
 * layout2mblock() - convert ecio_layout_descriptor to opaque mblock_descriptor
 *
 * This function converts the internally used ecio_layout_descriptor to
 * the externally used opaque mblock_descriptor.
 */
static struct mblock_descriptor *
layout2mblock(struct ecio_layout_descriptor *layout)
{
	return (struct mblock_descriptor *)layout;
}

static void
mblock_getprops_cmn(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout,
	struct mblock_props            *prop)
{
	struct media_class *mc;

	u32    mcid;

	assert(layout);
	assert(prop);

	prop->mpr_objid       = layout->eld_objid;
	prop->mpr_alloc_cap   = ecio_obj_get_cap_from_layout(mp, layout);
	prop->mpr_write_len   = layout->eld_mblen;
	prop->mpr_stripe_len  = ecio_mblock_stripe_size(mp, layout);
	mcid = mp->pds_pdv[layout->eld_ld.ol_pdh].pdi_mcid;
	if (unlikely(mcid == MCID_INVALID)) {
		prop->mpr_mclassp = MP_MED_INVALID;
	} else {
		mc = mc_id2class(mp, mcid);
		prop->mpr_mclassp = mc->mc_parms.mcp_classp;
	}
	prop->mpr_iscommitted = layout->eld_state & ECIO_LYT_COMMITTED;
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
	struct ecio_layout_descriptor  *layout = NULL;
	struct pmd_obj_capacity         ocap;
	merr_t                          err;

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
		pmd_obj_rdlock(mp, layout);
		mblock_getprops_cmn(mp, layout, prop);
		pmd_obj_rdunlock(mp, layout);
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
mblock_get(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props        *prop)
{
	struct ecio_layout_descriptor  *layout;
	merr_t                          err;

	layout = mblock2layout(mbh);

	if (ev(!layout))
		return merr(EINVAL);

	/* A read lock is sufficient here because pmd_obj_rdlock will take
	 * the mmi_reflock mutex while it increments the refcount; we just
	 * need to prevent the layout from being deleted while we grab the
	 * ref
	 */
	pmd_obj_rdlock(mp, layout);

	err = pmd_obj_get(mp, layout);

	if (!ev(err) && prop)
		mblock_getprops_cmn(mp, layout, prop);

	pmd_obj_rdunlock(mp, layout);

	return err;
}

merr_t
mblock_find_get(
	struct mpool_descriptor     *mp,
	u64                          objid,
	struct mblock_props         *prop,
	struct mblock_descriptor   **mbh)
{
	struct ecio_layout_descriptor  *layout;

	*mbh = NULL;

	if (ev(!mblock_objid(objid)))
		return merr(EINVAL);

	layout = pmd_obj_find_get(mp, objid);
	if (ev(!layout))
		return merr(ENOENT);

	pmd_obj_rdlock(mp, layout);

	*mbh = layout2mblock(layout);

	if (prop)
		mblock_getprops_cmn(mp, layout, prop);

	pmd_obj_rdunlock(mp, layout);

	return 0;
}

void mblock_put(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct ecio_layout_descriptor  *layout;

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
	struct ecio_layout_descriptor  *layout;
	merr_t                          err;

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

int
mblock_is_committed(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	struct ecio_layout_descriptor  *layout;
	int                             answer = 0;

	layout = mblock2layout(mbh);
	if (!layout)
		return 0;

	pmd_obj_rdlock(mp, layout);
	if (layout->eld_state & ECIO_LYT_COMMITTED)
		answer = 1;

	pmd_obj_rdunlock(mp, layout);

	return answer;
}

merr_t mblock_abort(struct mpool_descriptor *mp, struct mblock_descriptor *mbh)
{
	merr_t                          err;
	struct ecio_layout_descriptor  *layout;

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
	struct ecio_layout_descriptor  *layout;

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
	struct ecio_layout_descriptor  *layout;
	struct ecio_err_report		erpt;

	merr_t err = 0;
	u64    tdata = 0;
	u8     state;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	pmd_obj_wrlock(mp, layout);
	state = layout->eld_state;
	if (!(state & ECIO_LYT_COMMITTED))
		err = ecio_mblock_write(mp, layout, iov, iovcnt, &erpt, &tdata);
	pmd_obj_wrunlock(mp, layout);

	if (ev(state & ECIO_LYT_COMMITTED)) {
		err = merr(EALREADY);
		mp_pr_rl("mpool %s, mblock 0x%lx committed 0x%lx",
			 err, mp->pds_name, (ulong)layout->eld_objid, state);
	}

	return err;
}

merr_t
mblock_read(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct iovec               *iov,
	int                         iovcnt,
	u64                         boff)
{
	struct ecio_layout_descriptor  *layout;
	struct ecio_err_report          erpt;

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
	pmd_obj_rdlock(mp, layout);
	state = layout->eld_state;
	if (state & ECIO_LYT_COMMITTED)
		err = ecio_mblock_read(mp, layout, iov, iovcnt, boff, &erpt);
	pmd_obj_rdunlock(mp, layout);

	if (ev(!(state & ECIO_LYT_COMMITTED))) {
		err = merr(EAGAIN);
		mp_pr_rl("mpool %s, mblock 0x%lx not committed 0x%lx",
			 err, mp->pds_name, (ulong)layout->eld_objid, state);
	}

	return err;
}

merr_t
mblock_get_props(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props        *prop)
{
	struct ecio_layout_descriptor  *layout;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	pmd_obj_rdlock(mp, layout);
	mblock_getprops_cmn(mp, layout, prop);
	pmd_obj_rdunlock(mp, layout);

	return 0;
}

merr_t
mblock_get_props_ex(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props_ex     *prop)
{
	struct ecio_layout_descriptor  *layout;

	layout = mblock2layout(mbh);
	if (ev(!layout)) {
		mp_pr_layout_not_found(mp, mbh);
		return merr(EINVAL);
	}

	pmd_obj_rdlock(mp, layout);

	prop->mbx_zonecnt  = layout->eld_ld.ol_zcnt;

	mblock_getprops_cmn(mp, layout, &prop->mbx_props);

	pmd_obj_rdunlock(mp, layout);

	return 0;
}

u64 mblock_objid_to_uhandle(u64 objid)
{
	return pmd_objid_to_uhandle(objid);
}

u64 mblock_uhandle_to_objid(u64 uhandle)
{
	return pmd_uhandle_to_objid(uhandle);
}

bool mblock_uhandle(u64 uhandle)
{
	return (pmd_uhandle_type(uhandle) == OMF_OBJ_MBLOCK);
}

bool mblock_objid(u64 objid)
{
	return objid && (pmd_objid_type(objid) == OMF_OBJ_MBLOCK);
}
