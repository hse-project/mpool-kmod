// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * DOC: Module info.
 *
 * Pool metadata (pmd) module.
 *
 * Defines functions for probing, reading, and writing drives in an mpool.
 *
 */

#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <linux/delay.h>

#include "mpool_printk.h"
#include "uuid.h"
#include "assert.h"

#include "pd.h"
#include "omf_if.h"
#include "sb.h"
#include "mclass.h"
#include "smap.h"
#include "mpcore.h"
#include "pmd.h"

static struct kmem_cache *pmd_obj_erase_work_cache __read_mostly;
static struct kmem_cache *pmd_layout_priv_cache __read_mostly;
static struct kmem_cache *pmd_layout_cache __read_mostly;

static int pmd_mdc0_meta_update(struct mpool_descriptor *mp, struct pmd_layout *layout);
static struct pmd_layout *pmd_layout_find(struct rb_root *root, u64 key);
static struct pmd_layout *pmd_layout_insert(struct rb_root *root, struct pmd_layout *item);

/* Committed object tree operations... */
void pmd_co_rlock(struct pmd_mdc_info *cinfo, u8 slot)
{
	down_read_nested(&cinfo->mmi_co_lock, slot > 0 ? PMD_MDC_NORMAL : PMD_MDC_ZERO);
}

void pmd_co_runlock(struct pmd_mdc_info *cinfo)
{
	up_read(&cinfo->mmi_co_lock);
}

static void pmd_co_wlock(struct pmd_mdc_info *cinfo, u8 slot)
{
	down_write_nested(&cinfo->mmi_co_lock, slot > 0 ? PMD_MDC_NORMAL : PMD_MDC_ZERO);
}

static void pmd_co_wunlock(struct pmd_mdc_info *cinfo)
{
	up_write(&cinfo->mmi_co_lock);
}

struct pmd_layout *pmd_co_find(struct pmd_mdc_info *cinfo, u64 objid)
{
	return pmd_layout_find(&cinfo->mmi_co_root, objid);
}

struct pmd_layout *pmd_co_insert(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	return pmd_layout_insert(&cinfo->mmi_co_root, layout);
}

struct pmd_layout *pmd_co_remove(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	struct pmd_layout *found;

	found = pmd_co_find(cinfo, layout->eld_objid);
	if (found)
		rb_erase(&found->eld_nodemdc, &cinfo->mmi_co_root);

	return found;
}

/* Uncommitted object tree operations... */
static void pmd_uc_lock(struct pmd_mdc_info *cinfo, u8 slot)
{
	mutex_lock_nested(&cinfo->mmi_uc_lock, slot > 0 ? PMD_MDC_NORMAL : PMD_MDC_ZERO);
}

static void pmd_uc_unlock(struct pmd_mdc_info *cinfo)
{
	mutex_unlock(&cinfo->mmi_uc_lock);
}

static struct pmd_layout *pmd_uc_find(struct pmd_mdc_info *cinfo, u64 objid)
{
	return pmd_layout_find(&cinfo->mmi_uc_root, objid);
}

static struct pmd_layout *pmd_uc_insert(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	return pmd_layout_insert(&cinfo->mmi_uc_root, layout);
}

static struct pmd_layout *pmd_uc_remove(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	struct pmd_layout *found;

	found = pmd_uc_find(cinfo, layout->eld_objid);
	if (found)
		rb_erase(&found->eld_nodemdc, &cinfo->mmi_uc_root);

	return found;
}

/*
 * General object operations for both internal and external callers...
 *
 * See pmd.h for the various nesting levels for a locking class.
 */
void pmd_obj_rdlock(struct pmd_layout *layout)
{
	enum pmd_lock_class lc __maybe_unused = PMD_MDC_NORMAL;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	if (objid_slot(layout->eld_objid))
		lc = PMD_OBJ_CLIENT;
	else if (objid_mdc0log(layout->eld_objid))
		lc = PMD_MDC_ZERO;
#endif

	down_read_nested(&layout->eld_rwlock, lc);
}

void pmd_obj_rdunlock(struct pmd_layout *layout)
{
	up_read(&layout->eld_rwlock);
}

void pmd_obj_wrlock(struct pmd_layout *layout)
{
	enum pmd_lock_class lc __maybe_unused = PMD_MDC_NORMAL;

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	if (objid_slot(layout->eld_objid))
		lc = PMD_OBJ_CLIENT;
	else if (objid_mdc0log(layout->eld_objid))
		lc = PMD_MDC_ZERO;
#endif

	down_write_nested(&layout->eld_rwlock, lc);
}

void pmd_obj_wrunlock(struct pmd_layout *layout)
{
	up_write(&layout->eld_rwlock);
}

/*
 * Alloc and init object layout; non-arg fields and all strip descriptor
 * fields are set to 0/UNDEF/NONE; no auxiliary object info is allocated.
 *
 * Returns NULL if allocation fails.
 */
struct pmd_layout *pmd_layout_alloc(struct mpool_uuid *uuid, u64 objid,
				    u64 gen, u64 mblen, u32 zcnt)
{
	struct kmem_cache *cache = pmd_layout_cache;
	struct pmd_layout *layout;

	if (pmd_objid_type(objid) == OMF_OBJ_MLOG)
		cache = pmd_layout_priv_cache;

	layout = kmem_cache_zalloc(cache, GFP_KERNEL);
	if (!layout)
		return NULL;

	layout->eld_objid     = objid;
	layout->eld_gen       = gen;
	layout->eld_mblen     = mblen;
	layout->eld_ld.ol_zcnt = zcnt;
	kref_init(&layout->eld_ref);
	init_rwsem(&layout->eld_rwlock);

	if (pmd_objid_type(objid) == OMF_OBJ_MLOG)
		mpool_uuid_copy(&layout->eld_uuid, uuid);

	return layout;
}

/*
 * Deallocate all memory associated with object layout.
 */
void pmd_layout_release(struct kref *refp)
{
	struct kmem_cache *cache = pmd_layout_cache;
	struct pmd_layout *layout;

	layout = container_of(refp, typeof(*layout), eld_ref);

	WARN_ONCE(layout->eld_objid == 0 ||
		  kref_read(&layout->eld_ref), "%s: %p, objid %lx, state %x, refcnt %ld",
		  __func__, layout, (ulong)layout->eld_objid,
		  layout->eld_state, (long)kref_read(&layout->eld_ref));

	if (pmd_objid_type(layout->eld_objid) == OMF_OBJ_MLOG)
		cache = pmd_layout_priv_cache;

	layout->eld_objid = 0;

	kmem_cache_free(cache, layout);
}

static struct pmd_layout *pmd_layout_find(struct rb_root *root, u64 key)
{
	struct rb_node *node = root->rb_node;
	struct pmd_layout *this;

	while (node) {
		this = rb_entry(node, typeof(*this), eld_nodemdc);

		if (key < this->eld_objid)
			node = node->rb_left;
		else if (key > this->eld_objid)
			node = node->rb_right;
		else
			return this;
	}

	return NULL;
}

static struct pmd_layout *pmd_layout_insert(struct rb_root *root, struct pmd_layout *item)
{
	struct rb_node **pos = &root->rb_node, *parent = NULL;
	struct pmd_layout *this;

	/*
	 * Figure out where to insert given layout, or return the colliding
	 * layout if there's already a layout in the tree with the given ID.
	 */
	while (*pos) {
		this = rb_entry(*pos, typeof(*this), eld_nodemdc);
		parent = *pos;

		if (item->eld_objid < this->eld_objid)
			pos = &(*pos)->rb_left;
		else if (item->eld_objid > this->eld_objid)
			pos = &(*pos)->rb_right;
		else
			return this;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&item->eld_nodemdc, parent, pos);
	rb_insert_color(&item->eld_nodemdc, root);

	return NULL;
}

static void pmd_layout_unprovision(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	int rc;
	u16 pdh;

	pdh = layout->eld_ld.ol_pdh;

	/* smap_free() should never fail */

	rc = smap_free(mp, pdh, layout->eld_ld.ol_zaddr, layout->eld_ld.ol_zcnt);
	if (rc)
		mp_pr_err("releasing %s drive %s space for layout failed, objid 0x%lx",
			  rc, mp->pds_name, mp->pds_pdv[pdh].pdi_name, (ulong)layout->eld_objid);

	/* Drop birth reference... */
	pmd_obj_put(layout);
}

/**
 * pmd_layout_calculate() -
 * @mp:
 * @ocap:
 * @mc:
 * @zcnt:
 * @otype:
 */
static void pmd_layout_calculate(struct mpool_descriptor *mp, struct pmd_obj_capacity *ocap,
				 struct media_class *mc, u64 *zcnt)
{
	u32 zonepg;

	if (!ocap->moc_captgt) {
		/* Obj capacity not specified; use one zone. */
		*zcnt = 1;
		return;
	}

	zonepg = mp->pds_pdv[mc->mc_pdmc].pdi_parm.dpr_zonepg;
	*zcnt = 1 + ((ocap->moc_captgt - 1) / (zonepg << PAGE_SHIFT));
}

/**
 * pmd_layout_provision() - provision storage for the given layout
 * @mp:
 * @ocap:
 * @otype:
 * @layoutp:
 * @mc:		media class
 * @zcnt:
 */
static int pmd_layout_provision(struct mpool_descriptor *mp, struct pmd_obj_capacity *ocap,
				struct pmd_layout *layout, struct media_class *mc, u64 zcnt)
{
	enum smap_space_type spctype;
	struct mc_smap_parms mcsp;
	u64 zoneaddr, align;
	u8 pdh;
	int rc;

	spctype = SMAP_SPC_USABLE_ONLY;
	if (ocap->moc_spare)
		spctype = SMAP_SPC_SPARE_2_USABLE;

	/* To reduce/eliminate fragmenation, make sure the alignment is a power of 2. */
	rc = mc_smap_parms_get(&mp->pds_mc[mc->mc_parms.mcp_classp], &mp->pds_params, &mcsp);
	if (rc)
		return rc;

	align = min_t(u64, zcnt, mcsp.mcsp_align);
	align = roundup_pow_of_two(align);

	pdh = mc->mc_pdmc;
	rc = smap_alloc(mp, pdh, zcnt, spctype, &zoneaddr, align);
	if (rc)
		return rc;

	layout->eld_ld.ol_pdh = pdh;
	layout->eld_ld.ol_zaddr = zoneaddr;

	return 0;
}

int pmd_layout_rw(struct mpool_descriptor *mp, struct pmd_layout *layout,
		  const struct kvec *iov, int iovcnt, u64 boff, int flags, u8 rw)
{
	struct mpool_dev_info *pd;
	u64 zaddr;
	int rc;

	if (!mp || !layout || !iov)
		return -EINVAL;

	if (rw != MPOOL_OP_READ && rw != MPOOL_OP_WRITE)
		return -EINVAL;

	pd = &mp->pds_pdv[layout->eld_ld.ol_pdh];
	if (mpool_pd_status_get(pd) != PD_STAT_ONLINE)
		return -EIO;

	if (iovcnt == 0)
		return 0;

	zaddr = layout->eld_ld.ol_zaddr;
	if (rw == MPOOL_OP_READ)
		rc = pd_zone_preadv(&pd->pdi_parm, iov, iovcnt, zaddr, boff);
	else
		rc = pd_zone_pwritev(&pd->pdi_parm, iov, iovcnt, zaddr, boff, flags);

	if (rc)
		mpool_pd_status_set(pd, PD_STAT_OFFLINE);

	return rc;
}

int pmd_layout_erase(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct mpool_dev_info *pd;
	int rc;

	if (!mp || !layout)
		return -EINVAL;

	pd = &mp->pds_pdv[layout->eld_ld.ol_pdh];
	if (mpool_pd_status_get(pd) != PD_STAT_ONLINE)
		return -EIO;

	rc = pd_zone_erase(&pd->pdi_parm, layout->eld_ld.ol_zaddr, layout->eld_ld.ol_zcnt,
			   pmd_objid_type(layout->eld_objid) == OMF_OBJ_MLOG);
	if (rc)
		mpool_pd_status_set(pd, PD_STAT_OFFLINE);

	return rc;
}

u64 pmd_layout_cap_get(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	enum obj_type_omf otype = pmd_objid_type(layout->eld_objid);
	u32 zonepg;

	switch (otype) {
	case OMF_OBJ_MBLOCK:
	case OMF_OBJ_MLOG:
		zonepg = mp->pds_pdv[layout->eld_ld.ol_pdh].pdi_parm.dpr_zonepg;
		return ((u64)zonepg * layout->eld_ld.ol_zcnt) << PAGE_SHIFT;

	case OMF_OBJ_UNDEF:
		break;
	}

	mp_pr_warn("mpool %s objid 0x%lx, undefined object type %d",
		   mp->pds_name, (ulong)layout->eld_objid, otype);

	return 0;
}

struct mpool_dev_info *pmd_layout_pd_get(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	return &mp->pds_pdv[layout->eld_ld.ol_pdh];
}

int pmd_smap_insert(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	int rc;
	u16 pdh;

	pdh = layout->eld_ld.ol_pdh;

	/* Insert should never fail */

	rc = smap_insert(mp, pdh, layout->eld_ld.ol_zaddr, layout->eld_ld.ol_zcnt);
	if (rc)
		mp_pr_err("mpool %s, allocating drive %s space for layout failed, objid 0x%lx",
			  rc, mp->pds_name, mp->pds_pdv[pdh].pdi_name, (ulong)layout->eld_objid);

	return rc;
}

struct pmd_layout *pmd_obj_find_get(struct mpool_descriptor *mp, u64 objid, int which)
{
	struct pmd_mdc_info *cinfo;
	struct pmd_layout *found;
	u8 cslot;

	if (!objtype_user(objid_type(objid)))
		return NULL;

	cslot = objid_slot(objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	found = NULL;

	/*
	 * which < 0  - search uncommitted tree only
	 * which > 0  - search tree only
	 * which == 0 - search both trees
	 */
	if (which <= 0) {
		pmd_uc_lock(cinfo, cslot);
		found = pmd_uc_find(cinfo, objid);
		if (found)
			kref_get(&found->eld_ref);
		pmd_uc_unlock(cinfo);
	}

	if (!found && which >= 0) {
		pmd_co_rlock(cinfo, cslot);
		found = pmd_co_find(cinfo, objid);
		if (found)
			kref_get(&found->eld_ref);
		pmd_co_runlock(cinfo);
	}

	return found;
}

int pmd_obj_alloc(struct mpool_descriptor *mp, enum obj_type_omf otype,
		  struct pmd_obj_capacity *ocap, enum mp_media_classp mclassp,
		  struct pmd_layout **layoutp)
{
	return pmd_obj_alloc_cmn(mp, 0, otype, ocap, mclassp, 0, true, layoutp);
}

int pmd_obj_realloc(struct mpool_descriptor *mp, u64 objid, struct pmd_obj_capacity *ocap,
		    enum mp_media_classp mclassp, struct pmd_layout **layoutp)
{
	if (!pmd_objid_isuser(objid)) {
		*layoutp = NULL;
		return -EINVAL;
	}

	return pmd_obj_alloc_cmn(mp, objid, objid_type(objid), ocap, mclassp, 1, true, layoutp);
}

int pmd_obj_commit(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_mdc_info *cinfo;
	struct pmd_layout *found;
	int rc;
	u8 cslot;

	if (!objtype_user(objid_type(layout->eld_objid)))
		return -EINVAL;

	pmd_obj_wrlock(layout);
	if (layout->eld_state & PMD_LYT_COMMITTED) {
		pmd_obj_wrunlock(layout);
		return 0;
	}

	/*
	 * must log create before marking object committed to guarantee it will
	 * exist after a crash; must hold cinfo.compactclock while log create,
	 * update layout.state, and add to list of committed objects to prevent
	 * a race with mdc compaction
	 */
	cslot = objid_slot(layout->eld_objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];

	pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);

	rc = pmd_log_create(mp, layout);
	if (!rc) {
		pmd_uc_lock(cinfo, cslot);
		found = pmd_uc_remove(cinfo, layout);
		pmd_uc_unlock(cinfo);

		pmd_co_wlock(cinfo, cslot);
		found = pmd_co_insert(cinfo, layout);
		if (!found)
			layout->eld_state |= PMD_LYT_COMMITTED;
		pmd_co_wunlock(cinfo);

		if (found) {
			rc = -EEXIST;

			/*
			 * if objid exists in committed object list this is a
			 * SERIOUS bug; need to log a warning message; should
			 * never happen. Note in this case we are stuck because
			 * we just logged a second create for an existing
			 * object.  If mdc compaction runs before a restart this
			 * extraneous create record will be eliminated,
			 * otherwise pmd_objs_load() will see the conflict and
			 * fail the next mpool activation.  We could make
			 * pmd_objs_load() tolerate this but for now it is
			 * better to get an activation failure so that
			 * it's obvious this bug occurred. Best we can do is put
			 * the layout back in the uncommitted object list so the
			 * caller can abort after getting the commit failure.
			 */
			mp_pr_crit("mpool %s, obj 0x%lx collided during commit",
				   rc, mp->pds_name, (ulong)layout->eld_objid);

			/* Put the object back in the uncommitted objects tree */
			pmd_uc_lock(cinfo, cslot);
			pmd_uc_insert(cinfo, layout);
			pmd_uc_unlock(cinfo);
		} else {
			atomic_inc(&cinfo->mmi_pco_cnt.pcc_cr);
			atomic_inc(&cinfo->mmi_pco_cnt.pcc_cobj);
		}
	}

	pmd_mdc_unlock(&cinfo->mmi_compactlock);
	pmd_obj_wrunlock(layout);

	if (!rc)
		pmd_update_obj_stats(mp, layout, cinfo, PMD_OBJ_COMMIT);

	return rc;
}

static void pmd_obj_erase_cb(struct work_struct *work)
{
	struct pmd_obj_erase_work *oef;
	struct mpool_descriptor *mp;
	struct pmd_layout *layout;

	oef = container_of(work, struct pmd_obj_erase_work, oef_wqstruct);
	mp = oef->oef_mp;
	layout = oef->oef_layout;

	pmd_layout_erase(mp, layout);

	if (oef->oef_cache)
		kmem_cache_free(oef->oef_cache, oef);

	pmd_layout_unprovision(mp, layout);
}

static void pmd_obj_erase_start(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_obj_erase_work oefbuf, *oef;
	bool async = true;

	oef = kmem_cache_zalloc(pmd_obj_erase_work_cache, GFP_KERNEL);
	if (!oef) {
		oef = &oefbuf;
		async = false;
	}

	/* If async oef will be freed in pmd_obj_erase_and_free() */
	oef->oef_mp = mp;
	oef->oef_layout = layout;
	oef->oef_cache = async ? pmd_obj_erase_work_cache : NULL;
	INIT_WORK(&oef->oef_wqstruct, pmd_obj_erase_cb);

	queue_work(mp->pds_erase_wq, &oef->oef_wqstruct);

	if (!async)
		flush_work(&oef->oef_wqstruct);
}

int pmd_obj_abort(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_mdc_info *cinfo;
	struct pmd_layout *found;
	long refcnt;
	u8 cslot;

	if (!objtype_user(objid_type(layout->eld_objid)))
		return -EINVAL;

	cslot = objid_slot(layout->eld_objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	found = NULL;

	pmd_obj_wrlock(layout);

	pmd_uc_lock(cinfo, cslot);
	refcnt = kref_read(&layout->eld_ref);
	if (refcnt == 2) {
		found = pmd_uc_remove(cinfo, layout);
		if (found)
			found->eld_state |= PMD_LYT_REMOVED;
	}
	pmd_uc_unlock(cinfo);

	pmd_obj_wrunlock(layout);

	if (!found)
		return (refcnt > 2) ? -EBUSY : -EINVAL;

	pmd_update_obj_stats(mp, layout, cinfo, PMD_OBJ_ABORT);
	pmd_obj_erase_start(mp, layout);

	/* Drop caller's reference... */
	pmd_obj_put(layout);

	return 0;
}

int pmd_obj_delete(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_mdc_info *cinfo;
	struct pmd_layout *found;
	long refcnt;
	u64 objid;
	u8 cslot;
	int rc;

	if (!objtype_user(objid_type(layout->eld_objid)))
		return -EINVAL;

	objid = layout->eld_objid;
	cslot = objid_slot(objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	found = NULL;

	/*
	 * Must log delete record before removing object for crash recovery.
	 * Must hold cinfo.compactlock while logging delete record and
	 * removing object from the list of committed objects to prevent
	 * race with MDC compaction
	 */
	pmd_obj_wrlock(layout);
	pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);

	refcnt = kref_read(&layout->eld_ref);
	if (refcnt != 2) {
		pmd_mdc_unlock(&cinfo->mmi_compactlock);
		pmd_obj_wrunlock(layout);

		return (refcnt > 2) ? -EBUSY : -EINVAL;
	}

	rc = pmd_log_delete(mp, objid);
	if (!rc) {
		pmd_co_wlock(cinfo, cslot);
		found = pmd_co_remove(cinfo, layout);
		if (found)
			found->eld_state |= PMD_LYT_REMOVED;
		pmd_co_wunlock(cinfo);
	}

	pmd_mdc_unlock(&cinfo->mmi_compactlock);
	pmd_obj_wrunlock(layout);

	if (!found) {
		mp_pr_rl("mpool %s, objid 0x%lx, pmd_log_del failed",
			 rc, mp->pds_name, (ulong)objid);
		return rc;
	}

	atomic_inc(&cinfo->mmi_pco_cnt.pcc_del);
	atomic_dec(&cinfo->mmi_pco_cnt.pcc_cobj);
	pmd_update_obj_stats(mp, layout, cinfo, PMD_OBJ_DELETE);
	pmd_obj_erase_start(mp, layout);

	/* Drop caller's reference... */
	pmd_obj_put(layout);

	return 0;
}

int pmd_obj_erase(struct mpool_descriptor *mp, struct pmd_layout *layout, u64 gen)
{
	u64 objid = layout->eld_objid;
	int rc;

	if ((pmd_objid_type(objid) != OMF_OBJ_MLOG) ||
	     (!(layout->eld_state & PMD_LYT_COMMITTED)) ||
	     (layout->eld_state & PMD_LYT_REMOVED) || (gen <= layout->eld_gen)) {
		mp_pr_warn("mpool %s, object erase failed to start, objid 0x%lx state 0x%x gen %lu",
			   mp->pds_name, (ulong)objid, layout->eld_state, (ulong)gen);

		return -EINVAL;
	}

	/*
	 * Must log the higher gen number for the old active mlog before
	 * updating object state (layout->eld_gen of the old active mlog).
	 * It is to guarantee that a activate after crash will know which is the
	 * new active mlog.
	 */

	if (objid_mdc0log(objid)) {
		/* Compact lock is held by the caller */

		/*
		 * Change MDC0 metadata image in RAM
		 */
		if (objid == MDC0_OBJID_LOG1)
			mp->pds_sbmdc0.osb_mdc01gen = gen;
		else
			mp->pds_sbmdc0.osb_mdc02gen = gen;

		/*
		 * Write the updated MDC0 metadata in the super blocks of the
		 * drives holding MDC0 metadata.
		 * Note: for 1.0, there is only one drive.
		 */
		rc = pmd_mdc0_meta_update(mp, layout);
		if (!rc)
			/*
			 * Update in-memory eld_gen, only if on-media
			 * gen gets successfully updated
			 */
			layout->eld_gen = gen;
	} else {
		struct pmd_mdc_info *cinfo;
		u8                   cslot;

		/*
		 * Take the MDC0 (or mlog MDCi for user MDC) compact lock to
		 * avoid a race with MDC0 (or mlog MDCi) compaction).
		 */
		cslot = objid_slot(layout->eld_objid);
		cinfo = &mp->pds_mda.mdi_slotv[cslot];

		pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);

		rc = pmd_log_erase(mp, layout->eld_objid, gen);
		if (!rc) {
			layout->eld_gen = gen;
			if (cslot)
				atomic_inc(&cinfo->mmi_pco_cnt.pcc_er);

		}
		pmd_mdc_unlock(&cinfo->mmi_compactlock);
	}

	return rc;
}

/**
 * pmd_alloc_idgen() - generate an id for an allocated object.
 * @mp:
 * @otype:
 * @objid: outpout
 *
 * Does a round robin on the MDC1/255 avoiding the ones that are candidate
 * for pre compaction.
 *
 * The round robin has a bias toward the MDCs with the smaller number of
 * objects. This is to recover from rare and very big allocation bursts.
 * During an allocation, the MDC[s] candidate for pre compaction are avoided.
 * If the allocation is a big burst, the result is that these MDC[s] have much
 * less objects in them as compared to the other ones.
 * After the burst if a relatively constant allocation rate takes place, the
 * deficit in objects of the MDCs avoided during the burst, is never recovered.
 * The bias in the round robin allows to recover. After a while all MDCs ends
 * up again with about the same number of objects.
 */
static int pmd_alloc_idgen(struct mpool_descriptor *mp, enum obj_type_omf otype, u64 *objid)
{
	struct pmd_mdc_info *cinfo = NULL;
	int rc = 0;
	u8 cslot;
	u32 tidx;

	if (mp->pds_mda.mdi_slotvcnt < 2) {
		/* No mdc available to assign object to; cannot use mdc0 */
		rc = -ENOSPC;
		mp_pr_err("mpool %s, no MDCi with i>0", rc, mp->pds_name);
		*objid = 0;
		return rc;
	}

	/* Get next mdc for allocation */
	tidx = atomic_inc_return(&mp->pds_mda.mdi_sel.mds_tbl_idx) % MDC_TBL_SZ;
	assert(tidx <= MDC_TBL_SZ);

	cslot = mp->pds_mda.mdi_sel.mds_tbl[tidx];
	cinfo = &mp->pds_mda.mdi_slotv[cslot];

	pmd_mdc_lock(&cinfo->mmi_uqlock, cslot);
	*objid = objid_make(cinfo->mmi_luniq + 1, otype, cslot);
	if (objid_ckpt(*objid)) {

		/*
		 * Must checkpoint objid before assigning it to an object
		 * to guarantee it will not reissue objid after a crash.
		 * Must hold cinfo.compactlock while log checkpoint to mdc
		 * to prevent a race with mdc compaction.
		 */
		pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);
		rc = pmd_log_idckpt(mp, *objid);
		if (!rc)
			cinfo->mmi_lckpt = *objid;
		pmd_mdc_unlock(&cinfo->mmi_compactlock);
	}

	if (!rc)
		cinfo->mmi_luniq = cinfo->mmi_luniq + 1;
	pmd_mdc_unlock(&cinfo->mmi_uqlock);

	if (rc) {
		mp_pr_rl("mpool %s, checkpoint append for objid 0x%lx failed",
			 rc, mp->pds_name, (ulong)*objid);
		*objid = 0;
		return rc;
	}

	return 0;
}

static int pmd_realloc_idvalidate(struct mpool_descriptor *mp, u64 objid)
{
	struct pmd_mdc_info *cinfo = NULL;
	u8 cslot = objid_slot(objid);
	u64 uniq = objid_uniq(objid);
	int rc = 0;

	/* We never realloc objects in mdc0 */
	if (!cslot) {
		rc = -EINVAL;
		mp_pr_err("mpool %s, can't re-allocate an object 0x%lx associated to MDC0",
			  rc, mp->pds_name, (ulong)objid);
		return rc;
	}

	spin_lock(&mp->pds_mda.mdi_slotvlock);
	if (cslot >= mp->pds_mda.mdi_slotvcnt)
		rc = -EINVAL;
	spin_unlock(&mp->pds_mda.mdi_slotvlock);

	if (rc) {
		mp_pr_err("mpool %s, realloc failed, slot number %u is too big %u 0x%lx",
			  rc, mp->pds_name, cslot, mp->pds_mda.mdi_slotvcnt, (ulong)objid);
	} else {
		cinfo = &mp->pds_mda.mdi_slotv[cslot];

		pmd_mdc_lock(&cinfo->mmi_uqlock, cslot);
		if (uniq > cinfo->mmi_luniq)
			rc = -EINVAL;
		pmd_mdc_unlock(&cinfo->mmi_uqlock);

		if (rc) {
			mp_pr_err("mpool %s, realloc failed, unique id %lu too big %lu 0x%lx",
				  rc, mp->pds_name, (ulong)uniq,
				  (ulong)cinfo->mmi_luniq, (ulong)objid);
		}
	}

	return rc;
}

/**
 * pmd_alloc_argcheck() -
 * @mp:      Mpool descriptor
 * @objid:   Object ID
 * @otype:   Object type
 * @mclassp: Media class
 */
static int pmd_alloc_argcheck(struct mpool_descriptor *mp, u64 objid,
			      enum obj_type_omf otype, enum mp_media_classp mclassp)
{
	int rc = -EINVAL;

	if (!mp)
		return rc;

	if (!objtype_user(otype) || !mclass_isvalid(mclassp)) {
		mp_pr_err("mpool %s, unknown object type or media class %d %d",
			  rc, mp->pds_name, otype, mclassp);
		return rc;
	}

	if (objid && objid_type(objid) != otype) {
		mp_pr_err("mpool %s, unknown object type mismatch %d %d",
			  rc, mp->pds_name, objid_type(objid), otype);
		return rc;
	}

	return 0;
}

int pmd_obj_alloc_cmn(struct mpool_descriptor *mp, u64 objid, enum obj_type_omf otype,
		      struct pmd_obj_capacity *ocap, enum mp_media_classp mclass,
		      int realloc, bool needref, struct pmd_layout **layoutp)
{
	struct pmd_mdc_info *cinfo;
	struct media_class *mc;
	struct pmd_layout *layout;
	struct mpool_uuid uuid;
	int retries, flush, rc;
	u64 zcnt = 0;
	u8  cslot;

	*layoutp = NULL;

	rc = pmd_alloc_argcheck(mp, objid, otype, mclass);
	if (rc)
		return rc;

	if (!objid) {
		/*
		 * alloc: generate objid, checkpoint as needed to
		 * support realloc of uncommitted objects after crash and to
		 * guarantee objids never reuse
		 */
		rc = pmd_alloc_idgen(mp, otype, &objid);
	} else if (realloc) {
		/* realloc: validate objid */
		rc = pmd_realloc_idvalidate(mp, objid);
	}
	if (rc)
		return rc;

	if (otype == OMF_OBJ_MLOG)
		mpool_generate_uuid(&uuid);

	/*
	 * Retry from 128 to 256ms with a flush every 1/8th of the retries.
	 * This is a workaround for the async mblock trim problem.
	 */
	retries = 1024;
	flush   = retries >> 3;

retry:
	down_read(&mp->pds_pdvlock);

	mc = &mp->pds_mc[mclass];
	if (mc->mc_pdmc < 0) {
		up_read(&mp->pds_pdvlock);
		return -ENOENT;
	}

	/* Calculate the height (zcnt) of layout. */
	pmd_layout_calculate(mp, ocap, mc, &zcnt);

	layout = pmd_layout_alloc(&uuid, objid, 0, 0, zcnt);
	if (!layout) {
		up_read(&mp->pds_pdvlock);
		return -ENOMEM;
	}

	/* Try to allocate zones from drives in media class */
	rc = pmd_layout_provision(mp, ocap, layout, mc, zcnt);
	up_read(&mp->pds_pdvlock);

	if (rc) {
		pmd_obj_put(layout);

		/* TODO: Retry only if mperasewq is busy... */
		if (retries-- > 0) {
			usleep_range(128, 256);

			if (flush && (retries % flush == 0))
				flush_workqueue(mp->pds_erase_wq);

			goto retry;
		}

		mp_pr_rl("mpool %s, layout alloc failed: objid 0x%lx %lu %u",
			 rc, mp->pds_name, (ulong)objid, (ulong)zcnt, otype);

		return rc;
	}

	cslot = objid_slot(objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];

	pmd_update_obj_stats(mp, layout, cinfo, PMD_OBJ_ALLOC);

	if (needref)
		kref_get(&layout->eld_ref);

	/*
	 * If realloc, we MUST confirm (while holding the uncommitted obj
	 * tree lock) that objid is not in the committed obj tree in order
	 * to protect against an invalid *_realloc() call.
	 */
	pmd_uc_lock(cinfo, cslot);
	if (realloc) {
		pmd_co_rlock(cinfo, cslot);
		if (pmd_co_find(cinfo, objid))
			rc = -EEXIST;
		pmd_co_runlock(cinfo);
	}

	/*
	 * For both alloc and realloc, confirm that objid is not in the
	 * uncommitted obj tree and insert it.  Note that a reallocated
	 * objid can collide, but a generated objid should never collide.
	 */
	if (!rc && pmd_uc_insert(cinfo, layout))
		rc = -EEXIST;
	pmd_uc_unlock(cinfo);

	if (rc) {
		mp_pr_err("mpool %s, %sallocated obj 0x%lx should not be in the %scommitted tree",
			  rc, mp->pds_name, realloc ? "re-" : "",
			  (ulong)objid, realloc ? "" : "un");

		if (needref)
			pmd_obj_put(layout);

		/*
		 * Since object insertion failed, we need to undo the
		 * per-mdc stats update we did earlier in this routine
		 */
		pmd_update_obj_stats(mp, layout, cinfo, PMD_OBJ_ABORT);
		pmd_layout_unprovision(mp, layout);
		layout = NULL;
	}

	*layoutp = layout;

	return rc;
}

void pmd_mpool_usage(struct mpool_descriptor *mp, struct mpool_usage *usage)
{
	int sidx;
	u16 slotvcnt;

	/*
	 * Get a local copy of MDC count (slotvcnt), and then drop the lock
	 * It's okay another MDC is added concurrently, since pds_ds_info
	 * is always stale by design
	 */
	spin_lock(&mp->pds_mda.mdi_slotvlock);
	slotvcnt = mp->pds_mda.mdi_slotvcnt;
	spin_unlock(&mp->pds_mda.mdi_slotvlock);

	for (sidx = 1; sidx < slotvcnt; sidx++) {
		struct pmd_mdc_stats   *pms;
		struct pmd_mdc_info    *cinfo;

		cinfo = &mp->pds_mda.mdi_slotv[sidx];
		pms   = &cinfo->mmi_stats;

		mutex_lock(&cinfo->mmi_stats_lock);
		usage->mpu_mblock_alen += pms->pms_mblock_alen;
		usage->mpu_mblock_wlen += pms->pms_mblock_wlen;
		usage->mpu_mlog_alen   += pms->pms_mlog_alen;
		usage->mpu_mblock_cnt  += pms->pms_mblock_cnt;
		usage->mpu_mlog_cnt    += pms->pms_mlog_cnt;
		mutex_unlock(&cinfo->mmi_stats_lock);
	}

	if (slotvcnt < 2)
		return;

	usage->mpu_alen = (usage->mpu_mblock_alen + usage->mpu_mlog_alen);
	usage->mpu_wlen = (usage->mpu_mblock_wlen + usage->mpu_mlog_alen);
}

/**
 * pmd_mdc0_meta_update_update() - update on media the MDC0 metadata.
 * @mp:
 * @layout: Used to know on which drives to write the MDC0 metadata.
 *
 * For now write the whole super block, but only the MDC0 metadata needs
 * to be updated, the rest of the superblock doesn't change.
 *
 * In 1.0 the MDC0 metadata is replicated on the 4 superblocks of the drive.
 * In case of failure, the SBs of a same drive may end up having different
 * values for the MDC0 metadata.
 * To address this situation voting could be used along with the SB gen number
 * psb_gen. But for 1.0 a simpler approach is taken: SB gen number is not used
 * and SB0 is the authoritative replica. The other 3 replicas of MDC0 metadata
 * are not used when the mpool activates.
 */
static int pmd_mdc0_meta_update(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct omf_sb_descriptor *sb;
	struct mpool_dev_info *pd;
	struct mc_parms mc_parms;
	int rc;

	pd = &(mp->pds_pdv[layout->eld_ld.ol_pdh]);
	if (mpool_pd_status_get(pd) != PD_STAT_ONLINE) {
		rc = -EIO;
		mp_pr_err("%s: pd %s unavailable or offline, status %d",
			  rc, mp->pds_name, pd->pdi_name, mpool_pd_status_get(pd));
		return rc;
	}

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	if (!sb)
		return -ENOMEM;

	/*
	 * set superblock values common to all new drives in pool
	 * (new or extant)
	 */
	sb->osb_magic = OMF_SB_MAGIC;
	strlcpy((char *) sb->osb_name, mp->pds_name, sizeof(sb->osb_name));
	sb->osb_vers = OMF_SB_DESC_VER_LAST;
	mpool_uuid_copy(&sb->osb_poolid, &mp->pds_poolid);
	sb->osb_gen = 1;

	/* Set superblock values specific to this drive */
	mpool_uuid_copy(&sb->osb_parm.odp_devid, &pd->pdi_devid);
	sb->osb_parm.odp_devsz = pd->pdi_parm.dpr_devsz;
	sb->osb_parm.odp_zonetot = pd->pdi_parm.dpr_zonetot;
	mc_pd_prop2mc_parms(&pd->pdi_parm.dpr_prop, &mc_parms);
	mc_parms2omf_devparm(&mc_parms, &sb->osb_parm);

	sbutil_mdc0_copy(sb, &mp->pds_sbmdc0);

	mp_pr_debug("MDC0 compaction gen1 %lu gen2 %lu",
		    0, (ulong)sb->osb_mdc01gen, (ulong)sb->osb_mdc02gen);

	/*
	 * sb_write_update() succeeds if at least SB0 is written. It is
	 * not a problem to have SB1 not written because the authoritative
	 * MDC0 metadata replica is the one in SB0.
	 */
	rc = sb_write_update(&pd->pdi_parm, sb);
	if (rc)
		mp_pr_err("compacting %s MDC0, writing superblock on drive %s failed",
			  rc, mp->pds_name, pd->pdi_name);

	kfree(sb);
	return rc;
}

/**
 * pmd_update_obj_stats() - update per-MDC space usage
 * @mp:
 * @layout:
 * @cinfo:
 * @op: object opcode
 */
void pmd_update_obj_stats(struct mpool_descriptor *mp, struct pmd_layout *layout,
			  struct pmd_mdc_info *cinfo, enum pmd_obj_op op)
{
	struct pmd_mdc_stats *pms;
	enum obj_type_omf otype;
	u64 cap;

	otype = pmd_objid_type(layout->eld_objid);

	mutex_lock(&cinfo->mmi_stats_lock);
	pms = &cinfo->mmi_stats;

	/* Update space usage and mblock/mlog count */
	switch (op) {
	case PMD_OBJ_LOAD:
		if (otype == OMF_OBJ_MBLOCK)
			pms->pms_mblock_wlen += layout->eld_mblen;
		/* Fall through */

	case PMD_OBJ_ALLOC:
		cap = pmd_layout_cap_get(mp, layout);
		if (otype == OMF_OBJ_MLOG) {
			pms->pms_mlog_cnt++;
			pms->pms_mlog_alen += cap;
		} else if (otype == OMF_OBJ_MBLOCK) {
			pms->pms_mblock_cnt++;
			pms->pms_mblock_alen += cap;
		}
		break;

	case PMD_OBJ_COMMIT:
		if (otype == OMF_OBJ_MBLOCK)
			pms->pms_mblock_wlen += layout->eld_mblen;
		break;

	case PMD_OBJ_DELETE:
		if (otype == OMF_OBJ_MBLOCK)
			pms->pms_mblock_wlen -= layout->eld_mblen;
		/* Fall through */

	case PMD_OBJ_ABORT:
		cap = pmd_layout_cap_get(mp, layout);
		if (otype == OMF_OBJ_MLOG) {
			pms->pms_mlog_cnt--;
			pms->pms_mlog_alen -= cap;
		} else if (otype == OMF_OBJ_MBLOCK) {
			pms->pms_mblock_cnt--;
			pms->pms_mblock_alen -= cap;
		}
		break;

	default:
		assert(0);
		break;
	}

	mutex_unlock(&cinfo->mmi_stats_lock);
}

/**
 * pmd_compare_free_space - compare free space between MDCs
 * @f:  First  MDC
 * @s:  Second MDC
 *
 * Arrange MDCs in descending order of free space
 */
static int pmd_compare_free_space(const void *first, const void *second)
{
	const struct pmd_mdc_info *f = *(const struct pmd_mdc_info **)first;
	const struct pmd_mdc_info *s = *(const struct pmd_mdc_info **)second;

	/* return < 0 - first member should be ahead for second */
	if (f->mmi_credit.ci_free > s->mmi_credit.ci_free)
		return -1;

	/* return > 0 - first member should be after second */
	if (f->mmi_credit.ci_free < s->mmi_credit.ci_free)
		return 1;

	return 0;

}

/**
 * pmd_update_ms_tbl() - udpates mds_tlb with MDC slot numbers
 * @mp:  mpool descriptor
 * @slotnum:  array of slot numbers
 *
 * This function creates an array of mdc slot and credit sets by interleaving
 * MDC slots. Interleave maximize the interval at which the slots appear in
 * the mds_tbl.
 *
 * The first set in the array is reference set with only 1 member and has max
 * assigned credits. Subsequent sets are formed to match the reference set and
 * may contain one or more member such that total credit of the set will match
 * the reference set. The last set may have fewer credit than the reference set
 *
 * Locking: no lock need to be held when calling this function.
 *
 */
static void pmd_update_mds_tbl(struct mpool_descriptor *mp, u8 num_mdc, u8 *slotnum)
{
	struct mdc_credit_set *cset, *cs;
	struct pmd_mdc_info *cinfo;
	u16 refcredit, neededcredit, tidx, totalcredit = 0;
	u8 csidx, csmidx, num_cset, i;

	cset = kcalloc(num_mdc, sizeof(*cset), GFP_KERNEL);
	if (!cset)
		return;

	cinfo = &mp->pds_mda.mdi_slotv[slotnum[0]];
	refcredit = cinfo->mmi_credit.ci_credit;

	csidx = 0; /* creditset index */
	i     = 0; /* slotnum index   */
	while (i < num_mdc) {
		cs = &cset[csidx++];
		neededcredit = refcredit;

		csmidx = 0;
		/* Setup members of the credit set */
		while (csmidx < MPOOL_MDC_SET_SZ  && i < num_mdc) {
			/* slot 0 should never be there */
			assert(slotnum[i] != 0);

			cinfo = &mp->pds_mda.mdi_slotv[slotnum[i]];
			cs->cs_num_csm = csmidx + 1;
			cs->csm[csmidx].m_slot = slotnum[i];

			if (neededcredit <= cinfo->mmi_credit.ci_credit) {
				/*
				 * More than required credit is available,
				 * leftover will be assigned to the next set.
				 */
				cs->csm[csmidx].m_credit    += neededcredit;
				cinfo->mmi_credit.ci_credit -= neededcredit;
				totalcredit += neededcredit; /* Debug */
				neededcredit = 0;

				/* Some credit available stay at this mdc */
				if (cinfo->mmi_credit.ci_credit == 0)
					i++;
				break;
			}

			/*
			 * Available credit is < needed, assign all
			 * the available credit and move to the next
			 * mdc slot.
			 */
			cs->csm[csmidx].m_credit += cinfo->mmi_credit.ci_credit;
			neededcredit -= cinfo->mmi_credit.ci_credit;
			totalcredit  += cinfo->mmi_credit.ci_credit;
			cinfo->mmi_credit.ci_credit = 0;

			/* Move to the next mdcslot and set member */
			i++;
			csmidx++;
		}
	}
	assert(totalcredit == MDC_TBL_SZ);
	num_cset = csidx;

	tidx  = 0;
	csidx = 0;
	while (tidx < MDC_TBL_SZ) {
		cs = &cset[csidx];
		if (cs->cs_idx < cs->cs_num_csm) {
			csmidx = cs->cs_idx;
			if (cs->csm[csmidx].m_credit) {
				cs->csm[csmidx].m_credit--;
				mp->pds_mda.mdi_sel.mds_tbl[tidx] = cs->csm[csmidx].m_slot;
				totalcredit--;

				if (cs->csm[csmidx].m_credit == 0)
					cs->cs_idx += 1;

				tidx++;
			}
		}
		/* Loop over the sets */
		csidx = (csidx + 1) % num_cset;
	}
	assert(totalcredit == 0);

	kfree(cset);
}

/**
 * pmd_update_credit() - udpates MDC credit if new MDCs should be created
 * @mp:  mpool descriptor
 *
 * Credits are assigned as a ratio between MDC such that MDC with least free
 * space will fill up at the same time as other MDC.
 *
 * Locking: no lock need to be held when calling this function.
 *
 */
void pmd_update_credit(struct mpool_descriptor *mp)
{
	struct pre_compact_ctrs *pco_cnt;
	struct pmd_mdc_info *cinfo;
	u64 cap, used, free, nmtoc;
	u16 credit, cslot;
	u8 sidx, nidx, num_mdc;
	u8 *slotnum;
	void **sarray = mp->pds_mda.mdi_sel.mds_smdc;
	u32 nbnoalloc = (u32)mp->pds_params.mp_pconbnoalloc;

	if (mp->pds_mda.mdi_slotvcnt < 2) {
		mp_pr_warn("Not enough MDCn %u", mp->pds_mda.mdi_slotvcnt - 1);
		return;
	}

	slotnum = kcalloc(MDC_SLOTS, sizeof(*slotnum), GFP_KERNEL);
	if (!slotnum) {
		mp_pr_err("slotnum array alloc failed", -ENOMEM);
		return;
	}

	nmtoc = atomic_read(&mp->pds_pco.pco_nmtoc);
	nmtoc = nmtoc % (mp->pds_mda.mdi_slotvcnt - 1) + 1;

	/*
	 * slotvcnt includes MDC 0 and MDCn that are in precompaction
	 * list and should be excluded. If there are less than (nbnoalloc
	 * +2) MDCs exclusion is not possible. 2 is added to account for
	 * MDC0 and the MDC pointed to by pco_nmtoc.
	 *
	 * MDC that is in pre-compacting state and two MDCs that follows
	 * are excluded from allocation. This is done to prevent stall/
	 * delays for a sync that follows an allocation as both
	 * take a compaction lock.
	 */
	if (mp->pds_mda.mdi_slotvcnt < (nbnoalloc + 2)) {
		num_mdc = mp->pds_mda.mdi_slotvcnt - 1;
		cslot  = 1;
		mp_pr_debug("MDCn cnt %u, cannot skip %u num_mdc %u",
			    0, mp->pds_mda.mdi_slotvcnt - 1, (u32)nmtoc, num_mdc);
	} else {
		num_mdc = mp->pds_mda.mdi_slotvcnt - (nbnoalloc + 2);
		cslot = (nmtoc + nbnoalloc) % (mp->pds_mda.mdi_slotvcnt - 1);
	}


	/* Walkthrough all MDCs and exclude MDCs that are almost full */
	for (nidx = 0, sidx = 0; nidx < num_mdc; nidx++) {
		cslot = cslot % (mp->pds_mda.mdi_slotvcnt - 1) + 1;

		if (cslot == 0)
			cslot = 1;

		cinfo = &mp->pds_mda.mdi_slotv[cslot];
		pco_cnt = &(cinfo->mmi_pco_cnt);

		cap  = atomic64_read(&pco_cnt->pcc_cap);
		used = atomic64_read(&pco_cnt->pcc_len);

		if ((cap - used) < (cap / 400)) {
			/* Consider < .25% free space as full */
			mp_pr_warn("MDC slot %u almost full", cslot);
			continue;
		}
		sarray[sidx++] = cinfo;
		cinfo->mmi_credit.ci_free = cap - used;
	}

	/* Sort the array with decreasing order of space */
	sort((void *)sarray, sidx, sizeof(sarray[0]), pmd_compare_free_space, NULL);
	num_mdc = sidx;

	/* Calculate total free space across the chosen MDC set */
	for (sidx = 0, free = 0; sidx < num_mdc; sidx++) {
		cinfo = sarray[sidx];
		free += cinfo->mmi_credit.ci_free;
		slotnum[sidx] = cinfo->mmi_credit.ci_slot;
	}

	/*
	 * Assign credit to MDCs in the MDC set. Credit is relative and
	 * will not exceed the total slots in mds_tbl
	 */
	for (sidx = 0, credit = 0; sidx < num_mdc; sidx++) {
		cinfo = &mp->pds_mda.mdi_slotv[slotnum[sidx]];
		cinfo->mmi_credit.ci_credit = (MDC_TBL_SZ * cinfo->mmi_credit.ci_free) / free;
		credit += cinfo->mmi_credit.ci_credit;
	}
	assert(credit <= MDC_TBL_SZ);

	/*
	 * If the credit is not equal to the table size, assign
	 * credits so table can be filled all the way.
	 */
	if (credit < MDC_TBL_SZ) {
		credit = MDC_TBL_SZ - credit;

		sidx = 0;
		while (credit > 0) {
			sidx = (sidx % num_mdc);
			cinfo = &mp->pds_mda.mdi_slotv[slotnum[sidx]];
			cinfo->mmi_credit.ci_credit += 1;
			sidx++;
			credit--;
		}
	}

	pmd_update_mds_tbl(mp, num_mdc, slotnum);

	kfree(slotnum);
}

/*
 * pmd_mlogid2cslot() - Given an mlog object ID which makes one of the mpool
 *	core MDCs (MDCi with i >0), it returns i.
 *	Given an client created object ID (mblock or mlog), it returns -1.
 * @mlogid:
 */
static int pmd_mlogid2cslot(u64 mlogid)
{
	u64 uniq;

	if (pmd_objid_type(mlogid) != OMF_OBJ_MLOG)
		return -1;
	if (objid_slot(mlogid))
		return -1;
	uniq = objid_uniq(mlogid);
	if (uniq > (2 * MDC_SLOTS) - 1)
		return -1;

	return(uniq/2);
}

void pmd_precompact_alsz(struct mpool_descriptor *mp, u64 objid, u64 len, u64 cap)
{
	struct pre_compact_ctrs *pco_cnt;
	struct pmd_mdc_info *cinfo;
	int ret;
	u8 cslot;

	ret = pmd_mlogid2cslot(objid);
	if (ret <= 0)
		return;

	cslot = ret;
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	pco_cnt = &(cinfo->mmi_pco_cnt);
	atomic64_set(&pco_cnt->pcc_len, len);
	atomic64_set(&pco_cnt->pcc_cap, cap);
}

int pmd_init(void)
{
	int rc = 0;

	/* Initialize the slab caches. */
	pmd_layout_cache = kmem_cache_create("mpool_pmd_layout", sizeof(struct pmd_layout),
					     0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);
	if (!pmd_layout_cache) {
		rc = -ENOMEM;
		mp_pr_err("kmem_cache_create(pmd_layout, %zu) failed",
			  rc, sizeof(struct pmd_layout));
		goto errout;
	}

	pmd_layout_priv_cache = kmem_cache_create("mpool_pmd_layout_priv",
				sizeof(struct pmd_layout) + sizeof(union pmd_layout_priv),
				0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);
	if (!pmd_layout_priv_cache) {
		rc = -ENOMEM;
		mp_pr_err("kmem_cache_create(pmd priv, %zu) failed",
			  rc, sizeof(union pmd_layout_priv));
		goto errout;
	}

	pmd_obj_erase_work_cache = kmem_cache_create("mpool_pmd_obj_erase_work",
						     sizeof(struct pmd_obj_erase_work),
						     0, SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);
	if (!pmd_obj_erase_work_cache) {
		rc = -ENOMEM;
		mp_pr_err("kmem_cache_create(pmd_obj_erase, %zu) failed",
			  rc, sizeof(struct pmd_obj_erase_work));
		goto errout;
	}

errout:
	if (rc)
		pmd_exit();

	return rc;
}

void pmd_exit(void)
{
	kmem_cache_destroy(pmd_obj_erase_work_cache);
	kmem_cache_destroy(pmd_layout_priv_cache);
	kmem_cache_destroy(pmd_layout_cache);

	pmd_obj_erase_work_cache = NULL;
	pmd_layout_priv_cache = NULL;
	pmd_layout_cache = NULL;
}
