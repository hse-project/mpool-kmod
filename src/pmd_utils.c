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

#include "mpool_defs.h"
#include "pmd_utils.h"

/*
 * Alloc and init object layout; non-arg fields and all strip descriptor
 * fields are set to 0/UNDEF/NONE; no auxiliary object info is allocated.
 *
 * Returns NULL if allocation fails.
 */
struct pmd_layout *
pmd_layout_alloc(
	struct mpool_descriptor    *mp,
	struct mpool_uuid          *uuid,
	u64                         objid,
	u64                         gen,
	u64                         mblen,
	u32                         zcnt)
{
	struct kmem_cache *cache = pmd_layout_cache;
	struct pmd_layout *layout;

	if (pmd_objid_type(objid) == OMF_OBJ_MLOG)
		cache = pmd_layout_priv_cache;

	layout = kmem_cache_zalloc(cache, GFP_KERNEL);
	if (ev(!layout))
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

struct pmd_layout *pmd_layout_find(struct rb_root *root, u64 key)
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

struct pmd_layout *pmd_layout_insert(struct rb_root *root, struct pmd_layout *item)
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

void pmd_layout_unprovision(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	merr_t  err;
	u16     pdh;

	pdh = layout->eld_ld.ol_pdh;

	err = smap_free(mp, pdh, layout->eld_ld.ol_zaddr,
			layout->eld_ld.ol_zcnt);
	if (err) {
		/* smap_free() should never fail */
		mp_pr_err("releasing %s drive %s space for layout failed, objid 0x%lx",
			  err, mp->pds_name, mp->pds_pdv[pdh].pdi_name, (ulong)layout->eld_objid);
	}

	/* Drop birth reference... */
	pmd_obj_put(mp, layout);
}

/**
 * pmd_layout_calculate() -
 * @mp:
 * @ocap:
 * @mc:
 * @zcnt:
 * @otype:
 */
void
pmd_layout_calculate(
	struct mpool_descriptor   *mp,
	struct pmd_obj_capacity   *ocap,
	struct media_class        *mc,
	u64                       *zcnt,
	enum obj_type_omf          otype)
{
	u32    zonepg;

	zonepg = mp->pds_pdv[mc->mc_pdmc].pdi_parm.dpr_zonepg;

	if (!ocap->moc_captgt) {
		/* Obj capacity not specified; use one zone. */
		*zcnt = 1;
		return;
	}

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
merr_t
pmd_layout_provision(
	struct mpool_descriptor    *mp,
	struct pmd_obj_capacity    *ocap,
	struct pmd_layout          *layout,
	struct media_class         *mc,
	u64                         zcnt)
{
	enum smap_space_type    spctype;
	struct mc_smap_parms    mcsp;

	u64     zoneaddr, align;
	u8      pdh;
	merr_t  err;

	spctype = SMAP_SPC_USABLE_ONLY;
	if (ocap->moc_spare)
		spctype = SMAP_SPC_SPARE_2_USABLE;

	/* To reduce/eliminate fragmenation, make sure the alignment is a power of 2. */
	err = mc_smap_parms_get(mp, mc->mc_parms.mcp_classp, &mcsp);
	if (ev(err))
		return err;

	align = min_t(u64, zcnt, mcsp.mcsp_align);
	align = roundup_pow_of_two(align);

	pdh = mc->mc_pdmc;
	err = smap_alloc(mp, pdh, zcnt, spctype, &zoneaddr, align);
	if (ev(err))
		return err;

	layout->eld_ld.ol_pdh = pdh;
	layout->eld_ld.ol_zaddr = zoneaddr;

	return 0;
}

merr_t
pmd_layout_rw(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	const struct kvec          *iov,
	int                         iovcnt,
	u64                         boff,
	int                         flags,
	u8                          rw)
{
	struct mpool_dev_info  *pd;
	u64                     zaddr;
	merr_t                  err;

	if (!mp || !layout || !iov)
		return merr(EINVAL);

	if (rw != MPOOL_OP_READ && rw != MPOOL_OP_WRITE)
		return merr(EINVAL);

	pd = &mp->pds_pdv[layout->eld_ld.ol_pdh];
	if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL)
		return merr(EIO);

	if (iovcnt == 0)
		return 0;

	zaddr = layout->eld_ld.ol_zaddr;
	if (rw == MPOOL_OP_READ)
		err = pd_zone_preadv(pd, iov, iovcnt, zaddr, boff);
	else
		err = pd_zone_pwritev(pd, iov, iovcnt, zaddr, boff, flags);

	if (ev(err))
		mpool_pd_status_set(pd, PD_STAT_OFFLINE);

	return err;
}

merr_t pmd_layout_erase(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct mpool_dev_info  *pd;
	merr_t                  err;

	if (!mp || !layout)
		return merr(EINVAL);

	pd = &mp->pds_pdv[layout->eld_ld.ol_pdh];
	if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL)
		return merr(EIO);

	err = pd_zone_erase(pd, layout->eld_ld.ol_zaddr, layout->eld_ld.ol_zcnt,
			    pmd_objid_type(layout->eld_objid) == OMF_OBJ_MLOG);
	if (ev(err))
		mpool_pd_status_set(pd, PD_STAT_OFFLINE);

	return err;
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

merr_t pmd_smap_insert(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	merr_t  err;
	u16     pdh;

	pdh = layout->eld_ld.ol_pdh;

	err = smap_insert(mp, pdh, layout->eld_ld.ol_zaddr, layout->eld_ld.ol_zcnt);
	if (err) {
		/* Insert should never fail */
		mp_pr_err("mpool %s, allocating drive %s space for layout failed, objid 0x%lx",
			  err, mp->pds_name, mp->pds_pdv[pdh].pdi_name, (ulong)layout->eld_objid);
	}

	return err;
}

/**
 * pmd_update_mdc_stats() - update per-MDC space usage
 * @mp:
 * @layout:
 * @cinfo:
 * @op: object opcode
 */
void
pmd_update_mdc_stats(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	struct pmd_mdc_info        *cinfo,
	enum pmd_obj_op             op)
{
	struct pmd_mdc_stats   *pms;
	enum obj_type_omf       otype;
	u64                     cap;

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

merr_t pmd_mdc_append(struct mpool_descriptor *mp, u8 cslot, struct omf_mdcrec_data *cdr, int sync)
{
	merr_t                  err;
	struct pmd_mdc_info    *cinfo = &mp->pds_mda.mdi_slotv[cslot];
	s64                     plen;

	plen = omf_mdcrec_pack_htole(mp, cdr, cinfo->mmi_recbuf);
	if (plen < 0) {
		mp_pr_warn("mpool %s, MDC%u append failed", mp->pds_name, cslot);
		return plen;
	}

	err = mp_mdc_append(cinfo->mmi_mdc, cinfo->mmi_recbuf, plen, sync);
	ev(err);

	return err;
}

/**
 * pmd_mdc_needed() - determines if new MDCns should be created
 * @mp:  mpool descriptor
 *
 * New MDC's are created if total free space across all MDC's
 * is above a threshold value and the garbage to reclaim space
 * is below a garbage threshold.
 *
 * Locking: no lock needs to be held when calling this function.
 *
 * NOTES:
 * - Skip non-active MDC
 * - Accumulate total capacity, total garbage and total in-use capacity
 *   across all active MDCs.
 * - Return true if total used capacity across all MDCs is threshold and
 *   garbage is < a threshold that would yield significant free space upon
 *   compaction.
 */
bool pmd_mdc_needed(struct mpool_descriptor *mp)
{
	struct pmd_mdc_info        *cinfo;
	struct pre_compact_ctrs    *pco_cnt;

	u64    cap, tcap, used, garbage, record, rec, cobj;
	u32    pct, pctg, mdccnt;
	u16    cslot;

	cap = used = garbage = record = pctg = 0;

	assert(mp->pds_mda.mdi_slotvcnt <= MDC_SLOTS);
	if (mp->pds_mda.mdi_slotvcnt == MDC_SLOTS)
		return false;

	for (cslot = 1, mdccnt = 0; cslot < mp->pds_mda.mdi_slotvcnt; cslot++) {

		cinfo = &mp->pds_mda.mdi_slotv[cslot];
		pco_cnt = &(cinfo->mmi_pco_cnt);

		tcap = atomic64_read(&pco_cnt->pcc_cap);
		if (tcap == 0) {
			/*
			 * MDC closed for now and will not be considered
			 * in making a decision to create new MDC.
			 */
			mp_pr_warn("MDC %u not open", cslot);
			continue;
		}
		cap += tcap;

		mdccnt++;

		used += atomic64_read(&pco_cnt->pcc_len);
		rec = atomic_read(&pco_cnt->pcc_cr) + atomic_read(&pco_cnt->pcc_up) +
			atomic_read(&pco_cnt->pcc_del) + atomic_read(&pco_cnt->pcc_er);

		cobj = atomic_read(&pco_cnt->pcc_cobj);

		if (rec > cobj)
			garbage += (rec - cobj);

		record += rec;
	}

	if (mdccnt == 0) {
		mp_pr_warn("No mpool MDCs available");
		return false;
	}

	/* Percentage capacity used across all MDCs */
	pct  = (used  * 100) / cap;

	/* Percentage garbage available across all MDCs */
	if (garbage)
		pctg = (garbage * 100) / record;

	if (pct > mp->pds_params.mp_crtmdcpctfull && pctg < mp->pds_params.mp_crtmdcpctgrbg) {
		merr_t err = 0;

		mp_pr_debug("MDCn %u cap %u used %u rec %u grbg %u pct used %u grbg %u Thres %u-%u",
			    err, mdccnt, (u32)cap, (u32)used, (u32)record, (u32)garbage, pct, pctg,
			    (u32)mp->pds_params.mp_crtmdcpctfull,
			    (u32)mp->pds_params.mp_crtmdcpctgrbg);
		return true;
	}

	return false;
}

/**
 * pmd_alloc_argcheck() -
 * @mp:      Mpool descriptor
 * @objid:   Object ID
 * @otype:   Object type
 * @ocap:    Object capacity info
 * @mclassp: Media class
 */
merr_t
pmd_alloc_argcheck(
	struct mpool_descriptor    *mp,
	u64                         objid,
	enum obj_type_omf           otype,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclassp)
{
	merr_t err;

	if (!mp)
		return merr(EINVAL);

	if (!objtype_user(otype) || !mclass_isvalid(mclassp)) {
		err = merr(EINVAL);
		mp_pr_err("mpool %s, unknown object type or media class %d %d",
			  err, mp->pds_name, otype, mclassp);
		return err;
	}

	if (objid && objid_type(objid) != otype) {
		err = merr(EINVAL);
		mp_pr_err("mpool %s, unknown object type mismatch %d %d",
			  err, mp->pds_name, objid_type(objid), otype);
		return err;
	}

	return 0;
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
	struct mdc_credit_set  *cset, *cs;
	struct pmd_mdc_info    *cinfo;

	u8     csidx, csmidx, num_cset, i;
	u16    refcredit, neededcredit, tidx, totalcredit = 0;

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
	struct pmd_mdc_info        *cinfo;
	struct pre_compact_ctrs    *pco_cnt;

	u64      cap, used, free, nmtoc;
	u16      credit, cslot;
	u8       sidx, nidx, num_mdc;
	u8       slotnum[MDC_SLOTS] = { 0 };
	void   **sarray = mp->pds_mda.mdi_sel.mds_smdc;
	u32      nbnoalloc = (u32)mp->pds_params.mp_pconbnoalloc;

	if (mp->pds_mda.mdi_slotvcnt < 2) {
		mp_pr_warn("Not enough MDCn %u", mp->pds_mda.mdi_slotvcnt - 1);
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
	 * delays for a sync that follows an allocation as both take
	 * take a compaction lock.
	 */
	if (mp->pds_mda.mdi_slotvcnt < (nbnoalloc + 2)) {
		merr_t err = 0;

		num_mdc = mp->pds_mda.mdi_slotvcnt - 1;
		cslot  = 1;
		mp_pr_debug("MDCn cnt %u, cannot skip %u num_mdc %u",
			    err, mp->pds_mda.mdi_slotvcnt - 1, (u32)nmtoc, num_mdc);
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
	struct pre_compact_ctrs    *pco_cnt;
	struct pmd_mdc_info        *cinfo;

	int    ret;
	u8     cslot;

	ret = pmd_mlogid2cslot(objid);
	if (ret <= 0)
		return;

	cslot = ret;
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	pco_cnt = &(cinfo->mmi_pco_cnt);
	atomic64_set(&pco_cnt->pcc_len, len);
	atomic64_set(&pco_cnt->pcc_cap, cap);
}

void pmd_mpool_usage(struct mpool_descriptor *mp, struct mpool_usage *usage)
{
	int    sidx;
	u16    slotvcnt;

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
 * pmd_need_compact() - determine if MDCi corresponding to cslot
 *	need compaction of not.
 * @mp:
 * @cslot:
 *
 * The MDCi needs compaction if the active mlog is above some threshold and
 * if there is enough garbage (that can be eliminated by the compaction).
 *
 * Locking: not lock need to be held when calling this function.
 *	as a result of not holding lock the result may be off if a compaction
 *	of MDCi (with i = cslot) is taking place at the same time.
 */
bool pmd_need_compact(struct mpool_descriptor *mp, u8 cslot, char *msgbuf, size_t msgsz)
{
	struct pre_compact_ctrs    *pco_cnt;
	struct pmd_mdc_info        *cinfo;

	u64    rec, cobj, len, cap;
	u32    garbage, pct;

	assert(cslot > 0);

	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	pco_cnt = &(cinfo->mmi_pco_cnt);

	cap = atomic64_read(&pco_cnt->pcc_cap);
	if (cap == 0)
		return false; /* MDC closed for now. */

	len = atomic64_read(&pco_cnt->pcc_len);
	rec = atomic_read(&pco_cnt->pcc_cr) + atomic_read(&pco_cnt->pcc_up) +
		atomic_read(&pco_cnt->pcc_del) + atomic_read(&pco_cnt->pcc_er);
	cobj = atomic_read(&pco_cnt->pcc_cobj);

	pct = (len * 100) / cap;
	if (pct < mp->pds_params.mp_pcopctfull)
		return false; /* Active mlog not filled enough */

	if (rec > cobj) {
		garbage = (rec - cobj) * 100;
		garbage /= rec;
	} else {

		/*
		 * We may arrive here rarely if the caller doesn't
		 * hold the compact lock. In that case, the update of
		 * the counters may be seen out of order or a compaction
		 * may take place at the same time.
		 */
		garbage = 0;
	}

	if (garbage < mp->pds_params.mp_pcopctgarbage)
		return false;

	if (msgbuf)
		snprintf(msgbuf, msgsz,
			 "bytes used %lu, total %lu, pct %u, records %lu, objects %lu, garbage %u",
			 (ulong)len, (ulong)cap, pct, (ulong)rec, (ulong)cobj, garbage);

	return true;
}
