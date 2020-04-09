// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * This file contains the media class accessor functions.
 */
#include <linux/sort.h>
#include <asm/barrier.h>

#include "mpcore_defs.h"

/*
 * total ordering of media classes from fastest to slowest
 */
const enum mp_media_classp MCLASS_PERFV[] = {
	MP_MED_STAGING,
	MP_MED_CAPACITY,
};

bool mclass_asfast(enum mp_media_classp mc1, enum mp_media_classp mc2)
{
	int pvoff1 = MP_MED_NUMBER - 1;
	int pvoff2 = MP_MED_NUMBER - 1;
	int i;

	/* Return 1 if media class mc1 is as fast or faster than mc2. */
	for (i = 0; i < MP_MED_NUMBER; i++) {
		if (MCLASS_PERFV[i] == mc1)
			pvoff1 = i;
		if (MCLASS_PERFV[i] == mc2)
			pvoff2 = i;
	}

	return (pvoff1 <= pvoff2);
}

u32 mc_cnt(struct mpool_descriptor *mp)
{
	return mp->pds_mca.mca_cnt;
}

struct media_class *mc_id2class(struct mpool_descriptor *mp, u32 mcid)
{
	struct media_class *mc;
	struct mc_array    *mca;

	mca = &(mp->pds_mca);

	if (mcid >= mca->mca_cnt) {
		assert(mcid == MCID_INVALID || mcid == MCID_ALL);
		return NULL;
	}

	mc = &(mca->mca_array[mcid]);

	return mc;
}

struct media_class *
mc_lookup_from_mc_parms(struct mpool_descriptor *mp, struct mc_parms *mc_parms)
{
	struct media_class *mc;
	struct mc_array    *mca;
	int i;

	mca = &(mp->pds_mca);
	for (i = 0; i < mca->mca_cnt; i++) {
		mc = &(mca->mca_array[i]);
		if (!memcmp(mc_parms, &(mc->mc_parms), sizeof(*mc_parms)))
			return mc;
	}
	return NULL;
}

void
mc_omf_devparm2mc_parms(
	struct omf_devparm_descriptor *omf_devparm,
	struct mc_parms               *mc_parms)
{
	/* Zeroes mc_ parms because memcmp() may be used on it later. */
	memset(mc_parms, 0, sizeof(*mc_parms));
	mc_parms->mcp_classp   = omf_devparm->odp_mclassp;
	mc_parms->mcp_zonepg   = omf_devparm->odp_zonepg;
	mc_parms->mcp_sectorsz = omf_devparm->odp_sectorsz;
	mc_parms->mcp_devtype  = omf_devparm->odp_devtype;
	mc_parms->mcp_features = omf_devparm->odp_features;
}

void
mc_parms2omf_devparm(
	struct mc_parms               *mc_parms,
	struct omf_devparm_descriptor *omf_devparm)
{
	omf_devparm->odp_mclassp  = mc_parms->mcp_classp;
	omf_devparm->odp_zonepg   = mc_parms->mcp_zonepg;
	omf_devparm->odp_sectorsz = mc_parms->mcp_sectorsz;
	omf_devparm->odp_devtype  = mc_parms->mcp_devtype;
	omf_devparm->odp_features = mc_parms->mcp_features;
}

int
mc_cmp_omf_devparm(
	struct omf_devparm_descriptor *omf_devparm1,
	struct omf_devparm_descriptor *omf_devparm2)
{
	struct mc_parms mc_parms1;
	struct mc_parms mc_parms2;

	mc_omf_devparm2mc_parms(omf_devparm1, &mc_parms1);
	mc_omf_devparm2mc_parms(omf_devparm2, &mc_parms2);

	return memcmp(&mc_parms1, &mc_parms2, sizeof(mc_parms1));
}

struct media_class *
mc_lookup_from_omf_devparm(
	struct mpool_descriptor       *mp,
	struct omf_devparm_descriptor *omf_devparm)
{
	struct mc_parms mc_parms;

	mc_omf_devparm2mc_parms(omf_devparm, &mc_parms);

	return mc_lookup_from_mc_parms(mp, &mc_parms);
}

void
mc_init_class(
	struct media_class     *mc,
	struct mc_parms        *mc_parms,
	struct mc_smap_parms   *mcsp)
{
	memcpy(&(mc->mc_parms), mc_parms, sizeof(*mc_parms));
	mc->mc_uacnt = 0;
	mc->mc_sparms = *mcsp;
}

enum mc_perf_cksum
mc_perf_cksummed(struct mpool_descriptor *mp, enum mp_media_classp mclassp)
{
	struct media_class *mc;
	struct mc_array    *mca;
	enum mc_perf_cksum  ret;
	int i;

	ret = MC_EMPTY;

	mca = &(mp->pds_mca);
	for (i = 0; i < mca->mca_cnt; i++) {
		mc = &(mca->mca_array[i]);
		if (mc->mc_pdmc[0] && (mc->mc_parms.mcp_classp == mclassp)) {
			if (mc->mc_parms.mcp_features & OMF_MC_FEAT_CHECKSUM)
				ret = MC_CKSUM_USED;
			else
				ret = MC_CKSUM_NOTUSED;
			return ret;
		}
	}
	return ret;
}

merr_t
mc_add_class(
	struct mpool_descriptor     *mp,
	struct mc_parms             *mc_parms,
	struct mc_smap_parms        *mcsp,
	struct media_class         **mc,
	bool                         check_only)
{
	struct mc_array *mca;
	merr_t err;

	*mc = mc_lookup_from_mc_parms(mp, mc_parms);
	if (*mc != NULL)
		return 0;

	mca = &(mp->pds_mca);
	if (mca->mca_cnt == MP_MED_NUMBER) {
		err = merr(ENOSPC);
		mp_pr_err("mpool %s, reached max number %d of media classes",
			  err, mp->pds_name, MP_MED_NUMBER);
		return err;
	}

	*mc = &(mca->mca_array[mca->mca_cnt]);
	if (check_only)
		return 0;

	mc_init_class(*mc, mc_parms, mcsp);
	(*mc)->mc_id = mca->mca_cnt;
	mca->mca_cnt++;

	return 0;
}

void mc_pd_prop2mc_parms(struct pd_prop *pd_prop, struct mc_parms *mc_parms)
{
	/* Zeroes mc_ parms because memcmp() may be used on it later. */
	memset(mc_parms, 0, sizeof(*mc_parms));
	mc_parms->mcp_classp	= pd_prop->pdp_mclassp;
	mc_parms->mcp_zonepg	= pd_prop->pdp_zparam.dvb_zonepg;
	mc_parms->mcp_sectorsz	= PD_SECTORSZ(pd_prop);
	mc_parms->mcp_devtype	= pd_prop->pdp_devtype;
	mc_parms->mcp_features	= OMF_MC_FEAT_MBLOCK_TGT;

	if (pd_prop->pdp_cmdopt & PD_CMD_SECTOR_UPDATABLE)
		mc_parms->mcp_features |= OMF_MC_FEAT_MLOG_TGT;
	if (pd_prop->pdp_cmdopt & PD_CMD_DIF_ENABLED)
		mc_parms->mcp_features |= OMF_MC_FEAT_CHECKSUM;
}

/**
 * mc_perf_cmp()
 * @lhs:
 * @rhs:
 *
 * Return -1 if lhs is slower that rhs. Else return 1.
 */
static int mc_perf_cmp(const void *lhs, const void *rhs)
{
	const struct media_class *lmc = *((struct media_class **)lhs);
	const struct media_class *rmc = *((struct media_class **)rhs);

	if (mclass_asfast(lmc->mc_parms.mcp_classp, rmc->mc_parms.mcp_classp))
		/* lhs is faster */
		return 1;
	else
		return -1;
}

merr_t
mc_get_meta_class_candidate(
	struct mpool_descriptor     *mp,
	enum mp_media_classp         mclassp,
	u32                          min_pd,
	struct media_class         **mc_out)
{
	struct mc_array      *mca;
	struct media_class   *mc;
	struct media_class  **sorted;
	struct media_class   *lowest_perf_enough_pds = NULL;
	int    i;
	size_t sz;

	*mc_out = NULL;
	mca = &(mp->pds_mca);

	/*
	 * Sort the media class in increasing order of performance.
	 */
	sz = sizeof(*sorted) * mca->mca_cnt;
	sorted = kmalloc(sz, GFP_KERNEL);
	if (sorted == NULL)
		return merr(ENOMEM);
	for (i = 0; i < mca->mca_cnt; i++)
		sorted[i] = &(mca->mca_array[i]);
	sort(sorted, mca->mca_cnt, sizeof(*sorted), mc_perf_cmp, NULL);

	for (i = 0; i < mca->mca_cnt; i++) {
		mc = sorted[i];
		if (mc->mc_pdmc[0] < min_pd)
			continue;
		if (mc->mc_parms.mcp_classp == mclassp) {
			*mc_out = mc;
			break;
		}
		if (lowest_perf_enough_pds == NULL)
			lowest_perf_enough_pds = mc;
	}
	kfree(sorted);

	if ((*mc_out == NULL) && (mclassp == MP_MED_ANY))
		*mc_out = lowest_perf_enough_pds;

	return 0;
}

struct media_class *mc_perf2mclass(struct mpool_descriptor *mp, u8 classp)
{
	struct media_class *mc;
	struct mc_array    *mca;
	int i;

	mca = &(mp->pds_mca);
	for (i = 0; i < mca->mca_cnt; i++) {
		mc = &(mca->mca_array[i]);
		if (mc->mc_parms.mcp_classp == classp)
			return mc;
	}

	return NULL;
}

struct media_class *
mc_get_media_class(
	struct mpool_descriptor *mp,
	enum mp_media_classp     mclassp,
	enum mp_cksum_type       cktype)
{
	struct mc_array    *mca;
	struct media_class *mc;
	struct media_class *selected = NULL;
	int		    i;

	mca = &(mp->pds_mca);
	for (i = 0; i < mca->mca_cnt; i++) {
		mc = &(mca->mca_array[i]);
		if ((mc->mc_parms.mcp_classp == mclassp) &&
			((cktype == MP_CK_UNDEF) ||
			(((mc->mc_parms.mcp_features & OMF_MC_FEAT_CHECKSUM) &&
			(cktype == MP_CK_DIF)) ||
			(!(mc->mc_parms.mcp_features & OMF_MC_FEAT_CHECKSUM) &&
				(cktype == MP_CK_NONE))))) {
			/*
			 * Class and checksum match.
			 */
			selected = mc;
			break;
		}
	}
	return selected;
}

merr_t
mc_set_spzone(
	struct mpool_descriptor *mp,
	enum mp_media_classp     mclassp,
	u8			 spzone)
{
	struct media_class *mc;

	mc = mc_perf2mclass(mp, mclassp);
	if (mc == NULL)
		return merr(ENOENT);

	mc->mc_sparms.mcsp_spzone = spzone;

	return 0;
}

static void
mc_smap_parms_get_internal(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclassp,
	struct mc_smap_parms       *mcsp)
{
	mcsp->mcsp_spzone = mp->pds_params.mp_spare;
	mcsp->mcsp_rgnc   = mp->pds_params.mp_smaprgnc;
	mcsp->mcsp_align = mp->pds_params.mp_smapalign;
}

merr_t
mc_smap_parms_get(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclassp,
	struct mc_smap_parms       *mcsp)
{
	struct media_class *mc;

	if (ev(!mp || !mcsp))
		return merr(EINVAL);

	mc = mc_perf2mclass(mp, mclassp);
	if (mc)
		*mcsp = mc->mc_sparms;
	else
		mc_smap_parms_get_internal(mp, mclassp, mcsp);

	return 0;
}

merr_t
mc_get_pdcnt(
	struct mpool_descriptor *mp,
	enum mp_media_classp     mclassp,
	u32                     *pdcnt)
{
	struct media_class *mc;

	down_read(&mp->pds_pdvlock);
	mc = mc_get_media_class(mp, mclassp, MP_CK_UNDEF);
	if (mc)
		*pdcnt = min_t(u16, mc->mc_pdmc[0], MPOOL_DRIVES_MAX);
	up_read(&mp->pds_pdvlock);

	return mc ? 0 : merr(ENOENT);
}

enum mp_media_classp mpool_mc_first_get(enum mp_media_classp mclassp)
{
	return (mclassp < MP_MED_BEST_EFFORT) ? mclassp :
		mclassp - MP_MED_BEST_EFFORT;
}

bool mpool_mc_isbe(enum mp_media_classp mclassp)
{
	return mclassp >= MP_MED_BEST_EFFORT &&
		mclassp < MP_MED_BEST_EFFORT + MP_MED_NUMBER;
}

bool mpool_mc_isvalid(enum mp_media_classp mclassp)
{
	return (mclassp >= 0 &&
		(mclassp < MP_MED_NUMBER || mpool_mc_isbe(mclassp)));
}
