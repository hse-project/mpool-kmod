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

void mc_init_class(struct media_class *mc, struct mc_parms *mc_parms, struct mc_smap_parms *mcsp)
{
	memcpy(&(mc->mc_parms), mc_parms, sizeof(*mc_parms));
	mc->mc_uacnt = 0;
	mc->mc_sparms = *mcsp;
}

void mc_omf_devparm2mc_parms(struct omf_devparm_descriptor *omf_devparm, struct mc_parms *mc_parms)
{
	/* Zeroes mc_ parms because memcmp() may be used on it later. */
	memset(mc_parms, 0, sizeof(*mc_parms));
	mc_parms->mcp_classp   = omf_devparm->odp_mclassp;
	mc_parms->mcp_zonepg   = omf_devparm->odp_zonepg;
	mc_parms->mcp_sectorsz = omf_devparm->odp_sectorsz;
	mc_parms->mcp_devtype  = omf_devparm->odp_devtype;
	mc_parms->mcp_features = omf_devparm->odp_features;
}

void mc_parms2omf_devparm(struct mc_parms *mc_parms, struct omf_devparm_descriptor *omf_devparm)
{
	omf_devparm->odp_mclassp  = mc_parms->mcp_classp;
	omf_devparm->odp_zonepg   = mc_parms->mcp_zonepg;
	omf_devparm->odp_sectorsz = mc_parms->mcp_sectorsz;
	omf_devparm->odp_devtype  = mc_parms->mcp_devtype;
	omf_devparm->odp_features = mc_parms->mcp_features;
}

int mc_cmp_omf_devparm(struct omf_devparm_descriptor *omfd1, struct omf_devparm_descriptor *omfd2)
{
	struct mc_parms mc_parms1;
	struct mc_parms mc_parms2;

	mc_omf_devparm2mc_parms(omfd1, &mc_parms1);
	mc_omf_devparm2mc_parms(omfd2, &mc_parms2);

	return memcmp(&mc_parms1, &mc_parms2, sizeof(mc_parms1));
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

merr_t mc_set_spzone(struct mpool_descriptor *mp, enum mp_media_classp mclass, u8 spzone)
{
	struct media_class *mc;

	mc = &mp->pds_mc[mclass];
	if (mc->mc_pdmc < 0)
		return merr(ENOENT);

	mc->mc_sparms.mcsp_spzone = spzone;

	return 0;
}

static void mc_smap_parms_get_internal(struct mpool_descriptor *mp, struct mc_smap_parms *mcsp)
{
	mcsp->mcsp_spzone = mp->pds_params.mp_spare;
	mcsp->mcsp_rgnc = mp->pds_params.mp_smaprgnc;
	mcsp->mcsp_align = mp->pds_params.mp_smapalign;
}

merr_t
mc_smap_parms_get(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclass,
	struct mc_smap_parms       *mcsp)
{
	struct media_class *mc;

	if (ev(!mp || !mcsp))
		return merr(EINVAL);

	mc = &mp->pds_mc[mclass];
	if (mc->mc_pdmc >= 0)
		*mcsp = mc->mc_sparms;
	else
		mc_smap_parms_get_internal(mp, mcsp);

	return 0;
}
