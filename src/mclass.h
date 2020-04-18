/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MCLASS_PRIV_H
#define MPOOL_MCLASS_PRIV_H

/*
 * This file contains the media class structures definitions and prototypes
 * private to mpool core.
 */

/**
 * struct mc_parms - media class parameters
 * @mcp_classp:    class performance characteristics, enum mp_media_classp
 * @mcp_zonepg: virtual erase block size in PAGE_SIZE units
 * @mcp_sectorsz:  2^sectorsz is the logical sector size
 * @mcp_devtype:      device type. Enum pd_devtype.
 * @mcp_features:  ored bits from mp_mc_features
 *
 * Two PDs can't be placed in the same media class if they have different
 * mc_parms.
 */
struct mc_parms {
	u8  mcp_classp;
	u32 mcp_zonepg;
	u8  mcp_sectorsz;
	u8  mcp_devtype;
	u64 mcp_features;
};

/**
 * struct mc_smap_parms - media class space map parameters
 * @mcsp_spzone: percent spare zones for drives.
 * @mcsp_rgnc: no. of space map zones for drives in each media class
 * @mcsp_align: space map zone alignment for drives in each media class
 */
struct mc_smap_parms {
	u8		mcsp_spzone;
	u8		mcsp_rgnc;
	u8		mcsp_align;
};

/**
 * struct media_class - define a media class
 * @mc_parms:  define a media class, content differ for each media class
 * @mc_sparms: space map params for this media class
 * @mc_pdmc:   active pdv entries grouped by media class array
 * @mc_uacnt:  UNAVAIL status drive count in each media class
 *
 * Locking:
 *    Protected by mp.pds_pdvlock.
 */
struct media_class {
	struct mc_parms        mc_parms;
	struct mc_smap_parms   mc_sparms;
	s8                     mc_pdmc;
	u8                     mc_uacnt;
};

/**
 * mc_pd_prop2mc_parms() -  Convert PD properties into media class parameters.
 * @pd_prop: input, pd properties.
 * @mc_parms: output, media class parameters.
 *
 * Typically used before a lookup (mc_lookup_from_mc_parms()) to know in
 * which media class a PD belongs to.
 */
void mc_pd_prop2mc_parms(struct pd_prop *pd_prop, struct mc_parms *mc_parms);

/**
 * mc_omf_devparm2mc_parms() - convert a omf_devparm_descriptor into a
 *	mc_parms.
 * @omf_devparm: input
 * @mc_parms: output
 */
void
mc_omf_devparm2mc_parms(
	struct omf_devparm_descriptor  *omf_devparm,
	struct mc_parms	               *mc_parms);

/**
 * mc_parms2omf_devparm() - convert a mc_parms in a omf_devparm_descriptor
 * @mc_parms: input
 * @omf_devparm: output
 */
void
mc_parms2omf_devparm(
	struct mc_parms                *mc_parms,
	struct omf_devparm_descriptor  *omf_devparm);

/**
 * mc_cmp_omf_devparm() - check if two omf_devparm_descriptor corresponds
 *	to the same media class.
 * @omf_devparm1:
 * @omf_devparm2:
 *
 * Returns 0 if in same media class.
 */
int
mc_cmp_omf_devparm(
	struct omf_devparm_descriptor *omf_devparm1,
	struct omf_devparm_descriptor *omf_devparm2);

/**
 * mc_init_class() - initialize a media class
 * @mc:
 * @mc_parms: parameters of the media class
 * @mcsp:     smap parameters for mc
 */
void
mc_init_class(
	struct media_class     *mc,
	struct mc_parms        *mc_parms,
	struct mc_smap_parms   *mcsp);

/**
 * mc_set_spzone() - set the percent spare on the media class mclass.
 * @mp:
 * @mclass:
 * @spzone:
 *
 * Return: 0, or merr(ENOENT) if the specified mclass doesn't exist.
 */
merr_t
mc_set_spzone(
	struct mpool_descriptor *mp,
	enum mp_media_classp     mclass,
	u8                       spzone);

/**
 * mclassp_valid() - Return true if the media class is valid.
 * @mclass:
 */
static inline bool mclassp_valid(enum mp_media_classp mclass)
{
	return (mclass >= 0 && mclass < MP_MED_NUMBER);
};

/**
 * mc_smap_parms_get() - get space map params for the specified mclass.
 * @mp:
 * @mclass:
 * @mcsp: (output)
 */
merr_t
mc_smap_parms_get(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclass,
	struct mc_smap_parms       *mcsp);

#endif
