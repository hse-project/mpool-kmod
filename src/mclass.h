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

/* Invalid media class id. */
#define MCID_INVALID       ((u32)(-1))
#define MCID_ALL           (MCID_INVALID - 1)

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
 * @mc_id:     media class id (index in mca_array[])
 * @mc_pdmc:   active pdv entries grouped by media class array
 * @mc_uacnt:  UNAVAIL status drive count in each media class
 *
 * Locking:
 *    Protected by mp.pds_pdvlock.
 */
struct media_class {
	struct mc_parms        mc_parms;
	struct mc_smap_parms   mc_sparms;
	u32		       mc_id;
	u16                    mc_pdmc[MPOOL_DRIVES_MAX + 1];
	u16                    mc_uacnt;
};

/**
 * struct mc_array - array of media classes.
 * @mca_cnt:   number of media classes with drives.
 * @mca_array: table of media class structures
 *
 * Locking:
 *    Protected by mp.pds_pdvlock.
 */
struct mc_array {
	u16                 mca_cnt;
	struct media_class  mca_array[MP_MED_NUMBER];
};

/**
 * mc_cnt() - return the number of media classes
 * @mp:
 *
 * Some of the classes may not have PDs.
 */
u32 mc_cnt(struct mpool_descriptor *mp);

/**
 * mc_id2class() - get the pointer on media_class from the media class id.
 * @mp:
 * @mcid: media class id.
 */
struct media_class *mc_id2class(struct mpool_descriptor *mp, u32 mcid);

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
 * mc_add_class() - add a new media class
 * @mp:
 * @mc_parms: parameters of the media class (input)
 * @mcsp:     smap parameters for mc
 * @mc:       media class corresponding to the media class parameters
 * @check_only: if true, the call doesn't change any state, it only check
 *	if the new media class can be added.
 *
 * Add a new media class, but if a media class with the same parameters (as
 *	the new one to be added) already exists, then do not create a new
 *	class but return a pointer on the existing one.
 *	This function is called when a PD is added in its class. Can be during
 *	create or activate, or when a PD is added to a activated mpool. At that
 *	point a new media class may need to be created.
 *
 * Locking:
 *	Should be called with mp.pds_pdvlock held in write.
 *	Except if mpool is single threaded (during activate for example).
 */
merr_t
mc_add_class(
	struct mpool_descriptor     *mp,
	struct mc_parms             *mc_parms,
	struct mc_smap_parms        *mcsp,
	struct media_class         **mc,
	bool                         check_only);

/**
 * mc_perfc2mclass() - return the first media class corresponding to classp.
 * @mp:
 * @classp:
 */
struct media_class *mc_perf2mclass(struct mpool_descriptor *mp, u8 classp);

/**
 * mc_get_media_class() - select a class based on inputs.
 * @mp:
 * @mclassp:
 * @cktype: if MP_CK_UNDEF, this input is ignored to select the media class.
 *
 * Select first class corresponding to inputs.
 * No locking is needed because media classes structures are not going away.
 */
struct media_class *
mc_get_media_class(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclassp,
	enum mp_cksum_type          cktype);

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
 * mc_set_spzone() - set the percent spare on the media class mclassp.
 * @mp:
 * @mclassp:
 * @spzone:
 *
 * Return: MERR_SUCCESS, or merr(ENOENT) if there is no media class
 *	corresponding to mclassp.
 */
merr_t
mc_set_spzone(
	struct mpool_descriptor *mp,
	enum mp_media_classp     mclassp,
	u8			 spzone);

/**
 * mclassp_valid() - Return true if the media class is valid.
 * @mclassp:
 */
static inline bool mclassp_valid(enum mp_media_classp mclassp)
{
	return (mclassp >= 0 && mclassp < MP_MED_NUMBER);
};

/**
 * mc_smap_parms_get() - get space map params for the specified mclass.
 * @mp:
 * @mclassp:
 * @mcsp: (output)
 */
merr_t
mc_smap_parms_get(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclassp,
	struct mc_smap_parms       *mcsp);

#endif
