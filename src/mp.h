/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MP_H
#define MPOOL_MP_H

#include "mpool_ioctl.h"
#include "uuid.h"
#include "params.h"

struct mpool_descriptor;

#define MPOOL_OP_READ  0
#define MPOOL_OP_WRITE 1
#define PD_DEV_ID_PDUNAVAILABLE "DID_PDUNAVAILABLE"

#define MPOOL_DRIVES_MAX       MP_MED_NUMBER
#define MP_MED_ALL             MP_MED_NUMBER

/* Object types */
enum mp_obj_type {
	MP_OBJ_UNDEF  = 0,
	MP_OBJ_MBLOCK = 1,
	MP_OBJ_MLOG   = 2,
};

/**
 * struct mpool_config -
 * @mc_oid1:
 * @mc_oid2:
 * @mc_uid:
 * @mc_gid:
 * @mc_mode:
 * @mc_mclassp:
 * @mc_captgt:
 * @mc_ra_pages_max:
 * @mc_vma_sz_max:
 * @mc_utype:           user-defined type
 * @mc_label:           user-defined label

 */
struct mpool_config {
	u64                     mc_oid1;
	u64                     mc_oid2;
	uid_t                   mc_uid;
	gid_t                   mc_gid;
	mode_t                  mc_mode;
	u32                     mc_rsvd0;
	u64                     mc_captgt;
	u32                     mc_ra_pages_max;
	u32                     mc_vma_size_max;
	u32                     mc_rsvd1;
	u32                     mc_rsvd2;
	u64                     mc_rsvd3;
	u64                     mc_rsvd4;
	uuid_le                 mc_utype;
	char                    mc_label[MPOOL_LABELSZ_MAX];
};

/*
 * mpool API functions
 */

/**
 * mpool_create() - Create an mpool
 * @mpname:
 * @flags: enum mp_mgmt_flags
 * @dpaths:
 * @pd_prop: PDs properties obtained by mpool_create() caller.
 * @params:  mpcore parameters
 * @mlog_cap:
 *
 * Create an mpool from dcnt drive paths dpaths; store mpool metadata as
 * specified by mdparm;
 *
 * Return:
 * %0 if successful, -errno otherwise..
 * ENODEV if insufficient number of drives meeting mdparm,
 */
int mpool_create(const char *name, u32 flags, char **dpaths, struct pd_prop *pd_prop,
		 struct mpcore_params *params, u64 mlog_cap);

/**
 * mpool_activate() - Activate an mpool
 * @dcnt:
 * @dpaths:
 * @pd_prop: properties of the PDs. dcnt elements.
 * @mlog_cap:
 * @params:   mpcore parameters
 * @flags:
 * @mpp: *mpp is set to NULL if error
 *
 * Activate mpool on dcnt drive paths dpaths; if force flag is set tolerate
 * unavailable drives up to redundancy limit; if successful *mpp is a handle
 * for the mpool.
 *
 * Return:
 * %0 if successful, -errno otherwise
 * ENODEV if too many drives unavailable or failed,
 * ENXIO if device previously removed from mpool and is no longer a member
 */
int mpool_activate(u64 dcnt, char **dpaths, struct pd_prop *pd_prop, u64 mlog_cap,
		   struct mpcore_params *params, u32 flags, struct mpool_descriptor **mpp);


/**
 * mpool_deactivate() - Deactivate an mpool.
 * @mp: mpool descriptor
 *
 * Deactivate mpool; caller must ensure no other thread can access mp; mp is
 * invalid after call.
 */
int mpool_deactivate(struct mpool_descriptor *mp);

/**
 * mpool_destroy() - Destroy an mpool
 * @dcnt:
 * @dpaths:
 * @pd_prop: PD properties.
 * @flags:
 *
 * Destroy mpool on dcnt drive paths dpaths;
 *
 * Return:
 * %0 if successful, -errno otherwise
 */
int mpool_destroy(u64 dcnt, char **dpaths, struct pd_prop *pd_prop, u32 flags);

/**
 * mpool_rename() - Rename an mpool
 * @dcnt:
 * @dpaths:
 * @pd_prop: PD properties.
 * @flags:
 * @mp_newname:
 *
 * Rename mpool to mp_newname.
 *
 * Return:
 * %0 if successful, -errno otherwise
 */
int
mpool_rename(u64 dcnt, char **dpaths, struct pd_prop *pd_prop, u32 flags, const char *mp_newname);

/**
 * mpool_drive_add() - Add new drive dpath to mpool.
 * @mp:
 * @dpath:
 * @pd_prop: PD properties.
 *
 * Return: %0 if successful; -enno otherwise...
 */
int mpool_drive_add(struct mpool_descriptor *mp, char *dpath, struct pd_prop *pd_prop);

/**
 * mpool_drive_spares() -
 * @mp:
 * @mclassp:
 * @spzone:
 *
 * Set percent spare zones to spzone for drives in media class mclassp.
 *
 * Return: 0 if successful, -errno otherwise...
 */
int mpool_drive_spares(struct mpool_descriptor *mp, enum mp_media_classp mclassp, u8 spzone);

/**
 * mpool_mclass_get_cnt() -
 * @mp:
 * @info:
 *
 * Get a count of media classes with drives in this mpool
 */
void mpool_mclass_get_cnt(struct mpool_descriptor *mp, u32 *cnt);

/**
 * mpool_mclass_get() -
 * @mp:
 * @mcic:
 * @mciv:
 *
 * Get a information on mcl_cnt media classes
 *
 * Return: 0 if successful, -errno otherwise...
 */
int mpool_mclass_get(struct mpool_descriptor *mp, u32 *mcxc, struct mpool_mclass_xprops *mcxv);

/**
 * mpool_get_xprops() - Retrieve extended mpool properties
 * @mp:
 * @prop:
 */
void mpool_get_xprops(struct mpool_descriptor *mp, struct mpool_xprops *xprops);

/**
 * mpool_get_devprops_by_name() -
 * @mp:
 * @pdname:
 * @dprop:
 *
 * Fill in dprop for active drive with name pdname
 *
 * Return: %0 if success, -errno otherwise...
 * -ENOENT if device with specified name cannot be found
 */
int
mpool_get_devprops_by_name(struct mpool_descriptor *mp, char *pdname, struct mpool_devprops *dprop);

/**
 * mpool_get_usage() -
 * @mp:
 * @mclassp:
 * @usage:
 *
 * Fill in stats with mpool space usage for the media class mclassp;
 *	if mclassp is MCLASS_ALL, report on entire pool (all media classes).
 *
 * Return: %0 if successful; err_t otherwise...
 */
void
mpool_get_usage(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclassp,
	struct mpool_usage         *usage);

/**
 * mpool_config_store() - store a config record in MDC0
 * @mp:
 * @cfg:
 */
int mpool_config_store(struct mpool_descriptor *mp, const struct mpool_config *cfg);

/**
 * mpool_config_fetch() - fetch the current mpool config
 * @mp:
 * @cfg:
 */
int mpool_config_fetch(struct mpool_descriptor *mp, struct mpool_config *cfg);

#endif /* MPOOL_MP_H */
