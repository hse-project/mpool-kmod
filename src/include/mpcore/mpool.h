/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPOOL_H
#define MPOOL_MPOOL_H

/*
 * DOC: Module info
 *
 * Media pool (mpool) manager module.
 *
 * Defines functions to create and maintain mpools comprising multiple drives
 * in multiple media classes used for storing mblocks and mlogs.
 */

#include <mpool/mpool_ioctl.h>

#include <mpcore/uuid.h>
#include <mpcore/mpool_params.h>

struct mpool_descriptor;

#define MPOOL_OP_READ  0
#define MPOOL_OP_WRITE 1
#define PD_DEV_ID_PDUNAVAILABLE "DID_PDUNAVAILABLE"

/* Returns PD length in bytes. */
#define PD_LEN(_pd_prop) ((_pd_prop)->pdp_devsz)

/* Returns PD sector size (exponent, power of 2) */
#define PD_SECTORSZ(_pd_prop) ((_pd_prop)->pdp_sectorsz)

/* Return PD sector size mask */
#define PD_SECTORMASK(_pd_prop) ((uint64_t)(1 << PD_SECTORSZ(&pd->pdi_prop)) - 1)

#define MPOOL_DRIVES_MAX       MP_MED_NUMBER
#define MP_MED_ALL             MP_MED_NUMBER

/**
 * enum mpool_status -
 * @MPOOL_STAT_UNDEF:
 * @MPOOL_STAT_OPTIMAL:
 * @MPOOL_STAT_FAULTED:
 */
enum mpool_status {
	MPOOL_STAT_UNDEF    = 0,
	MPOOL_STAT_OPTIMAL  = 1,
	MPOOL_STAT_FAULTED  = 2,
	MPOOL_STAT_LAST = MPOOL_STAT_FAULTED,
};

_Static_assert((MPOOL_STAT_LAST < 256), "enum mpool_status must fit in u8");

/* Object types */
enum mp_obj_type {
	MP_OBJ_UNDEF  = 0,
	MP_OBJ_MBLOCK = 1,
	MP_OBJ_MLOG   = 2,
};

/**
 * enum pd_status - Transient drive status.
 * @PD_STAT_UNDEF:       undefined; should never occur
 * @PD_STAT_ONLINE:      drive is responding to I/O requests
 * @PD_STAT_SUSPECT:     drive is failing some I/O requests
 * @PD_STAT_OFFLINE:     drive declared non-responsive to I/O requests
 * @PD_STAT_UNAVAIL:     drive path not provided or open failed when
 *                        mpool was opened
 *
 * Transient drive status, these are stored as atomic_t variable
 * values
 */
enum pd_status {
	PD_STAT_UNDEF      = 0,
	PD_STAT_ONLINE     = 1,
	PD_STAT_SUSPECT    = 2,
	PD_STAT_OFFLINE    = 3,
	PD_STAT_UNAVAIL    = 4
};

_Static_assert((PD_STAT_UNAVAIL < 256), "enum pd_status must fit in uint8_t");

/**
 * enum pd_cmd_opt - drive command options
 * @PD_CMD_DISCARD:	     the device has TRIM/UNMAP command.
 * @PD_CMD_SECTOR_UPDATABLE: the device can be read/written with sector
 *	granularity.
 * @PD_CMD_DIF_ENABLED:      T10 DIF is used on this device.
 * @PD_CMD_SED_ENABLED:      Self encrypting enabled
 * @PD_CMD_DISCARD_ZERO:     the device supports discard_zero
 * @PD_CMD_RDONLY:           activate mpool with PDs in RDONLY mode,
 *                           write/discard commands are No-OPs.
 * Defined as a bit vector so can combine.
 * Fields holding such a vector should uint64_t.
 *
 * TODO: we need to find a way to detect if SED is enabled on a device
 */
enum pd_cmd_opt {
	PD_CMD_NONE             = 0,
	PD_CMD_DISCARD          = 0x1,
	PD_CMD_SECTOR_UPDATABLE = 0x2,
	PD_CMD_DIF_ENABLED      = 0x4,
	PD_CMD_SED_ENABLED      = 0x8,
	PD_CMD_DISCARD_ZERO     = 0x10,
	PD_CMD_RDONLY           = 0x20,
};

/**
 * Device types.
 * @PD_DEV_TYPE_BLOCK_STREAM: Block device implementing streams.
 * @PD_DEV_TYPE_BLOCK_STD:    Standard (non-streams) device (SSD, HDD).
 * @PD_DEV_TYPE_FILE:	      File in user space for UT.
 * @PD_DEV_TYPE_MEM:	      Memory semantic device. Such as NVDIMM
 *			      direct access (raw or dax mode).
 * @PD_DEV_TYPE_ZONE:	      zone-like device, such as open channel SSD
 *			      and SMR HDD (using ZBC/ZAC).
 * @PD_DEV_TYPE_BLOCK_NVDIMM: Standard (non-streams) NVDIMM in sector mode.
 */
enum pd_devtype {
	PD_DEV_TYPE_BLOCK_STREAM = 1,
	PD_DEV_TYPE_BLOCK_STD,
	PD_DEV_TYPE_FILE,
	PD_DEV_TYPE_MEM,
	PD_DEV_TYPE_ZONE,
	PD_DEV_TYPE_BLOCK_NVDIMM,
	PD_DEV_TYPE_LAST = PD_DEV_TYPE_BLOCK_NVDIMM,
};


_Static_assert((PD_DEV_TYPE_LAST < 256), "enum pd_devtype must fit in uint8_t");

/**
 * Device states.
 * @PD_DEV_STATE_AVAIL:       Device is available
 * @PD_DEV_STATE_UNAVAIL:     Device is unavailable
 */
enum pd_state {
	PD_DEV_STATE_UNDEFINED = 0,
	PD_DEV_STATE_AVAIL = 1,
	PD_DEV_STATE_UNAVAIL = 2,
	PD_DEV_STATE_LAST = PD_DEV_STATE_UNAVAIL,
};

_Static_assert((PD_DEV_STATE_LAST < 256), "enum pd_state must fit in uint8_t");

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
 * mpool_get_mpname() - Get the mpool name
 * @mp:     mpool descriptor of the mpool
 * @mpname: buffer to copy the mpool name into
 * @mplen:  buffer length
 *
 * Return:
 * %0 if successful, EINVAL otherwise
 */
merr_t mpool_get_mpname(struct mpool_descriptor *mp, char *mpname, size_t mplen);

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
 * %0 if successful, merr_t otherwise..
 * ENODEV if insufficient number of drives meeting mdparm,
 */
merr_t
mpool_create(
	const char              *name,
	u32                      flags,
	char                   **dpaths,
	struct pd_prop	        *pd_prop,
	struct mpcore_params    *params,
	u64                      mlog_cap);

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
 * %0 if successful, merr_t otherwise
 * ENODEV if too many drives unavailable or failed,
 * ENXIO if device previously removed from mpool and is no longer a member
 */
merr_t
mpool_activate(
	u64                          dcnt,
	char                       **dpaths,
	struct pd_prop              *pd_prop,
	u64                          mlog_cap,
	struct mpcore_params        *params,
	u32                          flags,
	struct mpool_descriptor    **mpp);


/**
 * mpool_deactivate() - Deactivate an mpool.
 * @mp: mpool descriptor
 *
 * Deactivate mpool; caller must ensure no other thread can access mp; mp is
 * invalid after call.
 */
merr_t mpool_deactivate(struct mpool_descriptor *mp);

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
 * %0 if successful, merr_t otherwise
 */
merr_t mpool_destroy(u64 dcnt, char **dpaths, struct pd_prop *pd_prop, u32 flags);

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
 * %0 if successful, merr_t otherwise
 */
merr_t
mpool_rename(u64 dcnt, char **dpaths, struct pd_prop *pd_prop, u32 flags, const char *mp_newname);

/**
 * mpool_drive_add() - Add new drive dpath to mpool.
 * @mp:
 * @dpath:
 * @pd_prop: PD properties.
 *
 * Return: %0 if successful; merr_t otherwise...
 */
merr_t mpool_drive_add(struct mpool_descriptor *mp, char *dpath, struct pd_prop *pd_prop);

/**
 * mpool_drive_spares() -
 * @mp:
 * @mclassp:
 * @spzone:
 *
 * Set percent spare zones to spzone for drives in media class mclassp.
 *
 * Return: 0 if successful, merr_t otherwise...
 */
merr_t mpool_drive_spares(struct mpool_descriptor *mp, enum mp_media_classp mclassp, u8 spzone);

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
 * Return: 0 if successful, merr_t otherwise...
 */
merr_t mpool_mclass_get(struct mpool_descriptor *mp, u32 *mcxc, struct mpool_mclass_xprops *mcxv);

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
 * Return: %0 if success, merr_t otherwise...
 * -ENOENT if device with specified name cannot be found
 */
merr_t
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
merr_t mpool_config_store(struct mpool_descriptor *mp, const struct mpool_config *cfg);

/**
 * mpool_config_fetch() - fetch the current mpool config
 * @mp:
 * @cfg:
 */
merr_t mpool_config_fetch(struct mpool_descriptor *mp, struct mpool_config *cfg);

#endif /* MPOOL_MPOOL_H */
