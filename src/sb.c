// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Superblock module.
 *
 * Defines functions for managing per drive superblocks.
 *
 */

#include <linux/slab.h>
#include <linux/uio.h>

#include "mpool_printk.h"
#include "assert.h"
#include "evc.h"

#include "mpool_ioctl.h"
#include "pd.h"
#include "omf_if.h"
#include "sb.h"
#include "mclass.h"

/* Cleared out sb */
struct omf_sb_descriptor SBCLEAR;

/*
 * Drives have 4 superblocks.
 * + sb0 at byte offset 0
 * + sb1 at byte offset SB_AREA_SZ + MDC0MD_AREA_SZ
 *
 * Read: sb0 is the authoritative copy, other copies are not used.
 * Updates: sb0 is updated first; if successful sb1 is updated
 */

/*
 * sb internal functions
 */

/**
 * sb_prop_valid() - Validate the PD properties needed to read the erase
 *	superblocks.
 *	When the superblocks are read, the zone parameters may not been known
 *	yet. They may be obtained from the superblocks.
 *
 * Returns: true if we have enough to read the superblocks.
 */
static bool sb_prop_valid(struct pd_dev_parm *dparm)
{
	struct pd_prop *pd_prop = &dparm->dpr_prop;

	if (SB_AREA_SZ < OMF_SB_DESC_PACKLEN) {
		merr_t err = merr(EINVAL);

		/* Guarantee that the SB area is large enough to hold an SB */
		mp_pr_err("sb(%s): structure too big %lu %lu",
			  err, dparm->dpr_name, (ulong)SB_AREA_SZ, OMF_SB_DESC_PACKLEN);
		return false;
	}

	if ((pd_prop->pdp_devtype != PD_DEV_TYPE_BLOCK_STD) &&
	    (pd_prop->pdp_devtype != PD_DEV_TYPE_BLOCK_NVDIMM) &&
	    (pd_prop->pdp_devtype != PD_DEV_TYPE_FILE)) {
		merr_t err = merr(EINVAL);

		mp_pr_err("sb(%s): unknown device type %d",
			  err, dparm->dpr_name, pd_prop->pdp_devtype);
		return false;
	}

	if (PD_LEN(pd_prop) == 0) {
		merr_t err = merr(EINVAL);

		mp_pr_err("sb(%s): unknown device size", err, dparm->dpr_name);
		return false;
	}

	return true;
};

static u64 sb_idx2woff(u32 idx)
{
	return (u64)idx * (SB_AREA_SZ + MDC0MD_AREA_SZ);
}

/**
 * sb_parm_valid() - Validate parameters passed to an SB API function
 * @dparm: struct pd_dev_parm
 *
 * When this function is called it is assumed that the zone parameters of the
 * PD are already known.
 *
 * Part of the validation is enforcing the rule from the comment above that
 * there needs to be at least one more zone than those consumed by the
 * (SB_SB_COUNT) superblocks.
 *
 * Returns: true if drive pd meets criteria for sb, false otherwise.
 */
static bool sb_parm_valid(struct pd_dev_parm *dparm)
{
	struct pd_prop *pd_prop = &dparm->dpr_prop;

	u32    cnt;

	if (SB_AREA_SZ < OMF_SB_DESC_PACKLEN) {
		/* Guarantee that the SB area is large enough to hold an SB */
		return false;
	}

	if (pd_prop->pdp_zparam.dvb_zonepg == 0) {
		/* Zone size can't be 0. */
		return false;
	}

	cnt = sb_zones_for_sbs(pd_prop);
	if (cnt < 1) {
		/* At least one zone is needed to hold SB0 and SB1. */
		return false;
	}

	if (dparm->dpr_zonetot < (cnt + 1)) {
		/* Guarantee that there is at least one zone not consumed by SBs. */
		return false;
	}

	return true;
};

/*
 * Write packed superblock in outbuf to sb copy number idx on drive pd.
 * Returns: 0 if successful; merr_t otherwise
 */
static merr_t sb_write_sbx(struct pd_dev_parm *dparm, char *outbuf, u32 idx)
{
	const struct kvec  iov = { outbuf, SB_AREA_SZ };
	merr_t             err;
	u64                woff;

	woff = sb_idx2woff(idx);

	err = pd_zone_pwritev_sync(dparm, &iov, 1, 0, woff);
	/* Reset the rval as per api */
	if (err >= 0)
		err = 0;
	else
		mp_pr_err("sb(%s, %d): write failed, woff %lu",
			  err, dparm->dpr_name, idx, (ulong)woff);

	return err;
}

/*
 * Read packed superblock into inbuf from sb copy number idx.
 * Returns: 0 if successful; merr_t otherwise
 *
 */
static merr_t sb_read_sbx(struct pd_dev_parm *dparm, char *inbuf, u32 idx)
{
	const struct kvec  iov = { inbuf, SB_AREA_SZ };
	u64                woff;
	merr_t             err;

	woff = sb_idx2woff(idx);

	err = pd_zone_preadv(dparm, &iov, 1, 0, woff);
	/* Reset rval as per api */
	if (err >= 0)
		err = 0;
	else
		mp_pr_err("sb(%s, %d): read failed, woff %lu",
			  err, dparm->dpr_name, idx, (ulong)woff);

	return err;
}

/*
 * sb API functions
 */

/*
 * Determine if the mpool magic value exists in at least one place where
 * expected on drive pd.  Does NOT imply drive has a valid superblock.
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Returns: 1 if found, 0 if not found, -(errno) if error reading
 *
 */
int sb_magic_check(struct pd_dev_parm *dparm)
{
	int     rval = 0, i;
	char   *inbuf;
	merr_t  err;

	if (!sb_prop_valid(dparm)) {
		err = merr(EINVAL);
		mp_pr_err("sb(%s): invalid param, zonepg %u zonetot %u",
			  err, dparm->dpr_name, dparm->dpr_zonepg, dparm->dpr_zonetot);
		return -merr_errno(err);
	}

	assert(SB_AREA_SZ >= OMF_SB_DESC_PACKLEN);

	inbuf = kmalloc_large(SB_AREA_SZ + 1, GFP_KERNEL);
	if (!inbuf) {
		err = merr(ENOMEM);
		mp_pr_err("sb(%s) magic check: buffer alloc failed", err, dparm->dpr_name);
		return -merr_errno(err);
	}

	for (i = 0; i < SB_SB_COUNT; i++) {
		const struct kvec iov = { inbuf, SB_AREA_SZ };
		u64 woff = sb_idx2woff(i);

		memset(inbuf, 0, SB_AREA_SZ);

		err = pd_zone_preadv(dparm, &iov, 1, 0, woff);
		if (err) {
			rval = merr_errno(err);
			mp_pr_err("sb(%s, %d) magic: read failed, woff %lu",
				  err, dparm->dpr_name, i, (ulong)woff);
		} else if (omf_sb_has_magic_le(inbuf)) {
			kfree(inbuf);
			return 1;
		}
	}

	kfree(inbuf);
	return rval;
}

/*
 * Write superblock sb to new (non-pool) drive
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Returns: 0 if successful; merr_t otherwise
 *
 */
merr_t sb_write_new(struct pd_dev_parm *dparm, struct omf_sb_descriptor *sb)
{
	merr_t  err;
	char   *outbuf;
	int     i;

	assert(SB_AREA_SZ >= OMF_SB_DESC_PACKLEN);

	if (!sb_parm_valid(dparm)) {
		err = merr(EINVAL);
		mp_pr_err("sb(%s) invalid param, zonepg %u zonetot %u",
			  err, dparm->dpr_name, dparm->dpr_zonepg, dparm->dpr_zonetot);
		return err;
	}

	outbuf = kmalloc_large(SB_AREA_SZ + 1, GFP_KERNEL);
	if (!outbuf)
		return merr(ENOMEM);

	memset(outbuf, 0, SB_AREA_SZ);

	err = omf_sb_pack_htole(sb, outbuf);
	if (err) {
		mp_pr_err("sb(%s) packing failed", err, dparm->dpr_name);
		kfree(outbuf);
		return err;
	}

	/*
	 * since pd is not yet a pool member only succeed if write all sb
	 * copies.
	 */
	for (i = 0; i < SB_SB_COUNT; i++) {
		err = sb_write_sbx(dparm, outbuf, i);
		if (err) {
			mp_pr_err("sb(%s, %d): write sbx failed", err, dparm->dpr_name, i);
			break;
		}
	}

	kfree(outbuf);
	return err;
}

/*
 * Update superblock on pool drive
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Returns: 0 if successful; merr_t otherwise
 *
 */
merr_t sb_write_update(struct pd_dev_parm *dparm, struct omf_sb_descriptor *sb)
{
	merr_t  err;
	char   *outbuf;
	int     i;

	assert(SB_AREA_SZ >= OMF_SB_DESC_PACKLEN);

	if (!sb_parm_valid(dparm)) {
		err = merr(EINVAL);
		mp_pr_err("sb(%s) invalid param, zonepg %u zonetot %u partlen %lu",
			  err, dparm->dpr_name, dparm->dpr_zonepg, dparm->dpr_zonetot,
			  (ulong)PD_LEN(&dparm->dpr_prop));
		return err;
	}

	outbuf = kmalloc_large(SB_AREA_SZ + 1, GFP_KERNEL);
	if (!outbuf)
		return merr(ENOMEM);

	memset(outbuf, 0, SB_AREA_SZ);

	err = omf_sb_pack_htole(sb, outbuf);
	if (ev(err)) {
		mp_pr_err("sb(%s) packing failed", err, dparm->dpr_name);
		kfree(outbuf);
		return err;
	}

	/* Update sb0 first and then sb1 if that is successful */
	for (i = 0; i < SB_SB_COUNT; i++) {
		err = sb_write_sbx(dparm, outbuf, i);
		if (ev(err)) {
			mp_pr_err("sb(%s, %d) sbx write failed", err, dparm->dpr_name, i);
			if (i == 0)
				break;
			err = 0;
		}
	}

	kfree(outbuf);

	return err;
}

/*
 * Erase superblock on drive pd.
 *
 * Note: only pd properties must be set.
 *
 * Returns: 0 if successful; merr_t otherwise
 *
 */
merr_t sb_erase(struct pd_dev_parm *dparm)
{
	merr_t  err = 0;
	char   *buf;
	int     i;

	if (!sb_prop_valid(dparm)) {
		err = merr(EINVAL);
		mp_pr_err("sb(%s) invalid param, zonepg %u zonetot %u", err, dparm->dpr_name,
			  dparm->dpr_zonepg, dparm->dpr_zonetot);
		return err;
	}

	assert(SB_AREA_SZ >= OMF_SB_DESC_PACKLEN);

	buf = kmalloc_large(SB_AREA_SZ + 1, GFP_KERNEL);
	if (!buf)
		return merr(EINVAL);

	memset(buf, 0, SB_AREA_SZ);

	for (i = 0; i < SB_SB_COUNT; i++) {
		const struct kvec iov = { buf, SB_AREA_SZ };
		u64 woff = sb_idx2woff(i);

		err = pd_zone_pwritev_sync(dparm, &iov, 1, 0, woff);
		if (err)
			mp_pr_err("sb(%s, %d): erase failed", err, dparm->dpr_name, i);
	}

	kfree(buf);

	return err;
}

static merr_t sb_reconcile(struct omf_sb_descriptor *sb, struct pd_dev_parm *dparm, bool force)
{
	struct pd_prop                 *pd_prop = &dparm->dpr_prop;
	struct omf_devparm_descriptor  *sb_parm = &(sb->osb_parm);
	struct mc_parms		        mc_parms;
	merr_t                          err;

	pd_prop->pdp_mclassp = sb_parm->odp_mclassp;
	pd_prop->pdp_zparam.dvb_zonepg = sb_parm->odp_zonepg;
	pd_prop->pdp_zparam.dvb_zonetot = sb_parm->odp_zonetot;

	if (force)
		return 0;

	if (pd_prop->pdp_devsz < sb_parm->odp_devsz) {
		err = merr(EINVAL);

		mp_pr_err("sb(%s): devsz(%lu) > discovered (%lu)",
			  err, dparm->dpr_name, (ulong)sb_parm->odp_devsz,
			  (ulong)pd_prop->pdp_devsz);
		return err;
	}

	if (PD_SECTORSZ(pd_prop) != sb_parm->odp_sectorsz) {
		err = merr(EINVAL);

		mp_pr_err("sb(%s) sector size(%u) mismatches discovered(%u)",
			  err, dparm->dpr_name, sb_parm->odp_sectorsz, PD_SECTORSZ(pd_prop));
		return err;
	}

	if (pd_prop->pdp_devtype != sb_parm->odp_devtype) {
		err = merr(EINVAL);

		mp_pr_err("sb(%s), pd type(%u) mismatches discovered(%u)",
			  err, dparm->dpr_name, sb_parm->odp_devtype, pd_prop->pdp_devtype);
		return err;
	}

	mc_pd_prop2mc_parms(pd_prop, &mc_parms);
	if (mc_parms.mcp_features != sb_parm->odp_features) {
		err = merr(EINVAL);

		mp_pr_err("sb(%s), pd features(%lu) mismatches discovered(%lu)",
			  err, dparm->dpr_name, (ulong)sb_parm->odp_features,
			  (ulong)mc_parms.mcp_features);
		return err;
	}

	return 0;
}

/*
 * Read superblock from drive pd.
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Returns: 0 if successful; merr_t otherwise
 *
 */
merr_t sb_read(struct pd_dev_parm *dparm, struct omf_sb_descriptor *sb, u16 *omf_ver, bool force)
{
	struct omf_sb_descriptor *sbtmp;

	merr_t  rval = 0, err;
	char   *buf;
	int     i;

	if (!sb_prop_valid(dparm)) {
		err = merr(EINVAL);
		mp_pr_err("sb(%s) invalid parameter, zonepg %u zonetot %u",
			  err, dparm->dpr_name, dparm->dpr_zonepg, dparm->dpr_zonetot);
		return err;
	}

	sbtmp = kzalloc(sizeof(*sbtmp), GFP_KERNEL);
	if (!sbtmp)
		return merr(ENOMEM);

	assert(SB_AREA_SZ >= OMF_SB_DESC_PACKLEN);

	buf = kmalloc_large(SB_AREA_SZ + 1, GFP_KERNEL);
	if (!buf) {
		kfree(sbtmp);
		return merr(ENOMEM);
	}

	/*
	 * In 1.0, voting + SB gen numbers across the drive SBs is not used.
	 * There is one authoritave replica that is SB0.
	 * SB1 only used for debugging.
	 */
	for (i = 0; i < SB_SB_COUNT; i++) {
		memset(buf, 0, SB_AREA_SZ);

		err = sb_read_sbx(dparm, buf, i);
		if (err)
			mp_pr_err("sb(%s, %d) read sbx failed", err, dparm->dpr_name, i);
		else {
			err = omf_sb_unpack_letoh(sbtmp, buf, omf_ver);
			if (err)
				mp_pr_err("sb(%s, %d) bad magic/version/cksum",
					  err, dparm->dpr_name, i);
			else if (i == 0)
				/* Deep copy to main struct  */
				*sb = *sbtmp;
		}
		if (err && (i == 0)) {
			/*
			 * SB0 has the authoritative replica of
			 * MDC0 metadata. We need it.
			 */
			rval = err;
			goto exit;
		}
	}

	/*
	 * Check that superblock SB0 is consistent and
	 * update the PD properties from it.
	 */
	err = sb_reconcile(sb, dparm, force);
	if (ev(err))
		rval = err;

exit:
	kfree(sbtmp);
	kfree(buf);
	return rval;
}

/*
 * Clear (set to zeros) mdc0 portion of sb.
 */
void sbutil_mdc0_clear(struct omf_sb_descriptor *sb)
{
	sb->osb_mdc01gen = 0;
	sb->osb_mdc01desc.ol_zcnt = 0;
	mpool_uuid_clear(&sb->osb_mdc01uuid);

	mpool_uuid_clear(&sb->osb_mdc01devid);
	sb->osb_mdc01desc.ol_zaddr = 0;

	sb->osb_mdc02gen = 0;
	sb->osb_mdc02desc.ol_zcnt = 0;
	mpool_uuid_clear(&sb->osb_mdc02uuid);

	mpool_uuid_clear(&sb->osb_mdc02devid);
	sb->osb_mdc02desc.ol_zaddr = 0;

	mpool_uuid_clear(&sb->osb_mdc0dev.odp_devid);
	sb->osb_mdc0dev.odp_zonetot = 0;
	sb->osb_mdc0dev.odp_zonepg = 0;
	sb->osb_mdc0dev.odp_mclassp = 0;
	sb->osb_mdc0dev.odp_devtype = 0;
	sb->osb_mdc0dev.odp_sectorsz = 0;
	sb->osb_mdc0dev.odp_features = 0;
}

/*
 * Copy mdc0 portion of srcsb to tgtsb.
 */
void sbutil_mdc0_copy(struct omf_sb_descriptor *tgtsb, struct omf_sb_descriptor *srcsb)
{
	tgtsb->osb_mdc01gen = srcsb->osb_mdc01gen;
	mpool_uuid_copy(&tgtsb->osb_mdc01uuid, &srcsb->osb_mdc01uuid);
	mpool_uuid_copy(&tgtsb->osb_mdc01devid, &srcsb->osb_mdc01devid);
	tgtsb->osb_mdc01desc.ol_zcnt = srcsb->osb_mdc01desc.ol_zcnt;
	tgtsb->osb_mdc01desc.ol_zaddr = srcsb->osb_mdc01desc.ol_zaddr;

	tgtsb->osb_mdc02gen = srcsb->osb_mdc02gen;
	mpool_uuid_copy(&tgtsb->osb_mdc02uuid, &srcsb->osb_mdc02uuid);
	mpool_uuid_copy(&tgtsb->osb_mdc02devid, &srcsb->osb_mdc02devid);
	tgtsb->osb_mdc02desc.ol_zcnt = srcsb->osb_mdc02desc.ol_zcnt;
	tgtsb->osb_mdc02desc.ol_zaddr = srcsb->osb_mdc02desc.ol_zaddr;

	mpool_uuid_copy(&tgtsb->osb_mdc0dev.odp_devid, &srcsb->osb_mdc0dev.odp_devid);
	tgtsb->osb_mdc0dev.odp_devsz    = srcsb->osb_mdc0dev.odp_devsz;
	tgtsb->osb_mdc0dev.odp_zonetot  = srcsb->osb_mdc0dev.odp_zonetot;
	tgtsb->osb_mdc0dev.odp_zonepg   = srcsb->osb_mdc0dev.odp_zonepg;
	tgtsb->osb_mdc0dev.odp_mclassp  = srcsb->osb_mdc0dev.odp_mclassp;
	tgtsb->osb_mdc0dev.odp_devtype  = srcsb->osb_mdc0dev.odp_devtype;
	tgtsb->osb_mdc0dev.odp_sectorsz = srcsb->osb_mdc0dev.odp_sectorsz;
	tgtsb->osb_mdc0dev.odp_features = srcsb->osb_mdc0dev.odp_features;
}

/*
 * Compare mdc0 portions of sb1 and sb2.
 */
static int sbutil_mdc0_eq(struct omf_sb_descriptor *sb1, struct omf_sb_descriptor *sb2)
{
	if (sb1->osb_mdc01gen != sb2->osb_mdc01gen ||
	    sb1->osb_mdc01desc.ol_zcnt != sb2->osb_mdc01desc.ol_zcnt)
		return 0;

	if (mpool_uuid_compare(&sb1->osb_mdc01devid, &sb2->osb_mdc01devid) ||
	    sb1->osb_mdc01desc.ol_zaddr != sb2->osb_mdc01desc.ol_zaddr)
		return 0;

	if (sb1->osb_mdc02gen != sb2->osb_mdc02gen ||
	    sb1->osb_mdc02desc.ol_zcnt != sb2->osb_mdc02desc.ol_zcnt)
		return 0;

	if (mpool_uuid_compare(&sb1->osb_mdc02devid, &sb2->osb_mdc02devid) ||
	    sb1->osb_mdc02desc.ol_zaddr != sb2->osb_mdc02desc.ol_zaddr)
		return 0;

	if (mpool_uuid_compare(&sb1->osb_mdc0dev.odp_devid, &sb2->osb_mdc0dev.odp_devid) ||
	    sb1->osb_mdc0dev.odp_zonetot != sb2->osb_mdc0dev.odp_zonetot ||
	    mc_cmp_omf_devparm(&sb1->osb_mdc0dev, &sb2->osb_mdc0dev))
		return 0;

	return 1;
}

/**
 * sbutil_mdc0_isclear() - returns 1 if there is no MDC0 metadata in the
 *	                   mdc0 portion of the super block.
 * @sb:
 *
 * Some fields in the MDC0 portion of "sb" may not be 0 even if there is no
 * MDC0 metadata present. It is due to metadata upgrade.
 * Metadata upgrade may have to place a specific (non zero) value in a field
 * that was not existing in a previous metadata version to indicate that
 * the value is invalid.
 */
int sbutil_mdc0_isclear(struct omf_sb_descriptor *sb)
{
	return sbutil_mdc0_eq(&SBCLEAR, sb);
}

/*
 * Validate mdc0 portion of sb
 * Returns: 1 if valid; 0 otherwise.
 */
int sbutil_mdc0_isvalid(struct omf_sb_descriptor *sb)
{
	/* Basic consistency validation; can make more extensive as needed */

	if (ev(mpool_uuid_compare(&sb->osb_mdc01devid, &sb->osb_mdc02devid) ||
	       mpool_uuid_compare(&sb->osb_mdc01devid, &sb->osb_mdc0dev.odp_devid)))
		return 0;

	if (ev(mpool_uuid_is_null(&sb->osb_mdc01devid)))
		return 0;

	if (ev(mpool_uuid_is_null(&sb->osb_parm.odp_devid)))
		return 0;

	/* Confirm this drive is supposed to contain this mdc0 info */
	if (!mpool_uuid_compare(&sb->osb_mdc01devid, &sb->osb_parm.odp_devid)) {
		/* Found this drive in mdc0 strip list; confirm param and ownership */
		if (ev(mc_cmp_omf_devparm(&sb->osb_parm, &sb->osb_mdc0dev)))
			return 0;
	} else {
		return 0;
	}

	if (ev(sb->osb_mdc01desc.ol_zcnt != sb->osb_mdc02desc.ol_zcnt))
		return 0;

	return 1;
}

merr_t sb_init(void)
{
	sbutil_mdc0_clear(&SBCLEAR);

	return 0;
}

void sb_exit(void)
{
}
