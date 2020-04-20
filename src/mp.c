// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Media pool (mpool) manager module.
 *
 * Defines functions to create and maintain mpools comprising multiple drives
 * in multiple media classes used for storing mblocks and mlogs.
 */

#include <linux/string.h>

#include <mpool/mpool_ioctl.h>

#include "mpcore_defs.h"
#include <mpcore/mdc.h>
#include <mpcore/upgrade.h>

/*
 * lock for serializing certain mpool ops where required/desirable; could be per
 * mpool in some cases but no meaningful performance benefit for these rare ops;
 * also protects mpool_pools and certain mpool_descriptor fields.
 */
static DEFINE_MUTEX(mpool_s_lock);

/* rbtree maps mpool UUID to mpool descriptor node: uuid_to_mpdesc_rb */
static struct rb_root mpool_pools = { NULL };

static merr_t mpool_create_rmlogs(struct mpool_descriptor *mp, u64 mlog_cap);

merr_t mpool_get_mpname(struct mpool_descriptor *mp, char *mpname, size_t mplen)
{
	if (!mp || !mpname)
		return merr(EINVAL);

	strlcpy(mpname, mp->pds_name, mplen);

	return 0;
}

static merr_t
mpool_mdc0_sb2obj(
	struct mpool_descriptor        *mp,
	struct omf_sb_descriptor       *sb,
	struct ecio_layout_descriptor **l1,
	struct ecio_layout_descriptor **l2)
{
	struct uuid_to_idx_rb  *urb_elem = NULL;
	merr_t                  err;

	/* mdc0 mlog1 layout */
	*l1 = ecio_layout_alloc(mp, &sb->osb_mdc01uuid, MDC0_OBJID_LOG1,
				sb->osb_mdc01gen, 0,
				sb->osb_mdc01desc.ol_zcnt);
	if (!*l1) {
		*l1 = NULL;
		*l2 = NULL;
		err = merr(ENOMEM);
		mp_pr_err("mpool %s, MDC0 mlog1 allocation failed",
			  err, mp->pds_name);
		return err;
	}

	(*l1)->eld_state = ECIO_LYT_COMMITTED;

	urb_elem = uuid_to_idx_search(&mp->pds_dev2pdh, &sb->osb_mdc01devid);
	if (urb_elem) {
		(*l1)->eld_ld.ol_pdh = urb_elem->uti_idx;
		(*l1)->eld_ld.ol_zaddr = sb->osb_mdc01desc.ol_zaddr;
	} else {
		char uuid_str[40];

		ecio_layout_free(*l1);
		/* should never happen */
		mpool_unparse_uuid(&sb->osb_mdc01devid, uuid_str);
		err = merr(ENOENT);
		mp_pr_err("mpool %s, allocating MDC0 mlog1, can't find handle for pd uuid %s,",
			  err, mp->pds_name, uuid_str);
		*l1 = NULL;
		*l2 = NULL;

		return err;
	}

	/* mdc0 mlog2 layout */
	*l2 = ecio_layout_alloc(mp, &sb->osb_mdc02uuid, MDC0_OBJID_LOG2,
				sb->osb_mdc02gen, 0,
				sb->osb_mdc02desc.ol_zcnt);
	if (!*l2) {
		ecio_layout_free(*l1);
		*l1 = NULL;
		*l2 = NULL;
		err = merr(ENOMEM);
		mp_pr_err("mpool %s, MDC0 mlog2 allocation failed",
			  err, mp->pds_name);
		return err;
	}

	(*l2)->eld_state = ECIO_LYT_COMMITTED;

	urb_elem = uuid_to_idx_search(&mp->pds_dev2pdh, &sb->osb_mdc02devid);
	if (urb_elem) {
		(*l2)->eld_ld.ol_pdh = urb_elem->uti_idx;
		(*l2)->eld_ld.ol_zaddr = sb->osb_mdc02desc.ol_zaddr;
	} else {
		char uuid_str[40];

		ecio_layout_free(*l1);
		ecio_layout_free(*l2);
		/* should never happen */
		mpool_unparse_uuid(&sb->osb_mdc02devid, uuid_str);
		err = merr(ENOENT);
		mp_pr_err("mpool %s, allocating MDC0 mlog2, can't find handle for pd uuid %s",
			  err, mp->pds_name, uuid_str);
		*l1 = NULL;
		*l2 = NULL;

		return err;
	}

	return 0;
}

static merr_t
mpool_dev_sbwrite(
	struct mpool_descriptor    *mp,
	struct mpool_dev_info      *pd,
	struct omf_sb_descriptor   *sbmdc0)
{
	merr_t                      err;
	struct omf_sb_descriptor   *sb = NULL;
	struct mc_parms		    mc_parms;


	sb = kzalloc(sizeof(struct omf_sb_descriptor), GFP_KERNEL);
	if (!sb) {
		err = merr(ENOMEM);
		mp_pr_err("mpool %s, writing superblock on drive %s, alloc of superblock descriptor failed %lu",
			  err, mp->pds_name, pd->pdi_name,
			  sizeof(struct omf_sb_descriptor));
		return err;
	}

	/*
	 * set superblock values common to all new drives in pool
	 * (new or extant)
	 */
	sb->osb_magic = OMF_SB_MAGIC;
	strlcpy((char *) sb->osb_name, mp->pds_name, sizeof(sb->osb_name));
	sb->osb_vers = OMF_SB_DESC_VER_LAST;
	mpool_uuid_copy(&sb->osb_poolid, &mp->pds_poolid);
	sb->osb_gen = 1;

	/* set superblock values specific to this drive */
	mpool_uuid_copy(&sb->osb_parm.odp_devid, &pd->pdi_devid);
	sb->osb_parm.odp_devsz = pd->pdi_parm.dpr_devsz;
	sb->osb_parm.odp_zonetot = pd->pdi_parm.dpr_zonetot;
	mc_pd_prop2mc_parms(&pd->pdi_parm.dpr_prop, &mc_parms);
	mc_parms2omf_devparm(&mc_parms, &sb->osb_parm);

	if (sbmdc0)
		sbutil_mdc0_copy(sb, sbmdc0);
	else
		sbutil_mdc0_clear(sb);

	err = sb_write_new(pd, sb);
	if (err) {
		mp_pr_err("mpool %s, writing superblock on drive %s, write failed",
			  err, mp->pds_name, pd->pdi_name);
	}

	kfree(sb);
	return err;
}

/**
 * mpool_mdc0_alloc()
 * @mp:
 * @sb:
 * @devrpt:
 *
 * In the context of a mpool create, allocate space for the two MDC0 mlogs
 *	and update the sb structure with the position of MDC0.
 *
 * Note: this function assumes that the media classes have already been
 *	created.
 */
static merr_t
mpool_mdc0_alloc(
	struct mpool_descriptor    *mp,
	struct omf_sb_descriptor   *sb,
	struct mpool_devrpt        *devrpt)
{
	merr_t                  err = 0;
	u64                     zcnt = 0;
	u64                     pdh = 0;
	u64                     zonelen = 0;
	u64                     fzero_flag;
	struct mpool_dev_info  *pd = NULL;
	struct media_class     *mc;
	bool                    alloc = false;

	sbutil_mdc0_clear(sb);

	/*
	 * PD_ERASE_FZERO: fill zeros
	 * PD_ERASE_READS_ERASED: need to read from the erased block after
	 *                        erase is finished
	 */
	fzero_flag = PD_ERASE_READS_ERASED;

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		struct mpool_uuid    uuid;

		u32    cnt;

		pd = &mp->pds_pdv[pdh];
		mc = &mp->pds_mc[pd->pdi_mclass];

		if (pd->pdi_mclass != mp->pds_mdparm.md_mclass)
			continue;

		alloc = true;

		/* Metadata media class */
		if (!zcnt) {
			zonelen = (u64)pd->pdi_parm.dpr_zonepg << PAGE_SHIFT;
			zcnt = 1 + ((mp->pds_params.mp_mdc0cap - 1) /
					zonelen);
		}

		cnt = sb_zones_for_sbs(&(pd->pdi_prop));
		if (cnt < 1) {
			err = merr(EINVAL);
			mp_pr_err("%s superblock update image MDC0 info, can't get non superblock range for drive %s %u",
				  err, mp->pds_name, pd->pdi_name, cnt);
			break;
		}

		if ((pd->pdi_zonetot - cnt) < zcnt * 2) {
			err = merr(ENOSPC);
			mp_pr_err("%s superblock upate image MDC0 info, not enough room for MDC0 on drive %s %lu %u %lu",
				  err, mp->pds_name, pd->pdi_name,
				  (ulong)pd->pdi_zonetot, cnt, (ulong)zcnt);
			break;
		}

		/*
		 * mdc0 log1/2 alloced on first 2 * zcnt zone's
		 */
		err = pd_bio_erase(pd, cnt, zcnt * 2, fzero_flag);
		if (err) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "erase MDC0 failed on %s %u %lu",
				     pd->pdi_name, cnt, (ulong)zcnt);
			break;
		}

		/*
		 * Fill in common mdc0 log1/2 and drive info.
		 */
		sb->osb_mdc01gen = 1;
		sb->osb_mdc01desc.ol_zcnt = zcnt;
		mpool_generate_uuid(&uuid);
		mpool_uuid_copy(&sb->osb_mdc01uuid, &uuid);

		sb->osb_mdc02gen = 2;
		sb->osb_mdc02desc.ol_zcnt = zcnt;
		mpool_generate_uuid(&uuid);
		mpool_uuid_copy(&sb->osb_mdc02uuid, &uuid);

		mpool_uuid_copy(&sb->osb_mdc01devid, &pd->pdi_devid);
		sb->osb_mdc01desc.ol_zaddr = cnt;

		mpool_uuid_copy(&sb->osb_mdc02devid, &pd->pdi_devid);
		sb->osb_mdc02desc.ol_zaddr = cnt + zcnt;

		mpool_uuid_copy(&sb->osb_mdc0dev.odp_devid, &pd->pdi_devid);
		sb->osb_mdc0dev.odp_devsz = pd->pdi_parm.dpr_devsz;
		sb->osb_mdc0dev.odp_zonetot = pd->pdi_parm.dpr_zonetot;
		mc_parms2omf_devparm(&mc->mc_parms, &sb->osb_mdc0dev);
	}

	if (!err && !alloc) {
		err = merr(ENOSPC);
		mp_pr_err("%s superblock update memory image MDC0 information, not enough drives",
			  err, mp->pds_name);
	}

	return err;
}

static merr_t
mpool_dev_sbwrite_newpool(
	struct mpool_descriptor    *mp,
	struct omf_sb_descriptor   *sbmdc0,
	struct mpool_devrpt        *devrpt)
{
	merr_t                  err;
	u64                     pdh = 0;
	struct mpool_dev_info  *pd = NULL;

	/* alloc mdc0 and generate mdc0 info for superblocks */
	err = mpool_mdc0_alloc(mp, sbmdc0, devrpt);
	if (err) {
		mp_pr_err("%s MDC0 allocation failed", err, mp->pds_name);
		return err;
	}

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		pd = &mp->pds_pdv[pdh];

		if (pd->pdi_mclass == mp->pds_mdparm.md_mclass)
			err = mpool_dev_sbwrite(mp, pd, sbmdc0);
		else
			err = mpool_dev_sbwrite(mp, pd, NULL);
		if (err) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "superblock write %s failed, %d %d %d",
				     pd->pdi_name, pd->pdi_mclass,
				     mp->pds_mdparm.md_mclass,
				     merr_errno(err));
			break;
		}
	}

	return err;
}

merr_t
mpool_desc_pdmc_add(
	struct mpool_descriptor		*mp,
	u32				 flags,
	u16				 pdh,
	struct omf_devparm_descriptor	*omf_devparm,
	bool				 check_only,
	struct mpool_devrpt		*devrpt)
{
	struct mpool_dev_info  *pd = NULL;
	struct media_class     *mc;
	struct mc_parms		mc_parms;

	merr_t err;

	pd = &mp->pds_pdv[pdh];
	if (omf_devparm == NULL)
		mc_pd_prop2mc_parms(&pd->pdi_parm.dpr_prop, &mc_parms);
	else
		mc_omf_devparm2mc_parms(omf_devparm, &mc_parms);

	if (!mclassp_valid(mc_parms.mcp_classp)) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "media class %u of %s is undefined",
			     mc_parms.mcp_classp, pd->pdi_name);
		return merr(EINVAL);
	}

	/*
	 * Devices that do not support updatable sectors can't be included
	 * in an mpool. Do not check if in the context of an unavailable PD
	 * during activate, because it is impossible to determine the PD
	 * properties.
	 */
	if ((omf_devparm == NULL) &&
	    !(pd->pdi_cmdopt & PD_CMD_SECTOR_UPDATABLE)) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "device %s sectors are not updatable",
			     pd->pdi_name);
		return merr(EINVAL);
	}

	/*
	 * Enforce that for a same media class, all drives of the mpool
	 * have the same parameters (listed in mc_parms).
	 */
	mc = &mp->pds_mc[mc_parms.mcp_classp];
	if (mc->mc_pdmc < 0) {
		struct mc_smap_parms   mcsp;
		/*
		 * No media class corresponding to the PD class yet, create one.
		 */
		err = mc_smap_parms_get(mp, mc_parms.mcp_classp, &mcsp);
		if (ev(err))
			return err;

		if (!check_only)
			mc_init_class(mc, &mc_parms, &mcsp);
	} else {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "drive add %s failed, only 1 device allowed per mclass",
			     pd->pdi_name);

		return merr(EINVAL);
	}

	if (check_only)
		return 0;

	mc->mc_pdmc = pdh;

	return 0;
}

/**
 * mpool_dev_check_new() - check if a drive is ready to be added in an mpool.
 * @mp:
 * @pd:
 * @devrpt:
 */
static merr_t
mpool_dev_check_new(
	struct mpool_descriptor    *mp,
	struct mpool_dev_info      *pd,
	struct mpool_devrpt        *devrpt)
{
	int     rval;

	/* confirm drive does not contain mpool magic value */
	rval = sb_magic_check(pd);
	if (rval) {
		if (rval < 0) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "can't read superblock mpool magic from %s %d",
				     pd->pdi_name, rval);
			return merr(rval);
		}

		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "device %s has mpool magic in the superblock",
			     pd->pdi_name);
		return merr(EBUSY);
	}

	return 0;
}

/**
 * mpool_desc_init_newpool() -
 * @mp:
 * @flags: enum mp_mgmt_flags
 * @mdparm:
 * @devrpt:
 *
 * Called on mpool create.
 * Create the media classes and add all the mpool PDs in their media class.
 * Update the metadata media class in mp->pds_mdparm
 *
 * Note: the PD properties (pd->pdi_parm.dpr_prop) must be updated
 * and correct when entering this function.
 */
static merr_t
mpool_desc_init_newpool(
	struct mpool_descriptor    *mp,
	u32                         flags,
	struct mpool_mdparm        *mdparm,
	struct mpool_devrpt        *devrpt)
{
	u64    pdh = 0;
	merr_t err;

	if (!(flags & (1 << MP_FLAGS_FORCE))) {
		err = mpool_dev_check_new(mp, &mp->pds_pdv[pdh], devrpt);
		if (ev(err))
			return err;
	}

	/*
	 * add drive in its media class. That may create the class
	 * if first drive of the class.
	 */
	err = mpool_desc_pdmc_add(mp, flags, pdh, NULL, false, devrpt);
	if (err) {
		struct mpool_dev_info  *pd __maybe_unused;

		if (devrpt->mdr_rcode == MPOOL_RC_NONE)
			mpool_devrpt(devrpt, MPOOL_RC_MIXED, pdh, NULL);

		pd = &mp->pds_pdv[pdh];

		mp_pr_err("mpool %s, initialization of mpool desc, adding drive %s in a media class failed",
			  err, mp->pds_name, pd->pdi_name);
		return err;
	}

	mp->pds_mdparm.md_mclass = mp->pds_pdv[pdh].pdi_mclass;

	return 0;
}

static merr_t
mpool_dev_init_all(
	struct mpool_dev_info  *pdv,
	u64                     dcnt,
	char                  **dpaths,
	struct mpool_devrpt    *devrpt,
	struct pd_prop	       *pd_prop)
{
	merr_t      err = 0;
	int         idx;
	char       *pdname;

	if (dcnt == 0)
		return merr(EINVAL);

	for (idx = 0; idx < dcnt; idx++, pd_prop++) {
		err = pd_bio_dev_open(dpaths[idx], &pdv[idx].pdi_parm);
		if (err) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "Getting device %s params, open failed %d",
				     dpaths[idx], merr_errno(err));
			break;
		}

		err = pd_dev_init(&pdv[idx].pdi_parm, pd_prop);
		if (err) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "Setting device %s params failed %d",
				     dpaths[idx], merr_errno(err));
			pd_bio_dev_close(&pdv[idx].pdi_parm);
			break;
		}

		pdv[idx].pdi_state = OMF_PD_ACTIVE;

		pdname = strrchr(dpaths[idx], '/');
		pdname = pdname ? pdname + 1 : dpaths[idx];
		strlcpy(pdv[idx].pdi_name, pdname, sizeof(pdv[idx].pdi_name));

		mpool_pd_status_set(&pdv[idx], PD_STAT_ONLINE);
	}

	while (err && idx-- > 0)
		pd_bio_dev_close(&pdv[idx].pdi_parm);

	return err;
}

static int
uuid_to_mpdesc_insert(struct rb_root *root, struct mpool_descriptor *data)
{
	struct rb_node    **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct mpool_descriptor    *this =
			rb_entry(*new, struct mpool_descriptor, pds_node);

		int result = mpool_uuid_compare(&data->pds_poolid,
					      &this->pds_poolid);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->pds_node, parent, new);
	rb_insert_color(&data->pds_node, root);

	return true;
}

static void
mpool_mdc_cap_init(struct mpool_descriptor *mp, struct mpool_dev_info *pd)
{
	u64    zonesz;
	u64    defmbsz;

	zonesz  = (pd->pdi_zonepg << PAGE_SHIFT) >> 20;
	defmbsz = MPOOL_MBSIZE_MB_DEFAULT;

	if (mp->pds_params.mp_mdc0cap == 0) {
		mp->pds_params.mp_mdc0cap = max_t(u64, defmbsz, zonesz);
		mp->pds_params.mp_mdc0cap <<= 20;
	}

	if (mp->pds_params.mp_mdcncap == 0) {
		mp->pds_params.mp_mdcncap = max_t(u64, zonesz, (256 / zonesz));
		mp->pds_params.mp_mdcncap <<= 20;
	}
}

merr_t
mpool_create(
	const char             *mpname,
	u32                     flags,
	struct mpool_mdparm    *mdparm,
	char                  **dpaths,
	struct pd_prop	       *pd_prop,
	struct mpcore_params   *params,
	u64                     mlog_cap,
	struct mpool_devrpt    *devrpt)
{
	struct ecio_layout_descriptor  *mdc01, *mdc02;
	struct omf_sb_descriptor       *sbmdc0;
	struct mpool_descriptor        *mp;
	struct uuid_to_idx_rb          *elem;

	bool    active, sbvalid;
	u16     sidx;
	merr_t  err;

	mpool_devrpt_init(devrpt);

	if (!mpname || !*mpname || (mdparm->mdp_mclassp != MP_MED_ANY &&
	     !mclassp_valid(mdparm->mdp_mclassp))) {
		err = merr(EINVAL);
		mp_pr_err("mpool %s, class perf %u",
			  err, mpname ? mpname : "?", mdparm->mdp_mclassp);
		return err;
	}

	mdc01 = mdc02 = NULL;
	active = sbvalid = false;

	/* alloc mpool descriptor and fill in device-independent values */
	mp = mpool_desc_alloc();
	if (!mp) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool_desc_alloc failed");
		return merr(ENOMEM);
	}

	sbmdc0 = &(mp->pds_sbmdc0);
	strlcpy((char *)mp->pds_name, mpname, sizeof(mp->pds_name));
	mpool_generate_uuid(&mp->pds_poolid);

	if (params)
		mp->pds_params = *params;

	mp->pds_pdvcnt = 0;

	/*
	 * note: don't need mp.* locks below since no other thread can
	 * access mp
	 */
	mutex_lock(&mpool_s_lock);

	/* Allocate the per-mpool workqueue. */
	mp->pds_erase_wq = alloc_workqueue("mperasewq", WQ_HIGHPRI, 0);
	if (!mp->pds_erase_wq) {
		err = merr(ENOMEM);
		goto errout;
	}

	/*
	 * Set the devices parameters from the ones placed by the discovery
	 * in pd_prop.
	 */
	err = mpool_dev_init_all(mp->pds_pdv, 1, dpaths, devrpt, pd_prop);
	if (err) {
		mp_pr_err("mpool %s, failed to get device parameters",
			  err, mpname);
		goto errout;
	}

	mp->pds_pdvcnt = 1;

	mpool_mdc_cap_init(mp, &mp->pds_pdv[0]);

	/* init new pool drives uuid and mclassp */
	mpool_generate_uuid(&mp->pds_pdv[0].pdi_devid);

	/*
	 * Init mpool descriptor from new drive info.
	 * Creates the media classes and place the PDs in them.
	 * Determine the media class used for the metadata.
	 */
	err = mpool_desc_init_newpool(mp, flags, mdparm, devrpt);
	if (err) {
		mp_pr_err("mpool %s, desc init from new drive info failed",
			  err, mpname);
		goto errout;
	}

	/*
	 * alloc empty mdc0 and write superblocks to all drives; if
	 * crash drives with superblocks will not be recognized as mpool
	 * members because there are not yet any drive state records in mdc0
	 */
	sbvalid = true;
	err = mpool_dev_sbwrite_newpool(mp, sbmdc0, devrpt);
	if (err) {
		mp_pr_err("mpool %s, couldn't write superblocks", err, mpname);
		goto errout;
	}

	/* add devid-to-pd mapping */
	elem = kmem_cache_alloc(uuid_to_idx_rb_cache, GFP_KERNEL);
	if (!elem) {
		err = merr(ENOMEM);
		mp_pr_err("mpool %s, alloc of association drive uuid <-> drive handle failed",
			  err, mpname);
		goto errout;
	}

	mpool_uuid_copy(&elem->uti_uuid, &mp->pds_pdv[0].pdi_devid);
	elem->uti_idx = 0;
	uuid_to_idx_insert(&mp->pds_dev2pdh, elem);

	/* alloc mdc0 mlog layouts and activate mpool with empty mdc0 */
	err = mpool_mdc0_sb2obj(mp, sbmdc0, &mdc01, &mdc02);
	if (err) {
		mp_pr_err("mpool %s, alloc of MDC0 mlogs failed", err, mpname);
		goto errout;
	}

	err = pmd_mpool_activate(mp, mdc01, mdc02, 1, devrpt, 0);
	if (err) {
		mp_pr_err("mpool %s, activation failed", err, mpname);
		goto errout;
	}

	active = true;

	/*
	 * Add the version record (always first record) in MDC0.
	 * The version record is used only from version 1.0.0.1.
	 */
	if (upg_ver_cmp2(upg_mdccver_latest(), ">=", 1, 0, 0, 1)) {
		err = pmd_mdc_addrec_version(mp, 0);
		if (err) {
			mp_pr_err("mpool %s, writing MDC version record in MDC0 failed",
				  err, mpname);
			goto errout;
		}
	}


	/*
	 * add drive state records to mdc0; if crash before complete will
	 * detect if attempt to open same drive list; it may be possible to
	 * open the subset of the drive list for which state records were
	 * written without detection, in which case the other drives can be
	 * added
	 */
	err = pmd_prop_mcconfig(mp, &mp->pds_pdv[0], false);
	if (err) {
		mp_pr_err("mpool %s, add drive state to MDC0 failed",
			  err, mpname);
		goto errout;
	}

	/*
	 * Create mdcs so user can create mlog/mblock objects;
	 * if crash before all the configured mdcs are created, or if create
	 * fails, will detect in activate and re-try.
	 *
	 * mp_cmdcn corresponds to the number of MDCNs used for client
	 * objects, i.e., [1 - mp_cmdcn]
	 */
	for (sidx = 1; sidx <= mp->pds_params.mp_mdcnum; sidx++) {
		err = pmd_mdc_alloc(mp, mp->pds_params.mp_mdcncap, sidx - 1);
		if (err) {
			mp_pr_info("mpool %s, only %u MDCs out of %lu MDCs were created",
				  mpname, sidx - 1,
				  (ulong)mp->pds_params.mp_mdcnum);
			/*
			 * For MDCN creation failure, mask the error and
			 * continue further with create.
			 */
			err = 0;
			break;
		}
	}
	pmd_update_credit(mp);

	/*
	 * Attempt root mlog creation only if MDC1 was successfully created.
	 * If MDC1 doesn't exist, it will be re-created during activate.
	 */
	if (sidx > 1) {
		err = mpool_create_rmlogs(mp, mlog_cap);
		if (err) {
			mp_pr_info("mpool %s, root mlog creation failed",
				   mpname);
			/*
			 * If root mlog creation fails, mask the error and
			 * proceed with create. root mlogs will be re-created
			 * during activate.
			 */
			err = 0;
		}
	}

	/* add mp to the list of all open mpools */
	uuid_to_mpdesc_insert(&mpool_pools, mp);

errout:

	if (mp->pds_erase_wq)
		destroy_workqueue(mp->pds_erase_wq);

	/* free up resources */
	if (active)
		pmd_mpool_deactivate(mp);

	if (err && sbvalid) {
		struct mpool_dev_info  *pd;
		merr_t                  err1;

		/* Erase super blocks on the drives */
		pd = &mp->pds_pdv[0];
		err1 = sb_erase(pd);
		if (err1)
			mp_pr_info("%s: cleanup, sb erase failed on device %s",
				   mp->pds_name, pd->pdi_name);
	}

	mpool_desc_free(mp);

	mutex_unlock(&mpool_s_lock);

	return err;
}

static struct mpool_descriptor *
uuid_to_mpdesc_search(struct rb_root *root, struct mpool_uuid *key_uuid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct mpool_descriptor    *data =  rb_entry(
			node, struct mpool_descriptor, pds_node);

		int  result = mpool_uuid_compare(key_uuid, &data->pds_poolid);

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

/**
 * mpool_desc_init_sb() -
 * @mp:
 * @sbmdc0: output. MDC0 information stored in the super blocks.
 * @devrpt:
 * @flags:
 * Read the super blocks of the PDs.
 * Adjust the discovered PD properties stored in pd->pdi_parm.dpr_prop with
 * PD parameters from the super block. Some of discovered PD properties are
 * default (like zone size) and need to to be adjusted to what the PD actually
 * use.
 */
static merr_t
mpool_desc_init_sb(
	struct mpool_descriptor    *mp,
	struct omf_sb_descriptor   *sbmdc0,
	struct mpool_devrpt        *devrpt,
	u32                         flags,
	bool                       *mc_resize,
	const char                 *mp_newname)
{
	struct omf_sb_descriptor   *sb = NULL;
	struct mpool_mdparm         mdtemp;
	struct mpool_dev_info      *pd = NULL;
	struct uuid_to_idx_rb      *urb_elem = NULL;

	merr_t err;
	u16    omf_ver = OMF_SB_DESC_UNDEF;
	u8     pdh = 0;
	bool   mdc0found = false;
	bool   force = ((flags & (1 << MP_FLAGS_FORCE)) != 0);

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	if (!sb) {
		err = merr(ENOMEM);
		mp_pr_err("allocation of superblock descriptor failed %lu",
			  err, (ulong)sizeof(struct omf_sb_descriptor));
		return err;
	}

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		struct omf_devparm_descriptor  *dparm;
		bool                            resize = false;

		pd = &mp->pds_pdv[pdh];

		/*
		 * Read superblock; init and validate pool drive info
		 * from device parameters stored in the super block.
		 */
		err = sb_read(pd, sb, &omf_ver, force, devrpt);
		if (ev(err)) {
			if (devrpt->mdr_rcode == MPOOL_RC_NONE) {
				mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
					     "superblock read from %s failed",
					     pd->pdi_name);
			}
			kfree(sb);
			return err;
		}

		if (!pdh) {
			size_t n __maybe_unused;

			/*
			 * first drive; confirm pool not open; set pool-wide
			 * properties
			 */
			if (uuid_to_mpdesc_search(&mpool_pools,
						  &sb->osb_poolid)) {
				char uuid_str[40];

				mpool_unparse_uuid(&sb->osb_poolid, uuid_str);

				mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
					     "mpool %s already activated, id %s, pd name %s",
					     err, sb->osb_name,
					     uuid_str, pd->pdi_name);

				kfree(sb);
				return merr(EBUSY);
			}
			mpool_uuid_copy(&mp->pds_poolid, &sb->osb_poolid);

			n = strlcpy(mp->pds_name, (char *)sb->osb_name,
				    sizeof(mp->pds_name));
			assert(n < sizeof(mp->pds_name));
		} else {
			/*
			 * second or later drive; validate pool-wide
			 * properties
			 */
			if (mpool_uuid_compare(&sb->osb_poolid,
					     &mp->pds_poolid) != 0) {
				char uuid_str1[40], uuid_str2[40];

				mpool_unparse_uuid(&sb->osb_poolid, uuid_str1);
				mpool_unparse_uuid(&mp->pds_poolid, uuid_str2);

				mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
					     "pd %s mpool id %s is different from initial mpool id %s",
					     err, mp->pds_name,
					     pd->pdi_name, uuid_str1,
					     uuid_str2);

				kfree(sb);
				return merr(EINVAL);
			}
		}

		dparm = &sb->osb_parm;
		if (!force && pd->pdi_devsz > dparm->odp_devsz) {
			mp_pr_info("mpool %s device %s, discovered size %lu > on-media size %lu",
				mp->pds_name, pd->pdi_name,
				(ulong)pd->pdi_devsz, (ulong)dparm->odp_devsz);

			if ((flags & (1 << MP_FLAGS_RESIZE)) == 0) {
				pd->pdi_devsz = dparm->odp_devsz;
			} else {
				dparm->odp_devsz  = pd->pdi_devsz;
				dparm->odp_zonetot = pd->pdi_devsz /
					(pd->pdi_zonepg << PAGE_SHIFT);

				pd->pdi_zonetot = dparm->odp_zonetot;
				resize = true;
			}
		}

		/* Validate mdc0 info in superblock if present */
		if (!sbutil_mdc0_isclear(sb)) {
			if (!force && !sbutil_mdc0_isvalid(sb, &mdtemp)) {
				mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
					     "invalid superblock MDC0 in pd %s",
					     pd->pdi_name);
				kfree(sb);
				return merr(EINVAL);
			}

			dparm = &sb->osb_mdc0dev;
			if (resize) {
				assert(pd->pdi_devsz > dparm->odp_devsz);

				dparm->odp_devsz  = pd->pdi_devsz;
				dparm->odp_zonetot = pd->pdi_devsz /
					(pd->pdi_zonepg << PAGE_SHIFT);
			}

			sbutil_mdc0_copy(sbmdc0, sb);
			mdc0found = true;
		}

		/*
		 * Set drive info confirming devid is unique and zone parms
		 * match
		 */
		if (uuid_to_idx_search(&mp->pds_dev2pdh,
				       &sb->osb_parm.odp_devid)) {
			char uuid_str[40];

			mpool_unparse_uuid(&sb->osb_parm.odp_devid, uuid_str);

			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "duplicate devices (same uuid %s), pd %s",
				     uuid_str, pd->pdi_name);

			kfree(sb);
			return merr(EINVAL);
		}

		urb_elem = kmem_cache_alloc(uuid_to_idx_rb_cache, GFP_KERNEL);
		if (!urb_elem) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "uuid_to_idx alloc failed");

			kfree(sb);
			return merr(ENOMEM);
		}

		if (omf_ver > OMF_SB_DESC_VER_LAST) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "unsupported superblock version %d",
				     omf_ver);

			kfree(sb);
			return merr(EOPNOTSUPP);
		} else if (!force && (omf_ver < OMF_SB_DESC_VER_LAST ||
				      resize)) {
			if ((flags & (1 << MP_FLAGS_PERMIT_META_CONV)) == 0) {
				char buf1[MAX_MDCCVERSTR];
				char buf2[MAX_MDCCVERSTR];
				struct omf_mdccver  *mdccver;

				/*
				 * We have to get the permission from users
				 * to update mpool meta data
				 */
				mdccver = omf_sbver_to_mdccver(omf_ver);
				assert(mdccver != NULL);

				upg_mdccver2str(mdccver, buf1, sizeof(buf1));
				upg_mdccver2str(upg_mdccver_latest(),
						buf2, sizeof(buf2));

				mpool_devrpt(
					devrpt, MPOOL_RC_ERRMSG, -1,
					"mpool metadata upgrade from version %s (%s) to %s (%s) required",
					buf1,
					upg_mdccver_comment(mdccver) ?: "",
					buf2, upg_mdccver_latest_comment());

				err = merr(EPERM);
				mp_pr_err("%s superblock content upgrade from version %d to %d required",
					  err, mp->pds_name, omf_ver,
					  OMF_SB_DESC_VER_LAST);

				kfree(sb);
				return err;
			}

			/*
			 * We need to overwrite the old version
			 * superblock on the device
			 */
			err = sb_write_update(pd, sb);
			if (err) {
				mp_pr_err("Failed to convert or overwrite the old version mpool %s's superblock on device %s",
					  err, mp->pds_name, pd->pdi_name);
				kfree(sb);
				return err;
			}

			if (!resize)
				mp_pr_info("Convert old version %d mpool %s superblock into new version %d on device %s",
					  omf_ver, mp->pds_name, sb->osb_vers,
					  pd->pdi_name);
		}

		urb_elem->uti_idx = pdh;
		mpool_uuid_copy(&urb_elem->uti_uuid, &sb->osb_parm.odp_devid);
		uuid_to_idx_insert(&mp->pds_dev2pdh, urb_elem);

		mpool_uuid_copy(&pd->pdi_devid, &sb->osb_parm.odp_devid);

		/*
		 * add drive in its media class. Create the media class if
		 * not yet created.
		 */
		err = mpool_desc_pdmc_add(mp, 0, pdh, NULL, false, devrpt);
		if (err) {
			mp_pr_err("Initialization of mpool %s desc, adding drive %s in a media class failed",
				  err, mp->pds_name, pd->pdi_name);

			kfree(sb);
			return err;
		}

		/*
		 * Record the media class used by the MDC0 metadata.
		 */
		if (mdc0found)
			mp->pds_mdparm.md_mclass = pd->pdi_mclass;

		if (resize && mc_resize)
			mc_resize[pd->pdi_mclass] = resize;
	}

	if (!mdc0found) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "no MDC0 instance found");

		kfree(sb);
		return merr(EINVAL);
	}

	kfree(sb);

	return 0;
}

merr_t
mpool_activate(
	u64                         dcnt,
	char                      **dpaths,
	struct pd_prop		   *pd_prop,
	bool                        force,
	u64                         mlog_cap,
	struct mpcore_params       *params,
	u32                         flags,
	struct mpool_descriptor   **mpp,
	struct mpool_devrpt        *devrpt)
{
	struct ecio_layout_descriptor  *mdc01 = NULL;
	struct ecio_layout_descriptor  *mdc02 = NULL;
	struct omf_sb_descriptor       *sbmdc0;
	struct mpool_descriptor        *mp;
	struct media_class	       *mcmeta;
	merr_t                          err;

	u64     mdcmax, mdcnum, mdcncap, mdc0cap;
	bool    active, uafound;
	int     dup, doff, cnt, i;
	u8      pdh;
	bool    mc_resize[MP_MED_NUMBER] = { };

	mpool_devrpt_init(devrpt);
	active = false;
	*mpp = NULL;

	if (dcnt > MPOOL_DRIVES_MAX) {
		err = merr(EINVAL);
		mp_pr_err("too many drives in input %lu, first drive path %s",
			  err, (ulong)dcnt, dpaths[0]);
		return err;
	}

	/*
	 * verify no duplicate drive paths
	 */
	err = check_for_dups(dpaths, dcnt, &dup, &doff);
	if (err) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "check_for_dups failed");
		return err;
	} else if (dup) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "duplicate device path %s",
			     (doff == -1) ? "" : dpaths[doff]);
		return merr(EINVAL);
	}

	/* alloc mpool descriptor and fill in device-indepdendent values */
	mp = mpool_desc_alloc();
	if (!mp) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool_desc_alloc failed");
		return merr(ENOMEM);
	}

	sbmdc0 = &(mp->pds_sbmdc0);

	mp->pds_pdvcnt = 0;

	if (params)
		mp->pds_params = *params;

	/*
	 * note: don't need mp.* locks below since no other thread can
	 * access mp
	 */
	mutex_lock(&mpool_s_lock);

	/* Note:  On Linux 2.x (and maybe somewhere in the 3.x train) you get
	 * exactly one worker thread if you ask for exactly one, and exactly
	 * one thread per-cpu if you ask for any other number of threads.
	 */
	cnt = max_t(int, 16, num_online_cpus());

	mp->pds_workq = alloc_workqueue("mpoolwq", WQ_UNBOUND, cnt);
	if (!mp->pds_workq) {
		err = merr(ENOMEM);
		mp_pr_err("alloc mpoolwq failed, first drive path %s",
			  err, dpaths[0]);
		goto errout;
	}

	mp->pds_erase_wq = alloc_workqueue("mperasewq", WQ_HIGHPRI, 0);
	if (!mp->pds_erase_wq) {
		err = merr(ENOMEM);
		mp_pr_err("alloc mperasewq failed, first drive path %s",
			  err, dpaths[0]);
		goto errout;
	}

	/* get device parm for all drive paths */
	err = mpool_dev_init_all(mp->pds_pdv, dcnt, dpaths, devrpt, pd_prop);
	if (ev(err)) {
		mp_pr_err("can't get drive device params, first drive path %s",
			  err, dpaths[0]);
		goto errout;
	}

	/* Set mp.pdvcnt so dpaths will get closed in cleanup if activate fails.
	 */
	mp->pds_pdvcnt = dcnt;

	/* init mpool descriptor from superblocks on drives */
	err = mpool_desc_init_sb(mp, sbmdc0, devrpt, flags, mc_resize, NULL);
	if (ev(err)) {
		mp_pr_err("mpool_desc_init_sb failed, first drive path %s",
			  err, dpaths[0]);
		goto errout;
	}

	mcmeta = &mp->pds_mc[mp->pds_mdparm.md_mclass];
	if (mcmeta->mc_pdmc < 0) {
		err = merr(ENODEV);
		mp_pr_err("mpool %s, too many unavailable drives",
			  err, mp->pds_name);
		goto errout;
	}

	/* alloc mdc0 mlog layouts from superblock and activate mpool */
	err = mpool_mdc0_sb2obj(mp, sbmdc0, &mdc01, &mdc02);
	if (ev(err)) {
		mp_pr_err("mpool %s, allocation of MDC0 mlogs layouts failed",
			  err, mp->pds_name);
		goto errout;
	}

	err = pmd_mpool_activate(mp, mdc01, mdc02, 0, devrpt, flags);
	if (ev(err)) {
		mp_pr_err("mpool %s, activation failed", err, mp->pds_name);
		goto errout;
	}

	active = true;

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		struct mpool_dev_info  *pd;

		pd = &mp->pds_pdv[pdh];

		if (mc_resize[pd->pdi_mclass]) {
			err = pmd_prop_mcconfig(mp, pd, false);
			if (err) {
				mp_pr_err("mpool %s, updating MCCONFIG record for resize failed",
					  err, mp->pds_name);
				goto errout;
			}
		}

		if (pd->pdi_mclass == MP_MED_CAPACITY)
			mpool_mdc_cap_init(mp, pd);
	}

	/* tolerate unavailable drives only if force flag specified */
	uafound = false;
	for (i = 0; i < MP_MED_NUMBER; i++) {
		struct media_class *mc;

		mc = &mp->pds_mc[i];
		if (mc->mc_uacnt) {
			uafound = true;
			break;
		}
	}

	if (!force && uafound) {
		err = merr(ENODEV);
		mp_pr_err("mpool %s, unavailable drives present",
			  err, mp->pds_name);
		goto errout;
	}

	/*
	 * Create mdcs if needed so user can create mlog/mblock objects;
	 * Only needed if the configured number of mdcs did not get created
	 * during mpool create due to crash or failure.
	 */
	mdcmax = mdcncap = mdc0cap = 0;
	mdcnum = mp->pds_params.mp_mdcnum;

	pmd_mdc_cap(mp, &mdcmax, &mdcncap, &mdc0cap);

	if (mdc0cap)
		mp->pds_params.mp_mdc0cap = mdc0cap;

	if (mdcncap && mdcmax) {
		mdcncap = mdcncap / mdcmax;
		mp->pds_params.mp_mdcncap = mdcncap;
		mp->pds_params.mp_mdcnum  = mdcmax;
	}

	if (mdcmax < mdcnum) {
		mp_pr_info("mpool %s, detected missing MDCs %lu %lu",
			   mp->pds_name, (ulong)mdcnum, (ulong)mdcmax);

		for (mdcmax++; mdcmax <= mdcnum; mdcmax++) {

			err = pmd_mdc_alloc(mp, mp->pds_params.mp_mdcncap,
					    mdcmax);
			if (!err)
				continue;

			/* MDC1 creation failure - non-functional mpool */
			if (mdcmax < 2) {
				mp_pr_err("mpool %s, MDC1 can't be created",
					  err, mp->pds_name);
				goto errout;
			}

			mp_pr_notice("mpool %s, couldn't create %lu MDCs out of the requested %lu MDCs",
				  mp->pds_name, (ulong)(mdcnum - mdcmax + 1),
				  (ulong)mdcnum);

			/*
			 * For MDCN (N > 1) creation failure, log a warning,
			 * mask the error and continue with activate. Mpool
			 * only needs a minimum of 1 MDC to be functional.
			 */
			err = 0;

			break;
		}
		mp->pds_params.mp_mdcnum = mdcmax - 1;
	}

	pmd_update_credit(mp);

	/*
	 * If we reach here, then MDC1 must exist. Now, make sure that the
	 * root mlogs also exist and if they don't, re-create them.
	 */
	err = mpool_create_rmlogs(mp, mlog_cap);
	if (ev(err)) {
		/* root mlogs creation failure - non-functional mpool */
		mp_pr_err("mpool %s, root mlogs creation failed",
			  err, mp->pds_name);
		goto errout;
	}

	/* add mp to the list of all activated mpools */
	uuid_to_mpdesc_insert(&mpool_pools, mp);

	/* Start the background thread doing pre-compaction of MDC1/255 */
	pmd_precompact_start(mp);


errout:
	if (ev(err)) {
		if (mp->pds_workq)
			destroy_workqueue(mp->pds_workq);
		if (mp->pds_erase_wq)
			destroy_workqueue(mp->pds_erase_wq);

		/* activate failed; cleanup */
		if (active)
			pmd_mpool_deactivate(mp);

		mpool_desc_free(mp);
		mp = NULL;
	}

	mutex_unlock(&mpool_s_lock);

	*mpp = mp;

	if (!err) {
		/*
		 * Start the periodic background job which logs a message
		 * when an mpool's usable space is close to its limits.
		 */
		struct smap_usage_work *usagew;

		usagew = &mp->pds_smap_usage_work;

		INIT_DELAYED_WORK(&usagew->smapu_wstruct, smap_log_mpool_usage);
		usagew->smapu_mp = mp;
		smap_log_mpool_usage(&usagew->smapu_wstruct.work);
	}

	return err;
}

merr_t mpool_deactivate(struct mpool_descriptor *mp)
{
	pmd_precompact_stop(mp);
	smap_wait_usage_done(mp);

	mutex_lock(&mpool_s_lock);
	destroy_workqueue(mp->pds_workq);
	destroy_workqueue(mp->pds_erase_wq);

	pmd_mpool_deactivate(mp);

	mpool_desc_free(mp);
	mutex_unlock(&mpool_s_lock);

	return 0;
}

merr_t mpool_queue_work(struct mpool_descriptor *mp, struct work_struct *work)
{
	if (!queue_work(mp->pds_workq, work))
		return merr(EEXIST);

	return 0;
}

merr_t
mpool_destroy(
	u64                         dcnt,
	char                      **dpaths,
	struct pd_prop             *pd_prop,
	u32                         flags,
	struct mpool_devrpt        *devrpt)
{
	struct omf_sb_descriptor   *sbmdc0;
	struct mpool_descriptor    *mp;
	merr_t                      err;

	int     i;
	int     dup;
	int     doff;

	mpool_devrpt_init(devrpt);

	if (dcnt > MPOOL_DRIVES_MAX) {
		err = merr(EINVAL);
		mp_pr_err("first drive path %s, too many drives %lu %d",
			  err, dpaths[0], (ulong)dcnt, MPOOL_DRIVES_MAX);
		return err;
	} else if (dcnt == 0) {
		return merr(EINVAL);
	}

	/*
	 * verify no duplicate drive paths
	 */
	err = check_for_dups(dpaths, dcnt, &dup, &doff);
	if (err) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "check_for_dups failed");
		return err;
	} else if (dup) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "duplicate device paths");
		return merr(ENOMEM);
	}

	sbmdc0 = kzalloc(sizeof(*sbmdc0), GFP_KERNEL);
	if (!sbmdc0) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "superblock alloc failed");
		return merr(ENOMEM);
	}

	/* alloc mpool descriptor and fill in device-indepdendent values */
	mp = mpool_desc_alloc();
	if (!mp) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool_desc_alloc failed");
		kfree(sbmdc0);
		return merr(ENOMEM);
	}

	mp->pds_pdvcnt = 0;

	/*
	 * note: don't need mp.* locks below since no other thread can
	 * access mp
	 */
	mutex_lock(&mpool_s_lock);

	/* get device parm for all drive paths */
	err = mpool_dev_init_all(mp->pds_pdv, dcnt, dpaths, devrpt, pd_prop);
	if (ev(err)) {
		mp_pr_err("can't get drives device parameters, first drive path %s",
			  err, dpaths[0]);
		goto errout;
	}

	/* Set mp.pdvcnt so dpaths will get closed in cleanup if open fails.
	 */
	mp->pds_pdvcnt = dcnt;

	/* init mpool descriptor from superblocks on drives */
	err = mpool_desc_init_sb(mp, sbmdc0, devrpt, flags, NULL, NULL);
	if (err) {
		mp_pr_err("mpool %s, first drive path %s, init of mpool descriptor from superblocks on drives failed",
			  err, (mp->pds_name == NULL) ? "" : mp->pds_name,
			  dpaths[0]);
		goto errout;
	}

	/* Erase super blocks on the drives */
	for (i = 0; i < mp->pds_pdvcnt; i++) {
		err = sb_erase(&mp->pds_pdv[i]);
		if (err) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "superblock erase on %s failed",
				     mp->pds_pdv[i].pdi_name);
			break;
		}
	}

errout:
	mpool_desc_free(mp);

	mutex_unlock(&mpool_s_lock);

	kfree(sbmdc0);

	return err;
}

merr_t
mpool_rename(
	u64                         dcnt,
	char                      **dpaths,
	struct pd_prop             *pd_prop,
	u32                         flags,
	const char                 *mp_newname,
	struct mpool_devrpt        *devrpt)
{
	struct omf_sb_descriptor   *sb;
	struct mpool_descriptor    *mp;
	struct mpool_dev_info      *pd = NULL;
	merr_t                      err = 0;

	u16    omf_ver = OMF_SB_DESC_UNDEF;
	u8     pdh;
	int    dup;
	int    doff;
	bool   force = ((flags & (1 << MP_FLAGS_FORCE)) != 0);

	mpool_devrpt_init(devrpt);

	if (!mp_newname || dcnt == 0)
		return merr(EINVAL);

	if (dcnt > MPOOL_DRIVES_MAX) {
		err = merr(EINVAL);
		mp_pr_err("first drive path %s, too many drives %lu %d",
			  err, dpaths[0], (ulong)dcnt, MPOOL_DRIVES_MAX);
		return err;
	}

	/*
	 * verify no duplicate drive paths
	 */
	err = check_for_dups(dpaths, dcnt, &dup, &doff);
	if (err) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "check_for_dups failed");
		return err;
	} else if (dup) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "duplicate device paths");
		return merr(ENOMEM);
	}

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	if (!sb) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "superblock alloc failed");
		return merr(ENOMEM);
	}

	/* alloc mpool descriptor and fill in device-indepdendent values */
	mp = mpool_desc_alloc();
	if (!mp) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool_desc_alloc failed");
		kfree(sb);
		return merr(ENOMEM);
	}

	mp->pds_pdvcnt = 0;

	/*
	 * Note: don't need mp.* locks below since no other thread can
	 * access mp
	 */
	mutex_lock(&mpool_s_lock);

	/* Get device parm for all drive paths */
	err = mpool_dev_init_all(mp->pds_pdv, dcnt, dpaths, devrpt, pd_prop);
	if (ev(err)) {
		mp_pr_err("can't get drives device parameters, first drive path %s",
			  err, dpaths[0]);
		goto errout;
	}

	/* Set mp.pdvcnt so dpaths will get closed in cleanup if open fails.
	 */
	mp->pds_pdvcnt = dcnt;

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		pd = &mp->pds_pdv[pdh];

		/*
		 * Read superblock; init and validate pool drive info
		 * from device parameters stored in the super block.
		 */
		err = sb_read(pd, sb, &omf_ver, force, devrpt);
		if (ev(err)) {
			if (devrpt->mdr_rcode == MPOOL_RC_NONE) {
				mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
					     "superblock read from %s failed",
					     pd->pdi_name);
			}
			goto errout;
		}

		if (omf_ver > OMF_SB_DESC_VER_LAST ||
		    omf_ver < OMF_SB_DESC_VER_LAST) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "superblock version invalid %d %d",
				     omf_ver, OMF_SB_DESC_VER_LAST);
			err = merr(EOPNOTSUPP);
			goto errout;
		}

		if (!strcmp(mp_newname, sb->osb_name))
			continue;

		strlcpy(sb->osb_name, mp_newname, sizeof(sb->osb_name));

		err = sb_write_update(pd, sb);
		if (err) {
			mp_pr_err("Failed to rename mpool %s on device %s",
				  err, mp->pds_name, pd->pdi_name);
			goto errout;
		}
	}

errout:
	mutex_unlock(&mpool_s_lock);

	mpool_desc_free(mp);
	kfree(sb);

	return err;
}

merr_t
mpool_drive_add(
	struct mpool_descriptor    *mp,
	char                       *dpath,
	struct pd_prop             *pd_prop,
	struct mpool_devrpt        *devrpt)
{
	struct mpool_dev_info  *pd;
	struct mc_smap_parms    mcsp;

	char  *dpathv[1] = { dpath };
	merr_t err;
	bool   smap = false;
	bool   erase = false;

	mpool_devrpt_init(devrpt);

	/*
	 * all device list changes are serialized via mpool_s_lock so
	 * don't need to acquire mp.pdvlock until ready to update mpool
	 * descriptor
	 */
	mutex_lock(&mpool_s_lock);

	if (mp->pds_pdvcnt >= MPOOL_DRIVES_MAX) {
		mutex_unlock(&mpool_s_lock);

		mp_pr_warn("mpool %s, adding drive %s failed, too many drives %u %d",
			   mp->pds_name, dpath, mp->pds_pdvcnt,
			   MPOOL_DRIVES_MAX);
		return merr(EINVAL);
	}

	/*
	 * get device parm for dpath; use next slot in mp.pdv which won't
	 * be visible until we update mp.pdvcnt
	 */
	pd = &mp->pds_pdv[mp->pds_pdvcnt];

	/*
	 * Some leftover may be present due to a previous try to add a PD
	 * at this position. Clear up.
	 */
	memset(pd, 0, sizeof(*pd));

	err = mpool_dev_init_all(pd, 1, dpathv, devrpt, pd_prop);
	if (err) {
		mutex_unlock(&mpool_s_lock);

		mp_pr_err("mpool %s, adding drive %s failed, can't get drives device parameters",
			   err, mp->pds_name, dpath);
		return err;
	}

	/* confirm drive meets all criteria for adding to this mpool */
	err = mpool_dev_check_new(mp, pd, devrpt);
	if (ev(err)) {
		mp_pr_err("mpool %s, adding drive %s failed, check of the drive failed",
			  err, mp->pds_name, dpath);
		goto errout;
	}

	/*
	 * Check that the drive can be added in a media class.
	 */
	down_read(&mp->pds_pdvlock);
	err = mpool_desc_pdmc_add(mp, 0, mp->pds_pdvcnt, NULL, true, devrpt);
	up_read(&mp->pds_pdvlock);
	if (err) {
		mp_pr_err("mpool %s, adding drive %s failed, can't place the drive in any media class",
			  err, mp->pds_name, dpath);
		goto errout;
	}


	mpool_generate_uuid(&pd->pdi_devid);

	/* write mpool superblock to drive */
	erase = true;
	err = mpool_dev_sbwrite(mp, pd, NULL);
	if (err) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "superblock write failed");
		goto errout;
	}

	/* Get percent spare */
	down_read(&mp->pds_pdvlock);
	err = mc_smap_parms_get(mp, pd->pdi_mclass, &mcsp);
	up_read(&mp->pds_pdvlock);
	if (ev(err))
		goto errout;

	/* alloc space map for drive */
	err = smap_drive_init(mp, &mcsp, mp->pds_pdvcnt);
	if (err) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "space map create for %s failed", dpath);
		goto errout;
	}
	smap = true;

	/*
	 * Take MDC0 compact lock to prevent race with MDC0 compaction.
	 * Take it across memory and media update.
	 */
	PMD_MDC0_COMPACTLOCK(mp);

	/*
	 * add drive state record to mdc0; if crash any time prior to adding
	 * this record the drive will not be recognized as an mpool member
	 * on next open
	 */
	err = pmd_prop_mcconfig(mp, pd, false);
	if (err) {
		PMD_MDC0_COMPACTUNLOCK(mp);

		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "device %s state to MDC0 failed", dpath);
		goto errout;
	}

	/* make new drive visible in mpool */
	down_write(&mp->pds_pdvlock);
	mp->pds_pdvcnt++;

	/*
	 * Add the PD in its class. That should NOT fail because we already
	 * checked that the drive can be added in a media class.
	 */
	err = mpool_desc_pdmc_add(mp, 0, mp->pds_pdvcnt - 1, NULL, false,
				  devrpt);
	if (ev(err))
		mp->pds_pdvcnt--;

	up_write(&mp->pds_pdvlock);
	PMD_MDC0_COMPACTUNLOCK(mp);

errout:
	if (err) {
		/* drive add failed; cleanup */

		/*
		 * No pd could have been be added at mp->pds_pdvcnt since we
		 * dropped pds_pdvlock because mpool_s_lock is held.
		 */
		if (smap)
			smap_drive_free(mp, mp->pds_pdvcnt);

		/*
		 * Erase the pd super blocks only if the pd doesn't already
		 * belong to this mpool or another one.
		 */
		if (erase)
			sb_erase(pd);

		pd_bio_dev_close(&pd->pdi_parm);
	}

	mutex_unlock(&mpool_s_lock);

	return err;
}

void mpool_mclass_get_cnt(struct mpool_descriptor *mp, u32 *cnt)
{
	int    i;

	*cnt = 0;
	down_read(&mp->pds_pdvlock);
	for (i = 0; i < MP_MED_NUMBER; i++) {
		struct media_class *mc;

		mc = &mp->pds_mc[i];
		if (mc->mc_pdmc >= 0)
			(*cnt)++;
	}
	up_read(&mp->pds_pdvlock);
}

merr_t
mpool_mclass_get(
	struct mpool_descriptor    *mp,
	u32                        *mcxc,
	struct mpool_mclass_xprops *mcxv)
{
	int    i, n;

	if (!mp || !mcxc || !mcxv)
		return merr(EINVAL);

	mutex_lock(&mpool_s_lock);
	down_read(&mp->pds_pdvlock);

	for (n = i = 0; i < MP_MED_NUMBER && n < *mcxc; i++) {
		struct media_class *mc;

		mc = &mp->pds_mc[i];
		if (mc->mc_pdmc < 0)
			continue;

		mcxv->mc_mclass = mc->mc_parms.mcp_classp;
		mcxv->mc_devtype = mc->mc_parms.mcp_devtype;
		mcxv->mc_spare = mc->mc_sparms.mcsp_spzone;

		mcxv->mc_zonepg = mc->mc_parms.mcp_zonepg;
		mcxv->mc_sectorsz = mc->mc_parms.mcp_sectorsz;
		mcxv->mc_features = mc->mc_parms.mcp_features;
		mcxv->mc_uacnt = mc->mc_uacnt;
		smap_mclass_usage(mp, i, &mcxv->mc_usage);

		++mcxv;
		++n;
	}

	up_read(&mp->pds_pdvlock);
	mutex_unlock(&mpool_s_lock);

	*mcxc = n;

	return 0;
}

merr_t
mpool_drive_spares(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclassp,
	u8                          drive_spares)
{
	struct media_class *mc;

	merr_t   err;

	if (!mclassp_valid(mclassp) || drive_spares > 100) {
		err = merr(EINVAL);
		mp_pr_err("mpool %s, setting percent %u spare for drives in media class %d failed",
			  err, mp->pds_name, drive_spares, mclassp);
		return err;
	}

	/*
	 * Do not write the spare record or try updating spare if there are
	 * no PDs in the specified media class.
	 */
	down_read(&mp->pds_pdvlock);
	mc = &mp->pds_mc[mclassp];
	up_read(&mp->pds_pdvlock);

	if (mc->mc_pdmc < 0) {
		err = merr(ENOENT);
		goto skip_update;
	}

	mutex_lock(&mpool_s_lock);

	/*
	 * Take mdc0 compact lock to prevent race with mdc0 compaction.
	 * Also make memory and media update to look atomic to compaction.
	 */
	PMD_MDC0_COMPACTLOCK(mp);

	/*
	 * update media class spare record in mdc0; no effect if crash before
	 * complete
	 */
	err = pmd_prop_mcspare(mp, mclassp, drive_spares, false);
	if (ev(err)) {
		mp_pr_err("mpool %s, setting percent %u spare for drives in media class %d failed, could not record in MDC0",
			  err, mp->pds_name, drive_spares, mclassp);
	} else {
		/* update spare zone accounting for media class */
		down_write(&mp->pds_pdvlock);

		err = mc_set_spzone(mp, mclassp, drive_spares);
		if (ev(err))
			mp_pr_err("mpool %s, setting percent %u spare for drives in media class %d failed",
				  err, mp->pds_name, drive_spares, mclassp);
		else
			/*
			 * smap accounting update always succeeds when
			 * mclassp/zone are valid
			 */
			smap_drive_spares(mp, mclassp, drive_spares);

		up_write(&mp->pds_pdvlock);
	}

	PMD_MDC0_COMPACTUNLOCK(mp);

	mutex_unlock(&mpool_s_lock);

skip_update:
	return err;
}

void
mpool_get_xprops(struct mpool_descriptor *mp, struct mpool_xprops *xprops)
{
	struct media_class *mc;

	int     mclassp, i;
	u16     ftmax;

	mutex_lock(&mpool_s_lock);
	down_read(&mp->pds_pdvlock);

	memcpy(xprops->ppx_params.mp_poolid.b, mp->pds_poolid.uuid,
	       MPOOL_UUID_SIZE);
	ftmax = 0;

	/* For now, we have maximum one class for a given mclassp.
	 */
	for (mclassp = 0; mclassp < MP_MED_NUMBER; mclassp++) {
		xprops->ppx_pd_mclassv[mclassp] = MP_MED_INVALID;

		mc = &mp->pds_mc[mclassp];
		if (mc->mc_pdmc < 0) {
			xprops->ppx_drive_spares[mclassp] = 0;
			xprops->ppx_uacnt[mclassp] = 0;

			xprops->ppx_params.mp_mblocksz[mclassp] = 0;
			continue;
		}

		xprops->ppx_drive_spares[mclassp] = mc->mc_sparms.mcsp_spzone;
		xprops->ppx_uacnt[mclassp] = mc->mc_uacnt;
		ftmax = max((u16)ftmax, (u16)(xprops->ppx_uacnt[mclassp]));
		if (mclassp == mp->pds_mdparm.md_mclass)
			xprops->ppx_mdparm.mdp_mclassp = mclassp;

		xprops->ppx_params.mp_mblocksz[mclassp] =
			(mc->mc_parms.mcp_zonepg << PAGE_SHIFT) >> 20;
	}

	for (i = 0; i < mp->pds_pdvcnt; ++i) {
		mc = &mp->pds_mc[mp->pds_pdv[i].pdi_mclass];
		if (mc->mc_pdmc < 0)
			continue;

		xprops->ppx_pd_mclassv[i] = mc->mc_parms.mcp_classp;

		strlcpy(xprops->ppx_pd_namev[i], mp->pds_pdv[i].pdi_name,
			sizeof(xprops->ppx_pd_namev[i]));
	}

	up_read(&mp->pds_pdvlock);
	mutex_unlock(&mpool_s_lock);

	xprops->ppx_params.mp_stat =
		ftmax ? MPOOL_STAT_FAULTED : MPOOL_STAT_OPTIMAL;
}


void mpool_get_props(struct mpool_descriptor *mp, struct mp_props *prop)
{
	struct mpool_xprops   xprops;

	memset(&xprops, 0, sizeof(xprops));
	mpool_get_xprops(mp, &xprops);
	*prop = xprops.ppx_params;
}

static void
fill_in_devprops(
	struct mpool_descriptor    *mp,
	u64                         pdh,
	struct mp_devprops         *dprop)
{
	merr_t			err;
	struct mpool_dev_info  *pd;
	struct media_class     *mc;

	pd = &mp->pds_pdv[pdh];
	memcpy(dprop->pdp_devid.b, pd->pdi_devid.uuid, MPOOL_UUID_SIZE);

	mc = &mp->pds_mc[pd->pdi_mclass];
	dprop->pdp_mclassp   = mc->mc_parms.mcp_classp;
	dprop->pdp_status    = mpool_pd_status_get(pd);
	dprop->pdp_state     = pd->pdi_state;

	err = smap_drive_usage(mp, pdh, dprop);
	if (err) {
		mp_pr_err("mpool %s, getting drive properties failed, can't get drive usage, media class %d",
			  err, mp->pds_name, dprop->pdp_mclassp);
	}
}

merr_t
mpool_get_devprops_by_name(
	struct mpool_descriptor    *mp,
	char                       *pdname,
	struct mp_devprops         *dprop)
{
	int    i;

	down_read(&mp->pds_pdvlock);

	for (i = 0; i < mp->pds_pdvcnt; i++) {
		if (!strcmp(pdname, mp->pds_pdv[i].pdi_name))
			fill_in_devprops(mp, i, dprop);
	}

	up_read(&mp->pds_pdvlock);

	return 0;
}

void
mpool_get_usage(
	struct mpool_descriptor    *mp,
	enum mp_media_classp        mclassp,
	struct mp_usage            *usage)
{
	memset(usage, 0, sizeof(*usage));

	down_read(&mp->pds_pdvlock);
	if (mclassp != MP_MED_ALL) {
		struct media_class *mc;

		assert(mclassp < MP_MED_NUMBER);
		mc = &mp->pds_mc[mclassp];
		if (mc->mc_pdmc < 0) {
			/* Not an error, this media class is empty. */
			up_read(&mp->pds_pdvlock);
			return;
		}
	}
	smap_mpool_usage(mp, mclassp, usage);
	up_read(&mp->pds_pdvlock);

	if (mclassp == MP_MED_ALL)
		pmd_mpool_usage(mp, usage);
}

/*
 * mpool internal functions
 */

static merr_t mpool_create_rmlogs(struct mpool_descriptor *mp, u64 mlog_cap)
{
	merr_t  err;
	u64     root_mlog_id[2];
	int     i;

	enum mp_media_classp    mclass;
	struct mlog_descriptor *ml_desc;
	struct mlog_props       mlprops;
	struct mlog_capacity    mlcap = {
		.lcp_captgt = mlog_cap,
	};

	mclass = MP_MED_CAPACITY;

	mlog_lookup_rootids(&root_mlog_id[0], &root_mlog_id[1]);

	for (i = 0; i < 2 ; i++) {

		err = mlog_find_get(mp, root_mlog_id[i], &mlprops, &ml_desc);

		if (!ev(err))
			continue;

		if (merr_errno(err) == ENOENT) { /* mlog doesn't exist */

			err = mlog_realloc(mp, root_mlog_id[i], &mlcap,
					   mclass, &mlprops, &ml_desc);
			if (err) {
				mp_pr_err("mpool %s, re-allocation of root mlog 0x%lx failed",
					  err, mp->pds_name,
					  (ulong)root_mlog_id[i]);
				return err;
			}

			if (mlprops.lpr_objid != root_mlog_id[i]) {
				err = ENOENT;
				mp_pr_err("mpool %s, allocation of root mlog mlog 0x%lx failed, inconsistent mlog id 0x%lx",
					  err, mp->pds_name,
					  (ulong)root_mlog_id[i],
					  (ulong)mlprops.lpr_objid);
				return err;
			}

			err = mlog_commit(mp, ml_desc);
			if (err) {
				(void)mlog_abort(mp, ml_desc);

				mp_pr_err("mpool %s, allocation of root mlog 0x%lx failed, commit failed",
					  err, mp->pds_name,
					  (ulong)root_mlog_id[i]);
				return err;
			}
		} else {
			mp_pr_err("mpool %s, alloc root mlog 0x%lx failed",
				  err, mp->pds_name, (ulong)root_mlog_id[i]);
			return err;
		}
	}

	return err;
}

void mpool_devrpt_init(struct mpool_devrpt *devrpt)
{
	if (!devrpt)
		return;

	devrpt->mdr_rcode = MPOOL_RC_NONE;
	devrpt->mdr_off = -1;
	devrpt->mdr_msg[0] = '\000';
}

void
mpool_devrpt(
	struct mpool_devrpt    *devrpt,
	enum mpool_rc           rcode,
	int                     off,
	const char             *fmt,
	...)
{
	va_list ap;

	if (!devrpt)
		return;

	devrpt->mdr_rcode = rcode;
	devrpt->mdr_off = off;

	if (fmt) {
		va_start(ap, fmt);
		vsnprintf(devrpt->mdr_msg, sizeof(devrpt->mdr_msg), fmt, ap);
		va_end(ap);
	}
}

static void linit_rwsem(void *mem)
{
	init_rwsem(mem);
}

struct mpool_descriptor *mpool_desc_alloc(void)
{
	struct mpool_descriptor    *mp;
	struct mpool_dev_info      *pd;
	struct uuid_to_idx_rb      *urb_elem;
	int                         i;

	mp = kzalloc(sizeof(*mp), GFP_KERNEL);
	if (!mp)
		return NULL;

	init_rwsem(&mp->pds_pdvlock);

	/* mp.pds_pdv[MPOOL_DRIVES_MAX] is a sentinel pointed at by all
	 * object layout strips representing consumed recon reservations.
	 */
	pd = &mp->pds_pdv[MPOOL_DRIVES_MAX];
	mpool_uuid_clear(&pd->pdi_devid);
	mpool_pd_status_set(pd, PD_STAT_UNAVAIL);
	pd->pdi_state = OMF_PD_DEFUNCT;

	urb_elem = kmem_cache_alloc(uuid_to_idx_rb_cache, GFP_KERNEL);
	if (!urb_elem) {
		kfree(mp);
		return NULL;
	}

	mp->pds_dev2pdh = RB_ROOT;
	urb_elem->uti_idx = MPOOL_DRIVES_MAX;
	mpool_uuid_clear(&urb_elem->uti_uuid);
	uuid_to_idx_insert(&mp->pds_dev2pdh, urb_elem);

	mutex_init(&mp->pds_omlock);
	mp->pds_oml = RB_ROOT;

	mp->pds_mdparm.md_mclass = MP_MED_INVALID;

	/* Allocate rw lock pool for ecio objects layouts.
	 */
	mp->pds_ecio_layout_rwl = numa_elmset_create(ECIO_RWL_PER_NODE,
		sizeof(struct rw_semaphore), linit_rwsem);
	if (!mp->pds_ecio_layout_rwl) {
		kmem_cache_free(uuid_to_idx_rb_cache, urb_elem);
		kfree(mp);
		return NULL;
	}

	mpcore_params_defaults(&mp->pds_params);

	for (i = 0; i < MP_MED_NUMBER; i++)
		mp->pds_mc[i].mc_pdmc = -1;

	return mp;
}

/*
 * remove mp from mpool_pools; close all dev; dealloc mp.
 */
void mpool_desc_free(struct mpool_descriptor *mp)
{
	struct mpool_descriptor    *found_mp = NULL;
	struct uuid_to_idx_rb      *found_ue = NULL;
	struct mpool_uuid           uuid_zero;
	int                         i;

	mpool_uuid_clear(&uuid_zero);

	/*
	 * handle case where poolid and devid not in mappings
	 * which can happen when cleaning up from failed create/open.
	 */
	found_mp = uuid_to_mpdesc_search(&mpool_pools, &mp->pds_poolid);
	if (found_mp)
		rb_erase(&found_mp->pds_node, &mpool_pools);

	found_ue = uuid_to_idx_search(&mp->pds_dev2pdh, &uuid_zero);
	if (found_ue) {
		rb_erase(&found_ue->uti_node, &mp->pds_dev2pdh);
		kmem_cache_free(uuid_to_idx_rb_cache, found_ue);
	}

	for (i = 0; i < mp->pds_pdvcnt; i++) {
		found_ue = uuid_to_idx_search(&mp->pds_dev2pdh,
					      &mp->pds_pdv[i].pdi_devid);
		if (found_ue) {
			rb_erase(&found_ue->uti_node, &mp->pds_dev2pdh);
			kmem_cache_free(uuid_to_idx_rb_cache, found_ue);
		}

		if (mp->pds_pdv[i].pdi_state != OMF_PD_DEFUNCT &&
		    mpool_pd_status_get(&mp->pds_pdv[i]) != PD_STAT_UNAVAIL)
			pd_bio_dev_close(&mp->pds_pdv[i].pdi_parm);
	}

	numa_elmset_destroy(mp->pds_ecio_layout_rwl);
	kfree(mp);
}

merr_t
mpool_sb_erase(
	int                   dcnt,
	char                **dpaths,
	struct pd_prop       *pd,
	struct mpool_devrpt  *devrpt)
{
	struct mpool_dev_info *pdv;
	merr_t                 err;
	int                    i;

	if (ev(!dpaths || !pd || !devrpt ||
		   dcnt < 1 || dcnt > MPOOL_DRIVES_MAX))
		return merr(EINVAL);

	pdv = kcalloc(MPOOL_DRIVES_MAX + 1, sizeof(*pdv), GFP_KERNEL);
	if (!pdv)
		return merr(ENOMEM);

	err = mpool_dev_init_all(pdv, dcnt, dpaths, devrpt, pd);
	if (ev(err))
		goto exit;

	for (i = 0; i < dcnt; i++) {
		err = sb_erase(&pdv[i]);
		if (err) {
			mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
				     "superblock erase of %s failed",
				     dpaths[i]);
			break;
		}
		pd_bio_dev_close(&pdv[i].pdi_parm);
	}
exit:
	kfree(pdv);

	return err;
}

merr_t
mpool_desc_unavail_add(
	struct mpool_descriptor        *mp,
	enum pd_state_omf               state,
	struct omf_devparm_descriptor  *omf_devparm)
{
	char                    uuid_str[40];
	merr_t                  err;
	struct mpool_dev_info  *pd = NULL;
	struct uuid_to_idx_rb  *urb_elem = NULL;

	mpool_unparse_uuid(&omf_devparm->odp_devid, uuid_str);

	mp_pr_warn("Activating mpool %s, adding unavailable drive %s",
		   mp->pds_name, uuid_str);

	if (mp->pds_pdvcnt >= MPOOL_DRIVES_MAX) {
		err = merr(EINVAL);
		mp_pr_err("Activating mpool %s, adding an unavailable drive, too many drives",
			  err, mp->pds_name);
		return err;
	}

	pd = &mp->pds_pdv[mp->pds_pdvcnt];

	mpool_uuid_copy(&pd->pdi_devid, &omf_devparm->odp_devid);

	/*
	 * Update the PD properties from the metadata record.
	 */

	mpool_pd_status_set(pd, PD_STAT_UNAVAIL);
	pd->pdi_state = state;

	pd_dev_set_unavail(&pd->pdi_parm, omf_devparm);

	/*
	 * Add the PD in its media class.
	 */
	err = mpool_desc_pdmc_add(mp, 0, mp->pds_pdvcnt, omf_devparm,
				  false, NULL);
	if (ev(err))
		return err;

	urb_elem = kmem_cache_alloc(uuid_to_idx_rb_cache, GFP_KERNEL);
	if (!urb_elem) {
		err = merr(ENOMEM);
		mp_pr_err("Activating mpool %s, can't allocate urb elem for unavailable drive",
			  err, mp->pds_name);
		return err;
	}

	urb_elem->uti_idx = mp->pds_pdvcnt;
	mpool_uuid_copy(&urb_elem->uti_uuid, &pd->pdi_devid);
	uuid_to_idx_insert(&mp->pds_dev2pdh, urb_elem);

	mp->pds_pdvcnt = mp->pds_pdvcnt + 1;

	return 0;
}

merr_t
mpool_sb_magic_check(
	char                   *dpath,
	struct pd_prop         *pd_prop,
	struct mpool_devrpt    *devrpt)
{
	struct mpool_dev_info *pd;
	merr_t                 err;
	int                    rval;

	if (ev(!dpath || !pd_prop || !devrpt))
		return merr(EINVAL);

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool dev info alloc failed");
		return merr(ENOMEM);
	}

	err = mpool_dev_init_all(pd, 1, &dpath, devrpt, pd_prop);
	if (ev(err)) {
		kfree(pd);
		return err;
	}

	/* confirm drive does not contain mpool magic value */
	rval = sb_magic_check(pd);
	if (rval < 0) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "superblock magic read from %s failed",
			     pd->pdi_name);
		err = merr(rval);
	} else if (rval > 0) {
		mpool_devrpt(devrpt, MPOOL_RC_MAGIC, 0, NULL);
		err = merr(EBUSY);
	}

	pd_bio_dev_close(&pd->pdi_parm);
	kfree(pd);

	return err;
}

merr_t
mpool_config_store(struct mpool_descriptor *mp, const struct mpool_config *cfg)
{
	merr_t err;

	if (ev(!mp || !cfg))
		return merr(EINVAL);

	mp->pds_cfg = *cfg;

	err = pmd_prop_mpconfig(mp, cfg, false);
	if (err)
		mp_pr_err("mpool %s, logging config record failed", err,
			  mp->pds_name);

	return err;
}

merr_t
mpool_config_fetch(struct mpool_descriptor *mp, struct mpool_config *cfg)
{
	if (ev(!mp || !cfg))
		return merr(EINVAL);

	*cfg = mp->pds_cfg;

	return 0;
}
