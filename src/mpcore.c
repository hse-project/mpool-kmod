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

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sort.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/rbtree.h>

#include "mpool_ioctl.h"

#include "mpool_printk.h"
#include "evc.h"
#include "assert.h"
#include "uuid.h"

#include "mp.h"
#include "omf.h"
#include "omf_if.h"
#include "pd.h"
#include "smap.h"
#include "mclass.h"
#include "pmd_obj.h"
#include "mpcore.h"
#include "sb.h"
#include "upgrade.h"

struct omf_devparm_descriptor;
struct mpool_descriptor;

/* Rbtree mapping mpool UUID to mpool descriptor node: uuid_to_mpdesc_rb */
struct rb_root mpool_pools = { NULL };

int uuid_to_mpdesc_insert(struct rb_root *root, struct mpool_descriptor *data)
{
	struct rb_node    **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct mpool_descriptor *this = rb_entry(*new, struct mpool_descriptor, pds_node);

		int result = mpool_uuid_compare(&data->pds_poolid, &this->pds_poolid);

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

static struct mpool_descriptor *
uuid_to_mpdesc_search(struct rb_root *root, struct mpool_uuid *key_uuid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct mpool_descriptor *data = rb_entry(node, struct mpool_descriptor, pds_node);

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

merr_t
mpool_dev_sbwrite(
	struct mpool_descriptor    *mp,
	struct mpool_dev_info      *pd,
	struct omf_sb_descriptor   *sbmdc0)
{
	merr_t                      err;
	struct omf_sb_descriptor   *sb = NULL;
	struct mc_parms		    mc_parms;

	if (mpool_pd_status_get(pd) != PD_STAT_ONLINE) {
		err = merr(EIO);
		mp_pr_err("%s:%s unavailable or offline, status %d",
			  err, mp->pds_name, pd->pdi_name, mpool_pd_status_get(pd));
		return err;
	}

	sb = kzalloc(sizeof(struct omf_sb_descriptor), GFP_KERNEL);
	if (!sb) {
		err = merr(ENOMEM);
		mp_pr_err("mpool %s, writing superblock on drive %s, alloc of superblock descriptor failed %lu",
			  err, mp->pds_name, pd->pdi_name, sizeof(struct omf_sb_descriptor));
		return err;
	}

	/*
	 * Set superblock values common to all new drives in pool
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

	if (sbmdc0)
		sbutil_mdc0_copy(sb, sbmdc0);
	else
		sbutil_mdc0_clear(sb);

	err = sb_write_new(&pd->pdi_parm, sb);
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
 *
 * In the context of a mpool create, allocate space for the two MDC0 mlogs
 *	and update the sb structure with the position of MDC0.
 *
 * Note: this function assumes that the media classes have already been
 *	created.
 */
static merr_t mpool_mdc0_alloc(struct mpool_descriptor *mp, struct omf_sb_descriptor *sb)
{
	struct mpool_dev_info  *pd;
	struct media_class     *mc;
	struct mpool_uuid       uuid;
	merr_t                  err;
	u64                     zcnt;
	u64                     zonelen;
	u32                     cnt;

	sbutil_mdc0_clear(sb);

	assert(mp->pds_mdparm.md_mclass < MP_MED_NUMBER);
	mc = &mp->pds_mc[mp->pds_mdparm.md_mclass];
	if (mc->mc_pdmc < 0) {
		err = merr(ENOSPC);
		mp_pr_err("%s: sb update memory image MDC0 information, not enough drives",
			  err, mp->pds_name);
		return err;
	}

	pd = &mp->pds_pdv[mc->mc_pdmc];

	zonelen = (u64)pd->pdi_parm.dpr_zonepg << PAGE_SHIFT;
	zcnt = 1 + ((mp->pds_params.mp_mdc0cap - 1) / zonelen);

	cnt = sb_zones_for_sbs(&(pd->pdi_prop));
	if (cnt < 1) {
		err = merr(EINVAL);
		mp_pr_err("%s: sb MDC0, getting sb range failed for drive %s %u",
			  err, mp->pds_name, pd->pdi_name, cnt);
		return err;
	}

	if ((pd->pdi_zonetot - cnt) < zcnt * 2) {
		err = merr(ENOSPC);
		mp_pr_err("%s: sb MDC0, no room for MDC0 on drive %s %lu %u %lu",
			  err, mp->pds_name, pd->pdi_name,
			  (ulong)pd->pdi_zonetot, cnt, (ulong)zcnt);
		return err;
	}

	/*
	 * mdc0 log1/2 alloced on first 2 * zcnt zone's
	 */
	err = pd_zone_erase(&pd->pdi_parm, cnt, zcnt * 2, true);
	if (err) {
		mp_pr_err("%s: sb MDC0, erase failed on %s %u %lu",
			  err, mp->pds_name, pd->pdi_name, cnt, (ulong)zcnt);
		return err;
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

	return 0;
}

merr_t mpool_dev_sbwrite_newpool(struct mpool_descriptor *mp, struct omf_sb_descriptor *sbmdc0)
{
	merr_t                  err;
	u64                     pdh = 0;
	struct mpool_dev_info  *pd = NULL;

	/* Alloc mdc0 and generate mdc0 info for superblocks */
	err = mpool_mdc0_alloc(mp, sbmdc0);
	if (err) {
		mp_pr_err("%s: MDC0 allocation failed", err, mp->pds_name);
		return err;
	}

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		pd = &mp->pds_pdv[pdh];

		if (pd->pdi_mclass == mp->pds_mdparm.md_mclass)
			err = mpool_dev_sbwrite(mp, pd, sbmdc0);
		else
			err = mpool_dev_sbwrite(mp, pd, NULL);
		if (err) {
			mp_pr_err("%s: sb write %s failed, %d %d", err, mp->pds_name,
				  pd->pdi_name, pd->pdi_mclass, mp->pds_mdparm.md_mclass);
			break;
		}
	}

	return err;
}

merr_t
mpool_mdc0_sb2obj(
	struct mpool_descriptor    *mp,
	struct omf_sb_descriptor   *sb,
	struct pmd_layout         **l1,
	struct pmd_layout         **l2)
{
	merr_t err;
	int    i;

	/* MDC0 mlog1 layout */
	*l1 = pmd_layout_alloc(&sb->osb_mdc01uuid, MDC0_OBJID_LOG1, sb->osb_mdc01gen, 0,
			       sb->osb_mdc01desc.ol_zcnt);
	if (!*l1) {
		*l1 = *l2 = NULL;

		err = merr(ENOMEM);
		mp_pr_err("mpool %s, MDC0 mlog1 allocation failed", err, mp->pds_name);
		return err;
	}

	(*l1)->eld_state = PMD_LYT_COMMITTED;

	for (i = 0; i < mp->pds_pdvcnt; i++) {
		if (mpool_uuid_compare(&mp->pds_pdv[i].pdi_devid, &sb->osb_mdc01devid) == 0) {
			(*l1)->eld_ld.ol_pdh = i;
			(*l1)->eld_ld.ol_zaddr = sb->osb_mdc01desc.ol_zaddr;
			break;
		}
	}

	if (i >= mp->pds_pdvcnt) {
		char uuid_str[40];

		/* Should never happen */
		pmd_obj_put(*l1);
		*l1 = *l2 = NULL;

		mpool_unparse_uuid(&sb->osb_mdc01devid, uuid_str);
		err = merr(ENOENT);
		mp_pr_err("mpool %s, allocating MDC0 mlog1, can't find handle for pd uuid %s,",
			  err, mp->pds_name, uuid_str);

		return err;
	}

	/* MDC0 mlog2 layout */
	*l2 = pmd_layout_alloc(&sb->osb_mdc02uuid, MDC0_OBJID_LOG2, sb->osb_mdc02gen, 0,
			       sb->osb_mdc02desc.ol_zcnt);
	if (!*l2) {
		pmd_obj_put(*l1);

		*l1 = *l2 = NULL;

		err = merr(ENOMEM);
		mp_pr_err("mpool %s, MDC0 mlog2 allocation failed", err, mp->pds_name);
		return err;
	}

	(*l2)->eld_state = PMD_LYT_COMMITTED;

	for (i = 0; i < mp->pds_pdvcnt; i++) {
		if (mpool_uuid_compare(&mp->pds_pdv[i].pdi_devid, &sb->osb_mdc02devid) == 0) {
			(*l2)->eld_ld.ol_pdh = i;
			(*l2)->eld_ld.ol_zaddr = sb->osb_mdc02desc.ol_zaddr;
			break;
		}
	}

	if (i >= mp->pds_pdvcnt) {
		char uuid_str[40];

		/* Should never happen */
		pmd_obj_put(*l1);
		pmd_obj_put(*l2);
		*l1 = *l2 = NULL;

		mpool_unparse_uuid(&sb->osb_mdc02devid, uuid_str);
		err = merr(ENOENT);
		mp_pr_err("mpool %s, allocating MDC0 mlog2, can't find handle for pd uuid %s",
			  err, mp->pds_name, uuid_str);

		return err;
	}

	return 0;
}

/**
 * mpool_dev_check_new() - check if a drive is ready to be added in an mpool.
 * @mp:
 * @pd:
 */
merr_t mpool_dev_check_new(struct mpool_descriptor *mp, struct mpool_dev_info *pd)
{
	int     rval;
	merr_t  err;

	if (mpool_pd_status_get(pd) != PD_STAT_ONLINE) {
		err = merr(EIO);
		mp_pr_err("%s:%s unavailable or offline, status %d",
			  err, mp->pds_name, pd->pdi_name, mpool_pd_status_get(pd));
		return err;
	}

	/* Confirm drive does not contain mpool magic value */
	rval = sb_magic_check(&pd->pdi_parm);
	if (rval) {
		if (rval < 0) {
			err = merr(rval);
			mp_pr_err("%s:%s read sb magic failed", err, mp->pds_name, pd->pdi_name);
			return err;
		}

		err = merr(EBUSY);
		mp_pr_err("%s:%s sb magic already exists", err, mp->pds_name, pd->pdi_name);
		return err;
	}

	return 0;
}

merr_t
mpool_desc_pdmc_add(
	struct mpool_descriptor	       *mp,
	u16                             pdh,
	struct omf_devparm_descriptor  *omf_devparm,
	bool                            check_only)
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

	if (!mclass_isvalid(mc_parms.mcp_classp)) {
		err = merr(EINVAL);
		mp_pr_err("%s: media class %u of %s is undefined",  err, mp->pds_name,
			  mc_parms.mcp_classp, pd->pdi_name);
		return err;
	}

	/*
	 * Devices that do not support updatable sectors can't be included
	 * in an mpool. Do not check if in the context of an unavailable PD
	 * during activate, because it is impossible to determine the PD
	 * properties.
	 */
	if ((omf_devparm == NULL) && !(pd->pdi_cmdopt & PD_CMD_SECTOR_UPDATABLE)) {
		err = merr(EINVAL);
		mp_pr_err("%s: device %s sectors not updatable", err, mp->pds_name, pd->pdi_name);
		return err;
	}

	mc = &mp->pds_mc[mc_parms.mcp_classp];
	if (mc->mc_pdmc < 0) {
		struct mc_smap_parms   mcsp;
		/*
		 * No media class corresponding to the PD class yet, create one.
		 */
		err = mc_smap_parms_get(&mp->pds_mc[mc_parms.mcp_classp], &mp->pds_params, &mcsp);
		if (ev(err))
			return err;

		if (!check_only)
			mc_init_class(mc, &mc_parms, &mcsp);
	} else {
		err = merr(EINVAL);
		mp_pr_err("%s: add %s, only 1 device allowed per media class",
			  err, mp->pds_name, pd->pdi_name);
		return err;
	}

	if (check_only)
		return 0;

	mc->mc_pdmc = pdh;

	return 0;
}

/**
 * mpool_desc_init_newpool() -
 * @mp:
 * @flags: enum mp_mgmt_flags
 *
 * Called on mpool create.
 * Create the media classes and add all the mpool PDs in their media class.
 * Update the metadata media class in mp->pds_mdparm
 *
 * Note: the PD properties (pd->pdi_parm.dpr_prop) must be updated
 * and correct when entering this function.
 */
merr_t mpool_desc_init_newpool(struct mpool_descriptor *mp, u32 flags)
{
	u64    pdh = 0;
	merr_t err;

	if (!(flags & (1 << MP_FLAGS_FORCE))) {
		err = mpool_dev_check_new(mp, &mp->pds_pdv[pdh]);
		if (ev(err))
			return err;
	}

	/*
	 * Add drive in its media class. That may create the class
	 * if first drive of the class.
	 */
	err = mpool_desc_pdmc_add(mp, pdh, NULL, false);
	if (err) {
		struct mpool_dev_info  *pd __maybe_unused;

		pd = &mp->pds_pdv[pdh];

		mp_pr_err("mpool %s, mpool desc init, adding drive %s in a media class failed",
			  err, mp->pds_name, pd->pdi_name);
		return err;
	}

	mp->pds_mdparm.md_mclass = mp->pds_pdv[pdh].pdi_mclass;

	return 0;
}

merr_t
mpool_dev_init_all(
	struct mpool_dev_info  *pdv,
	u64                     dcnt,
	char                  **dpaths,
	struct pd_prop	       *pd_prop)
{
	merr_t      err = 0;
	int         idx;
	char       *pdname;

	if (dcnt == 0)
		return merr(EINVAL);

	for (idx = 0; idx < dcnt; idx++, pd_prop++) {
		err = pd_dev_open(dpaths[idx], &pdv[idx].pdi_parm, pd_prop);
		if (err) {
			mp_pr_err("opening device %s failed", err, dpaths[idx]);
			break;
		}

		pdname = strrchr(dpaths[idx], '/');
		pdname = pdname ? pdname + 1 : dpaths[idx];
		strlcpy(pdv[idx].pdi_name, pdname, sizeof(pdv[idx].pdi_name));

		mpool_pd_status_set(&pdv[idx], PD_STAT_ONLINE);
	}

	while (err && idx-- > 0)
		pd_dev_close(&pdv[idx].pdi_parm);

	return err;
}

void mpool_mdc_cap_init(struct mpool_descriptor *mp, struct mpool_dev_info *pd)
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

/**
 * mpool_desc_init_sb() -
 * @mp:
 * @sbmdc0: output. MDC0 information stored in the super blocks.
 * @flags:
 * Read the super blocks of the PDs.
 * Adjust the discovered PD properties stored in pd->pdi_parm.dpr_prop with
 * PD parameters from the super block. Some of discovered PD properties are
 * default (like zone size) and need to be adjusted to what the PD actually
 * use.
 */
merr_t
mpool_desc_init_sb(
	struct mpool_descriptor    *mp,
	struct omf_sb_descriptor   *sbmdc0,
	u32                         flags,
	bool                       *mc_resize)
{
	struct omf_sb_descriptor   *sb = NULL;
	struct mpool_dev_info      *pd = NULL;

	merr_t err;
	u16    omf_ver = OMF_SB_DESC_UNDEF;
	u8     pdh = 0;
	bool   mdc0found = false;
	bool   force = ((flags & (1 << MP_FLAGS_FORCE)) != 0);

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	if (!sb) {
		err = merr(ENOMEM);
		mp_pr_err("sb desc alloc failed %lu", err, (ulong)sizeof(*sb));
		return err;
	}

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		struct omf_devparm_descriptor  *dparm;

		bool   resize = false;
		int    i;

		pd = &mp->pds_pdv[pdh];
		if (mpool_pd_status_get(pd) != PD_STAT_ONLINE) {
			err = merr(EIO);
			mp_pr_err("pd %s unavailable or offline, status %d",
				  err, pd->pdi_name, mpool_pd_status_get(pd));
			kfree(sb);
			return err;
		}

		/*
		 * Read superblock; init and validate pool drive info
		 * from device parameters stored in the super block.
		 */
		err = sb_read(&pd->pdi_parm, sb, &omf_ver, force);
		if (ev(err)) {
			mp_pr_err("sb read from %s failed", err, pd->pdi_name);
			kfree(sb);
			return err;
		}

		if (!pdh) {
			size_t n __maybe_unused;

			/*
			 * First drive; confirm pool not open; set pool-wide
			 * properties
			 */
			if (uuid_to_mpdesc_search(&mpool_pools, &sb->osb_poolid)) {
				char *uuid_str;

				uuid_str = kmalloc(MPOOL_UUID_STRING_LEN + 1, GFP_KERNEL);
				if (uuid_str)
					mpool_unparse_uuid(&sb->osb_poolid, uuid_str);

				err = merr(EBUSY);
				mp_pr_err("%s: mpool already activated, id %s, pd name %s",
					  err, sb->osb_name, uuid_str, pd->pdi_name);
				kfree(sb);
				kfree(uuid_str);
				return err;
			}
			mpool_uuid_copy(&mp->pds_poolid, &sb->osb_poolid);

			n = strlcpy(mp->pds_name, (char *)sb->osb_name, sizeof(mp->pds_name));
			assert(n < sizeof(mp->pds_name));
		} else {
			/* Second or later drive; validate pool-wide properties */
			if (mpool_uuid_compare(&sb->osb_poolid, &mp->pds_poolid) != 0) {
				char *uuid_str1, *uuid_str2 = NULL;

				uuid_str1 = kmalloc(2 * (MPOOL_UUID_STRING_LEN + 1), GFP_KERNEL);
				if (uuid_str1) {
					uuid_str2 = uuid_str1 + MPOOL_UUID_STRING_LEN + 1;
					mpool_unparse_uuid(&sb->osb_poolid, uuid_str1);
					mpool_unparse_uuid(&mp->pds_poolid, uuid_str2);
				}

				err = merr(EINVAL);
				mp_pr_err("%s: pd %s, mpool id %s different from prior id %s",
					  err, mp->pds_name, pd->pdi_name, uuid_str1, uuid_str2);
				kfree(sb);
				kfree(uuid_str1);
				return err;
			}
		}

		dparm = &sb->osb_parm;
		if (!force && pd->pdi_devsz > dparm->odp_devsz) {
			mp_pr_info("%s: pd %s, discovered size %lu > on-media size %lu",
				mp->pds_name, pd->pdi_name,
				(ulong)pd->pdi_devsz, (ulong)dparm->odp_devsz);

			if ((flags & (1 << MP_FLAGS_RESIZE)) == 0) {
				pd->pdi_devsz = dparm->odp_devsz;
			} else {
				dparm->odp_devsz  = pd->pdi_devsz;
				dparm->odp_zonetot = pd->pdi_devsz / (pd->pdi_zonepg << PAGE_SHIFT);

				pd->pdi_zonetot = dparm->odp_zonetot;
				resize = true;
			}
		}

		/* Validate mdc0 info in superblock if present */
		if (!sbutil_mdc0_isclear(sb)) {
			if (!force && !sbutil_mdc0_isvalid(sb)) {
				err = merr(EINVAL);
				mp_pr_err("%s: pd %s, invalid sb MDC0",
					  err, mp->pds_name, pd->pdi_name);
				kfree(sb);
				return err;
			}

			dparm = &sb->osb_mdc0dev;
			if (resize) {
				assert(pd->pdi_devsz > dparm->odp_devsz);

				dparm->odp_devsz = pd->pdi_devsz;
				dparm->odp_zonetot = pd->pdi_devsz / (pd->pdi_zonepg << PAGE_SHIFT);
			}

			sbutil_mdc0_copy(sbmdc0, sb);
			mdc0found = true;
		}

		/* Set drive info confirming devid is unique and zone parms match */
		for (i = 0; i < pdh; i++) {
			if (mpool_uuid_compare(&mp->pds_pdv[i].pdi_devid,
					       &sb->osb_parm.odp_devid) == 0) {
				char *uuid_str;

				uuid_str = kmalloc(MPOOL_UUID_STRING_LEN + 1, GFP_KERNEL);
				if (uuid_str)
					mpool_unparse_uuid(&sb->osb_parm.odp_devid, uuid_str);
				err = merr(EINVAL);
				mp_pr_err("%s: pd %s, duplicate devices, uuid %s",
					  err, mp->pds_name, pd->pdi_name, uuid_str);
				kfree(sb);
				kfree(uuid_str);
				return err;
			}
		}

		if (omf_ver > OMF_SB_DESC_VER_LAST) {
			err = merr(EOPNOTSUPP);
			mp_pr_err("%s: unsupported sb version %d", err, mp->pds_name, omf_ver);
			kfree(sb);
			return err;
		} else if (!force && (omf_ver < OMF_SB_DESC_VER_LAST || resize)) {
			if ((flags & (1 << MP_FLAGS_PERMIT_META_CONV)) == 0) {
				char *buf1;
				char *buf2 = NULL;
				struct omf_mdcver  *mdcver;

				/*
				 * We have to get the permission from users
				 * to update mpool meta data
				 */
				mdcver = omf_sbver_to_mdcver(omf_ver);
				assert(mdcver != NULL);

				buf1 = kmalloc(2 * MAX_MDCVERSTR, GFP_KERNEL);
				if (buf1) {
					buf2 = buf1 + MAX_MDCVERSTR;
					omfu_mdcver_to_str(mdcver, buf1, sizeof(buf1));
					omfu_mdcver_to_str(omfu_mdcver_cur(), buf2, sizeof(buf2));
				}

				err = merr(EPERM);
				mp_pr_err("%s: reqd sb upgrade from version %s (%s) to %s (%s)",
					  err, mp->pds_name,
					  buf1, omfu_mdcver_comment(mdcver) ?: "",
					  buf2, omfu_mdcver_comment(omfu_mdcver_cur()));
				kfree(sb);
				kfree(buf1);
				return err;
			}

			/* We need to overwrite the old version superblock on the device */
			err = sb_write_update(&pd->pdi_parm, sb);
			if (err) {
				mp_pr_err("%s: pd %s, failed to convert or overwrite mpool sb",
					  err, mp->pds_name, pd->pdi_name);
				kfree(sb);
				return err;
			}

			if (!resize)
				mp_pr_info("%s: pd %s, Convert mpool sb, oldv %d newv %d",
					   mp->pds_name, pd->pdi_name, omf_ver, sb->osb_vers);
		}

		mpool_uuid_copy(&pd->pdi_devid, &sb->osb_parm.odp_devid);

		/* Add drive in its media class. Create the media class if not yet created. */
		err = mpool_desc_pdmc_add(mp, pdh, NULL, false);
		if (err) {
			mp_pr_err("%s: pd %s, adding drive in a media class failed",
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
		err = merr(EINVAL);
		mp_pr_err("%s: MDC0 not found", err, mp->pds_name);
		kfree(sb);
		return err;
	}

	kfree(sb);

	return 0;
}

static int comp_func(const void *c1, const void *c2)
{
	return strcmp(*(char **)c1, *(char **)c2);
}

merr_t check_for_dups(char **listv, int cnt, int *dup, int *offset)
{
	const char **sortedv;
	const char  *prev;
	int          i;
	merr_t       err;

	*dup = 0;
	*offset = -1;

	if (0 == cnt || 1 == cnt)
		return 0;

	sortedv = kcalloc(cnt + 1, sizeof(char *), GFP_KERNEL);
	if (!sortedv) {
		err = merr(ENOMEM);
		mp_pr_err("kcalloc failed for %d paths, first path %s", err, cnt, *listv);
		return err;
	}

	/* Make a shallow copy */
	for (i = 0; i < cnt; i++)
		sortedv[i] = listv[i];

	sortedv[i] = NULL;

	sort(sortedv, cnt, sizeof(char *), comp_func, NULL);

	prev = sortedv[0];
	for (i = 1; i < cnt; i++) {
		if (strcmp(sortedv[i], prev) == 0) {
			mp_pr_info("path %s is duplicated", prev);
			*dup = 1;
			break;
		}

		prev = sortedv[i];
	}

	/* Find offset, prev points to first dup */
	if (*dup) {
		for (i = 0; i < cnt; i++) {
			if (prev == listv[i]) {
				*offset = i;
				break;
			}
		}
	}

	kfree(sortedv);
	return 0;
}

void fill_in_devprops(struct mpool_descriptor *mp, u64 pdh, struct mpool_devprops *dprop)
{
	merr_t			err;
	struct mpool_dev_info  *pd;
	struct media_class     *mc;

	pd = &mp->pds_pdv[pdh];
	memcpy(dprop->pdp_devid.b, pd->pdi_devid.uuid, MPOOL_UUID_SIZE);

	mc = &mp->pds_mc[pd->pdi_mclass];
	dprop->pdp_mclassp = mc->mc_parms.mcp_classp;
	dprop->pdp_status  = mpool_pd_status_get(pd);

	err = smap_drive_usage(mp, pdh, dprop);
	if (err) {
		mp_pr_err("mpool %s, can't get drive usage, media class %d",
			  err, mp->pds_name, dprop->pdp_mclassp);
	}
}

merr_t
mpool_desc_unavail_add(struct mpool_descriptor *mp, struct omf_devparm_descriptor *omf_devparm)
{
	char                    uuid_str[40];
	merr_t                  err;
	struct mpool_dev_info  *pd = NULL;

	mpool_unparse_uuid(&omf_devparm->odp_devid, uuid_str);

	mp_pr_warn("Activating mpool %s, adding unavailable drive %s", mp->pds_name, uuid_str);

	if (mp->pds_pdvcnt >= MPOOL_DRIVES_MAX) {
		err = merr(EINVAL);
		mp_pr_err("Activating mpool %s, adding an unavailable drive, too many drives",
			  err, mp->pds_name);
		return err;
	}

	pd = &mp->pds_pdv[mp->pds_pdvcnt];

	mpool_uuid_copy(&pd->pdi_devid, &omf_devparm->odp_devid);

	/* Update the PD properties from the metadata record. */
	mpool_pd_status_set(pd, PD_STAT_UNAVAIL);
	pd_dev_set_unavail(&pd->pdi_parm, omf_devparm);

	/* Add the PD in its media class. */
	err = mpool_desc_pdmc_add(mp, mp->pds_pdvcnt, omf_devparm, false);
	if (ev(err))
		return err;

	mp->pds_pdvcnt = mp->pds_pdvcnt + 1;

	return 0;
}

merr_t mpool_create_rmlogs(struct mpool_descriptor *mp, u64 mlog_cap)
{
	struct mlog_descriptor *ml_desc;
	struct mlog_props       mlprops;
	struct mlog_capacity    mlcap = {
		.lcp_captgt = mlog_cap,
	};

	u64     root_mlog_id[2];
	merr_t  err;
	int     i;

	mlog_lookup_rootids(&root_mlog_id[0], &root_mlog_id[1]);

	for (i = 0; i < 2; ++i) {
		err = mlog_find_get(mp, root_mlog_id[i], 1, NULL, &ml_desc);
		if (!err) {
			mlog_put(ml_desc);
			continue;
		}

		if (merr_errno(err) != ENOENT) {
			mp_pr_err("mpool %s, root mlog find 0x%lx failed",
				  err, mp->pds_name, (ulong)root_mlog_id[i]);
			return err;
		}

		err = mlog_realloc(mp, root_mlog_id[i], &mlcap,
				   MP_MED_CAPACITY, &mlprops, &ml_desc);
		if (err) {
			mp_pr_err("mpool %s, root mlog realloc 0x%lx failed",
				  err, mp->pds_name, (ulong)root_mlog_id[i]);
			return err;
		}

		if (mlprops.lpr_objid != root_mlog_id[i]) {
			mlog_put(ml_desc);
			err = ENOENT;
			mp_pr_err("mpool %s, root mlog mismatch 0x%lx 0x%lx", err,
				  mp->pds_name, (ulong)root_mlog_id[i], (ulong)mlprops.lpr_objid);
			return err;
		}

		err = mlog_commit(mp, ml_desc);
		if (err) {
			if (mlog_abort(mp, ml_desc))
				mlog_put(ml_desc);

			mp_pr_err("mpool %s, root mlog commit 0x%lx failed",
				  err, mp->pds_name, (ulong)root_mlog_id[i]);
			return err;
		}

		mlog_put(ml_desc);
	}

	return err;
}

struct mpool_descriptor *mpool_desc_alloc(void)
{
	struct mpool_descriptor    *mp;
	int                         i;

	mp = kzalloc(sizeof(*mp), GFP_KERNEL);
	if (!mp)
		return NULL;

	init_rwsem(&mp->pds_pdvlock);

	mutex_init(&mp->pds_oml_lock);
	mp->pds_oml_root = RB_ROOT;

	mp->pds_mdparm.md_mclass = MP_MED_INVALID;

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
	struct mpool_uuid           uuid_zero;
	int                         i;

	mpool_uuid_clear(&uuid_zero);

	/*
	 * Handle case where poolid and devid not in mappings
	 * which can happen when cleaning up from failed create/open.
	 */
	found_mp = uuid_to_mpdesc_search(&mpool_pools, &mp->pds_poolid);
	if (found_mp)
		rb_erase(&found_mp->pds_node, &mpool_pools);

	for (i = 0; i < mp->pds_pdvcnt; i++) {
		if (mpool_pd_status_get(&mp->pds_pdv[i]) != PD_STAT_UNAVAIL)
			pd_dev_close(&mp->pds_pdv[i].pdi_parm);
	}

	kfree(mp);
}
