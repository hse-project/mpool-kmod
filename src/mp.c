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
#include <linux/mutex.h>
#include <crypto/hash.h>

#include "assert.h"
#include "mpool_printk.h"

#include "sb.h"
#include "upgrade.h"
#include "mpcore.h"
#include "mp.h"

/*
 * Lock for serializing certain mpool ops where required/desirable; could be per
 * mpool in some cases but no meaningful performance benefit for these rare ops;
 * also protects mpool_pools and certain mpool_descriptor fields.
 */
static DEFINE_MUTEX(mpool_s_lock);

int mpool_create(const char *mpname, u32 flags, char **dpaths, struct pd_prop *pd_prop,
		 struct mpcore_params *params, u64 mlog_cap)
{
	struct omf_sb_descriptor *sbmdc0;
	struct mpool_descriptor *mp;
	struct pmd_layout *mdc01, *mdc02;
	bool active, sbvalid;
	u16 sidx;
	int err;

	if (!mpname || !*mpname || !dpaths || !pd_prop)
		return -EINVAL;

	mdc01 = mdc02 = NULL;
	active = sbvalid = false;

	mp = mpool_desc_alloc();
	if (!mp) {
		err = -ENOMEM;
		mp_pr_err("mpool %s, alloc desc failed", err, mpname);
		return err;
	}

	sbmdc0 = &(mp->pds_sbmdc0);
	strlcpy((char *)mp->pds_name, mpname, sizeof(mp->pds_name));
	mpool_generate_uuid(&mp->pds_poolid);

	if (params)
		mp->pds_params = *params;

	mp->pds_pdvcnt = 0;

	mutex_lock(&mpool_s_lock);

	/*
	 * Allocate the per-mpool workqueue.
	 * TODO: Make this per-driver
	 */
	mp->pds_erase_wq = alloc_workqueue("mperasewq", WQ_HIGHPRI, 0);
	if (!mp->pds_erase_wq) {
		err = -ENOMEM;
		mp_pr_err("mpool %s, alloc per-mpool wq failed", err, mpname);
		goto errout;
	}

	/*
	 * Set the devices parameters from the ones placed by the discovery
	 * in pd_prop.
	 */
	err = mpool_dev_init_all(mp->pds_pdv, 1, dpaths, pd_prop);
	if (err) {
		mp_pr_err("mpool %s, failed to get device parameters", err, mpname);
		goto errout;
	}

	mp->pds_pdvcnt = 1;

	mpool_mdc_cap_init(mp, &mp->pds_pdv[0]);

	/* Init new pool drives uuid and mclassp */
	mpool_generate_uuid(&mp->pds_pdv[0].pdi_devid);

	/*
	 * Init mpool descriptor from new drive info.
	 * Creates the media classes and place the PDs in them.
	 * Determine the media class used for the metadata.
	 */
	err = mpool_desc_init_newpool(mp, flags);
	if (err) {
		mp_pr_err("mpool %s, desc init from new drive info failed", err, mpname);
		goto errout;
	}

	/*
	 * Alloc empty mdc0 and write superblocks to all drives; if
	 * crash drives with superblocks will not be recognized as mpool
	 * members because there are not yet any drive state records in mdc0
	 */
	sbvalid = true;
	err = mpool_dev_sbwrite_newpool(mp, sbmdc0);
	if (err) {
		mp_pr_err("mpool %s, couldn't write superblocks", err, mpname);
		goto errout;
	}

	/* Alloc mdc0 mlog layouts and activate mpool with empty mdc0 */
	err = mpool_mdc0_sb2obj(mp, sbmdc0, &mdc01, &mdc02);
	if (err) {
		mp_pr_err("mpool %s, alloc of MDC0 mlogs failed", err, mpname);
		goto errout;
	}

	err = pmd_mpool_activate(mp, mdc01, mdc02, 1);
	if (err) {
		mp_pr_err("mpool %s, activation failed", err, mpname);
		goto errout;
	}

	active = true;

	/*
	 * Add the version record (always first record) in MDC0.
	 * The version record is used only from version 1.0.0.1.
	 */
	if (omfu_mdcver_cmp2(omfu_mdcver_cur(), ">=", 1, 0, 0, 1)) {
		err = pmd_mdc_addrec_version(mp, 0);
		if (err) {
			mp_pr_err("mpool %s, writing MDC version record in MDC0 failed",
				  err, mpname);
			goto errout;
		}
	}

	/*
	 * Add drive state records to mdc0; if crash before complete will
	 * detect if attempt to open same drive list; it may be possible to
	 * open the subset of the drive list for which state records were
	 * written without detection, in which case the other drives can be
	 * added
	 */
	err = pmd_prop_mcconfig(mp, &mp->pds_pdv[0], false);
	if (err) {
		mp_pr_err("mpool %s, add drive state to MDC0 failed", err, mpname);
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
				  mpname, sidx - 1, (ulong)mp->pds_params.mp_mdcnum);
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
			mp_pr_info("mpool %s, root mlog creation failed", mpname);
			/*
			 * If root mlog creation fails, mask the error and
			 * proceed with create. root mlogs will be re-created
			 * during activate.
			 */
			err = 0;
		}
	}

	/* Add mp to the list of all open mpools */
	uuid_to_mpdesc_insert(&mpool_pools, mp);

errout:

	if (mp->pds_erase_wq)
		destroy_workqueue(mp->pds_erase_wq);

	if (active)
		pmd_mpool_deactivate(mp);

	if (err && sbvalid) {
		struct mpool_dev_info *pd;
		int err1;

		/* Erase super blocks on the drives */
		pd = &mp->pds_pdv[0];
		if (mpool_pd_status_get(pd) != PD_STAT_ONLINE) {
			err1 = -EIO;
			mp_pr_err("%s:%s unavailable or offline, status %d",
				  err1, mp->pds_name, pd->pdi_name, mpool_pd_status_get(pd));
		} else {
			err1 = sb_erase(&pd->pdi_parm);
			if (err1)
				mp_pr_info("%s: cleanup, sb erase failed on device %s",
					   mp->pds_name, pd->pdi_name);
		}
	}

	mpool_desc_free(mp);

	mutex_unlock(&mpool_s_lock);

	return err;
}

int mpool_activate(u64 dcnt, char **dpaths, struct pd_prop *pd_prop, u64 mlog_cap,
		   struct mpcore_params *params, u32 flags, struct mpool_descriptor **mpp)
{
	struct omf_sb_descriptor *sbmdc0;
	struct mpool_descriptor *mp;
	struct pmd_layout *mdc01 = NULL;
	struct pmd_layout *mdc02 = NULL;
	struct media_class *mcmeta;
	u64 mdcmax, mdcnum, mdcncap, mdc0cap;
	bool force = ((flags & (1 << MP_FLAGS_FORCE)) != 0);
	bool mc_resize[MP_MED_NUMBER] = { };
	bool active;
	int dup, doff, err, i;
	u8  pdh;

	active = false;
	*mpp = NULL;

	if (dcnt > MPOOL_DRIVES_MAX) {
		err = -EINVAL;
		mp_pr_err("too many drives in input %lu, first drive path %s",
			  err, (ulong)dcnt, dpaths[0]);
		return err;
	}

	/*
	 * Verify no duplicate drive paths
	 */
	err = check_for_dups(dpaths, dcnt, &dup, &doff);
	if (err) {
		mp_pr_err("duplicate drive check failed", err);
		return err;
	} else if (dup) {
		err = -EINVAL;
		mp_pr_err("duplicate drive path %s", err, (doff == -1) ? "" : dpaths[doff]);
		return err;
	}

	/* Alloc mpool descriptor and fill in device-indepdendent values */
	mp = mpool_desc_alloc();
	if (!mp) {
		err = -ENOMEM;
		mp_pr_err("alloc mpool desc failed", err);
		return err;
	}

	sbmdc0 = &(mp->pds_sbmdc0);

	mp->pds_pdvcnt = 0;

	if (params)
		mp->pds_params = *params;

	mutex_lock(&mpool_s_lock);

	mp->pds_workq = alloc_workqueue("mpoolwq", WQ_UNBOUND, 0);
	if (!mp->pds_workq) {
		err = -ENOMEM;
		mp_pr_err("alloc mpoolwq failed, first drive path %s", err, dpaths[0]);
		goto errout;
	}

	mp->pds_erase_wq = alloc_workqueue("mperasewq", WQ_HIGHPRI, 0);
	if (!mp->pds_erase_wq) {
		err = -ENOMEM;
		mp_pr_err("alloc mperasewq failed, first drive path %s", err, dpaths[0]);
		goto errout;
	}

	/* Get device parm for all drive paths */
	err = mpool_dev_init_all(mp->pds_pdv, dcnt, dpaths, pd_prop);
	if (err) {
		mp_pr_err("can't get drive device params, first drive path %s", err, dpaths[0]);
		goto errout;
	}

	/* Set mp.pdvcnt so dpaths will get closed in cleanup if activate fails. */
	mp->pds_pdvcnt = dcnt;

	/* Init mpool descriptor from superblocks on drives */
	err = mpool_desc_init_sb(mp, sbmdc0, flags, mc_resize);
	if (err) {
		mp_pr_err("mpool_desc_init_sb failed, first drive path %s", err, dpaths[0]);
		goto errout;
	}

	mcmeta = &mp->pds_mc[mp->pds_mdparm.md_mclass];
	if (mcmeta->mc_pdmc < 0) {
		err = -ENODEV;
		mp_pr_err("mpool %s, too many unavailable drives", err, mp->pds_name);
		goto errout;
	}

	/* Alloc mdc0 mlog layouts from superblock and activate mpool */
	err = mpool_mdc0_sb2obj(mp, sbmdc0, &mdc01, &mdc02);
	if (err) {
		mp_pr_err("mpool %s, allocation of MDC0 mlogs layouts failed", err, mp->pds_name);
		goto errout;
	}

	err = pmd_mpool_activate(mp, mdc01, mdc02, 0);
	if (err) {
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

	/* Tolerate unavailable drives only if force flag specified */
	for (i = 0; !force && i < MP_MED_NUMBER; i++) {
		struct media_class *mc;

		mc = &mp->pds_mc[i];
		if (mc->mc_uacnt) {
			err = -ENODEV;
			mp_pr_err("mpool %s, unavailable drives present", err, mp->pds_name);
			goto errout;
		}
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
				mp_pr_err("mpool %s, MDC1 can't be created", err, mp->pds_name);
				goto errout;
			}

			mp_pr_notice("mpool %s, couldn't create %lu MDCs out of %lu MDCs",
				     mp->pds_name, (ulong)(mdcnum - mdcmax + 1), (ulong)mdcnum);

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
	if (err) {
		/* Root mlogs creation failure - non-functional mpool */
		mp_pr_err("mpool %s, root mlogs creation failed", err, mp->pds_name);
		goto errout;
	}

	/* Add mp to the list of all activated mpools */
	uuid_to_mpdesc_insert(&mpool_pools, mp);

	/* Start the background thread doing pre-compaction of MDC1/255 */
	pmd_precompact_start(mp);

errout:
	if (err) {
		if (mp->pds_workq)
			destroy_workqueue(mp->pds_workq);
		if (mp->pds_erase_wq)
			destroy_workqueue(mp->pds_erase_wq);

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

int mpool_deactivate(struct mpool_descriptor *mp)
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

int mpool_destroy(u64 dcnt, char **dpaths, struct pd_prop *pd_prop, u32 flags)
{
	struct omf_sb_descriptor *sbmdc0;
	struct mpool_descriptor *mp;
	int dup, doff;
	int err, i;

	if (dcnt > MPOOL_DRIVES_MAX) {
		err = -EINVAL;
		mp_pr_err("first pd %s, too many drives %lu %d",
			  err, dpaths[0], (ulong)dcnt, MPOOL_DRIVES_MAX);
		return err;
	} else if (dcnt == 0) {
		return -EINVAL;
	}

	/*
	 * Verify no duplicate drive paths
	 */
	err = check_for_dups(dpaths, dcnt, &dup, &doff);
	if (err) {
		mp_pr_err("check_for_dups failed, dcnt %lu", err, (ulong)dcnt);
		return err;
	} else if (dup) {
		err = -ENOMEM;
		mp_pr_err("duplicate drives found", err);
		return err;
	}

	sbmdc0 = kzalloc(sizeof(*sbmdc0), GFP_KERNEL);
	if (!sbmdc0) {
		err = -ENOMEM;
		mp_pr_err("alloc sb %zu failed", err, sizeof(*sbmdc0));
		return err;
	}

	mp = mpool_desc_alloc();
	if (!mp) {
		err = -ENOMEM;
		mp_pr_err("alloc mpool desc failed", err);
		kfree(sbmdc0);
		return err;
	}

	mp->pds_pdvcnt = 0;

	mutex_lock(&mpool_s_lock);

	/* Get device parm for all drive paths */
	err = mpool_dev_init_all(mp->pds_pdv, dcnt, dpaths, pd_prop);
	if (err) {
		mp_pr_err("first pd %s, get device params failed", err, dpaths[0]);
		goto errout;
	}

	/* Set pdvcnt so dpaths will get closed in cleanup if open fails. */
	mp->pds_pdvcnt = dcnt;

	/* Init mpool descriptor from superblocks on drives */
	err = mpool_desc_init_sb(mp, sbmdc0, flags, NULL);
	if (err) {
		mp_pr_err("mpool %s, first pd %s, mpool desc init from sb failed",
			  err, (mp->pds_name == NULL) ? "" : mp->pds_name, dpaths[0]);
		goto errout;
	}

	/* Erase super blocks on the drives */
	for (i = 0; i < mp->pds_pdvcnt; i++) {
		struct mpool_dev_info *pd;

		pd = &mp->pds_pdv[i];
		if (mpool_pd_status_get(pd) != PD_STAT_ONLINE) {
			err = -EIO;
			mp_pr_err("pd %s unavailable or offline, status %d",
				  err, pd->pdi_name, mpool_pd_status_get(pd));
		} else {
			err = sb_erase(&pd->pdi_parm);
			if (err)
				mp_pr_err("pd %s, sb erase failed", err, pd->pdi_name);
		}

		if (err)
			break;
	}

errout:
	mpool_desc_free(mp);

	mutex_unlock(&mpool_s_lock);

	kfree(sbmdc0);

	return err;
}

int mpool_rename(u64 dcnt, char **dpaths, struct pd_prop *pd_prop,
		 u32 flags, const char *mp_newname)
{
	struct omf_sb_descriptor*sb;
	struct mpool_descriptor *mp;
	struct mpool_dev_info *pd = NULL;
	u16 omf_ver = OMF_SB_DESC_UNDEF;
	bool force = ((flags & (1 << MP_FLAGS_FORCE)) != 0);
	u8 pdh;
	int dup, doff;
	int err = 0;

	if (!mp_newname || dcnt == 0)
		return -EINVAL;

	if (dcnt > MPOOL_DRIVES_MAX) {
		err = -EINVAL;
		mp_pr_err("first pd %s, too many drives %lu %d",
			  err, dpaths[0], (ulong)dcnt, MPOOL_DRIVES_MAX);
		return err;
	}

	/*
	 * Verify no duplicate drive paths
	 */
	err = check_for_dups(dpaths, dcnt, &dup, &doff);
	if (err) {
		mp_pr_err("check_for_dups failed, dcnt %lu", err, (ulong)dcnt);
		return err;
	} else if (dup) {
		err = -ENOMEM;
		mp_pr_err("duplicate drives found", err);
		return err;
	}

	sb = kzalloc(sizeof(*sb), GFP_KERNEL);
	if (!sb) {
		err = -ENOMEM;
		mp_pr_err("alloc sb %zu failed", err, sizeof(*sb));
		return err;
	}

	mp = mpool_desc_alloc();
	if (!mp) {
		err = -ENOMEM;
		mp_pr_err("alloc mpool desc failed", err);
		kfree(sb);
		return err;
	}

	mp->pds_pdvcnt = 0;

	mutex_lock(&mpool_s_lock);

	/* Get device parm for all drive paths */
	err = mpool_dev_init_all(mp->pds_pdv, dcnt, dpaths, pd_prop);
	if (err) {
		mp_pr_err("first pd %s, get device params failed", err, dpaths[0]);
		goto errout;
	}

	/* Set pdvcnt so dpaths will get closed in cleanup if open fails.
	 */
	mp->pds_pdvcnt = dcnt;

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		pd = &mp->pds_pdv[pdh];

		if (mpool_pd_status_get(pd) != PD_STAT_ONLINE) {
			err = -EIO;
			mp_pr_err("pd %s unavailable or offline, status %d",
				  err, pd->pdi_name, mpool_pd_status_get(pd));
			goto errout;
		}

		/*
		 * Read superblock; init and validate pool drive info
		 * from device parameters stored in the super block.
		 */
		err = sb_read(&pd->pdi_parm, sb, &omf_ver, force);
		if (err) {
			mp_pr_err("pd %s, sb read failed", err, pd->pdi_name);
			goto errout;
		}

		if (omf_ver > OMF_SB_DESC_VER_LAST ||
		    omf_ver < OMF_SB_DESC_VER_LAST) {
			err = -EOPNOTSUPP;
			mp_pr_err("pd %s, invalid sb version %d %d",
				  err, pd->pdi_name, omf_ver, OMF_SB_DESC_VER_LAST);
			goto errout;
		}

		if (!strcmp(mp_newname, sb->osb_name))
			continue;

		strlcpy(sb->osb_name, mp_newname, sizeof(sb->osb_name));

		err = sb_write_update(&pd->pdi_parm, sb);
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

int mpool_drive_add(struct mpool_descriptor *mp, char *dpath, struct pd_prop *pd_prop)
{
	struct mpool_dev_info *pd;
	struct mc_smap_parms mcsp;
	char *dpathv[1] = { dpath };
	bool erase = false;
	bool smap = false;
	int err;

	/*
	 * All device list changes are serialized via mpool_s_lock so
	 * don't need to acquire mp.pdvlock until ready to update mpool
	 * descriptor
	 */
	mutex_lock(&mpool_s_lock);

	if (mp->pds_pdvcnt >= MPOOL_DRIVES_MAX) {
		mutex_unlock(&mpool_s_lock);

		mp_pr_warn("%s: pd %s, too many drives %u %d",
			   mp->pds_name, dpath, mp->pds_pdvcnt, MPOOL_DRIVES_MAX);
		return -EINVAL;
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

	err = mpool_dev_init_all(pd, 1, dpathv, pd_prop);
	if (err) {
		mutex_unlock(&mpool_s_lock);

		mp_pr_err("%s: pd %s, getting drive params failed", err, mp->pds_name, dpath);
		return err;
	}

	/* Confirm drive meets all criteria for adding to this mpool */
	err = mpool_dev_check_new(mp, pd);
	if (err) {
		mp_pr_err("%s: pd %s, drive doesn't pass criteria", err, mp->pds_name, dpath);
		goto errout;
	}

	/*
	 * Check that the drive can be added in a media class.
	 */
	down_read(&mp->pds_pdvlock);
	err = mpool_desc_pdmc_add(mp, mp->pds_pdvcnt, NULL, true);
	up_read(&mp->pds_pdvlock);
	if (err) {
		mp_pr_err("%s: pd %s, can't place in any media class", err, mp->pds_name, dpath);
		goto errout;
	}


	mpool_generate_uuid(&pd->pdi_devid);

	/* Write mpool superblock to drive */
	erase = true;
	err = mpool_dev_sbwrite(mp, pd, NULL);
	if (err) {
		mp_pr_err("%s: pd %s, sb write failed", err, mp->pds_name, dpath);
		goto errout;
	}

	/* Get percent spare */
	down_read(&mp->pds_pdvlock);
	err = mc_smap_parms_get(&mp->pds_mc[pd->pdi_mclass], &mp->pds_params, &mcsp);
	up_read(&mp->pds_pdvlock);
	if (err)
		goto errout;

	/* Alloc space map for drive */
	err = smap_drive_init(mp, &mcsp, mp->pds_pdvcnt);
	if (err) {
		mp_pr_err("%s: pd %s, smap init failed", err, mp->pds_name, dpath);
		goto errout;
	}
	smap = true;

	/*
	 * Take MDC0 compact lock to prevent race with MDC0 compaction.
	 * Take it across memory and media update.
	 */
	PMD_MDC0_COMPACTLOCK(mp);

	/*
	 * Add drive state record to mdc0; if crash any time prior to adding
	 * this record the drive will not be recognized as an mpool member
	 * on next open
	 */
	err = pmd_prop_mcconfig(mp, pd, false);
	if (err) {
		PMD_MDC0_COMPACTUNLOCK(mp);
		mp_pr_err("%s: pd %s, adding drive state to MDC0 failed", err, mp->pds_name, dpath);
		goto errout;
	}

	/* Make new drive visible in mpool */
	down_write(&mp->pds_pdvlock);
	mp->pds_pdvcnt++;

	/*
	 * Add the PD in its class. That should NOT fail because we already
	 * checked that the drive can be added in a media class.
	 */
	err = mpool_desc_pdmc_add(mp, mp->pds_pdvcnt - 1, NULL, false);
	if (err)
		mp->pds_pdvcnt--;

	up_write(&mp->pds_pdvlock);
	PMD_MDC0_COMPACTUNLOCK(mp);

errout:
	if (err) {
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
			sb_erase(&pd->pdi_parm);

		pd_dev_close(&pd->pdi_parm);
	}

	mutex_unlock(&mpool_s_lock);

	return err;
}

void mpool_mclass_get_cnt(struct mpool_descriptor *mp, u32 *cnt)
{
	int i;

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

int mpool_mclass_get(struct mpool_descriptor *mp, u32 *mcxc, struct mpool_mclass_xprops *mcxv)
{
	int i, n;

	if (!mp || !mcxc || !mcxv)
		return -EINVAL;

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

int mpool_drive_spares(struct mpool_descriptor *mp, enum mp_media_classp mclassp, u8 drive_spares)
{
	struct media_class *mc;
	int err;

	if (!mclass_isvalid(mclassp) || drive_spares > 100) {
		err = -EINVAL;
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
		err = -ENOENT;
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
	if (err) {
		mp_pr_err("mpool %s, setting spare %u mclass %d failed, could not record in MDC0",
			  err, mp->pds_name, drive_spares, mclassp);
	} else {
		/* Update spare zone accounting for media class */
		down_write(&mp->pds_pdvlock);

		err = mc_set_spzone(&mp->pds_mc[mclassp], drive_spares);
		if (err)
			mp_pr_err("mpool %s, setting spare %u mclass %d failed",
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

void mpool_get_xprops(struct mpool_descriptor *mp, struct mpool_xprops *xprops)
{
	struct media_class *mc;
	int mclassp, i;
	u16 ftmax;

	mutex_lock(&mpool_s_lock);
	down_read(&mp->pds_pdvlock);

	memcpy(xprops->ppx_params.mp_poolid.b, mp->pds_poolid.uuid, MPOOL_UUID_SIZE);
	ftmax = 0;

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

	xprops->ppx_params.mp_stat = ftmax ? MPOOL_STAT_FAULTED : MPOOL_STAT_OPTIMAL;
}

int mpool_get_devprops_by_name(struct mpool_descriptor *mp, char *pdname,
			       struct mpool_devprops *dprop)
{
	int i;

	down_read(&mp->pds_pdvlock);

	for (i = 0; i < mp->pds_pdvcnt; i++) {
		if (!strcmp(pdname, mp->pds_pdv[i].pdi_name))
			fill_in_devprops(mp, i, dprop);
	}

	up_read(&mp->pds_pdvlock);

	return 0;
}

void mpool_get_usage(struct mpool_descriptor *mp, enum mp_media_classp mclassp,
		     struct mpool_usage *usage)
{
	memset(usage, 0, sizeof(*usage));

	down_read(&mp->pds_pdvlock);
	if (mclassp != MP_MED_ALL) {
		struct media_class *mc;

		ASSERT(mclassp < MP_MED_NUMBER);

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

int mpool_config_store(struct mpool_descriptor *mp, const struct mpool_config *cfg)
{
	int err;

	if (!mp || !cfg)
		return -EINVAL;

	mp->pds_cfg = *cfg;

	err = pmd_prop_mpconfig(mp, cfg, false);
	if (err)
		mp_pr_err("mpool %s, logging config record failed", err, mp->pds_name);

	return err;
}

int mpool_config_fetch(struct mpool_descriptor *mp, struct mpool_config *cfg)
{
	if (!mp || !cfg)
		return -EINVAL;

	*cfg = mp->pds_cfg;

	return 0;
}
