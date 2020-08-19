// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * DOC: Module info.
 *
 * Pool metadata (pmd) module.
 *
 * Defines functions for probing, reading, and writing drives in an mpool.
 *
 */

#include <linux/workqueue.h>
#include <linux/log2.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/sort.h>
#include <linux/delay.h>

#include "mpool_defs.h"
#include "pmd_utils.h"

DEFINE_MUTEX(pmd_s_lock);

static merr_t
pmd_obj_alloc_cmn(
	struct mpool_descriptor    *mp,
	u64                         objid,
	enum obj_type_omf           otype,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclass,
	int                         realloc,
	bool                        needref,
	struct pmd_layout         **layoutp);

static merr_t pmd_write_meta_to_latest_version(struct mpool_descriptor *mp, bool permitted);
static void pmd_mdc_alloc_set(struct mpool_descriptor *mp);
static merr_t pmd_mdc0_validate(struct mpool_descriptor *mp, int activation);

static const char *msg_unavail1 __maybe_unused =
	"defunct and unavailable drive still belong to the mpool";

static const char *msg_unavail2 __maybe_unused =
	"defunct and available drive still belong to the mpool";

static merr_t pmd_props_load(struct mpool_descriptor *mp)
{
	struct omf_mdcrec_data          cdr;
	struct pmd_mdc_info            *cinfo = NULL;
	struct omf_devparm_descriptor   netdev[MP_MED_NUMBER] = { };
	enum mp_media_classp            mclassp;
	struct media_class             *mc;
	size_t                          rlen = 0;
	merr_t                          err;
	u64                             pdh, buflen;
	int                             spzone[MP_MED_NUMBER], i;
	bool                            zombie[MPOOL_DRIVES_MAX];

	cinfo = &mp->pds_mda.mdi_slotv[0];
	buflen = OMF_MDCREC_PACKLEN_MAX;

	/*  Note: single threaded here so don't need any locks */

	/* Set mpool properties to defaults; overwritten by property records (if any). */
	for (mclassp = 0; mclassp < MP_MED_NUMBER; mclassp++)
		spzone[mclassp] = -1;

	/*
	 * read mdc0 to capture net of drives, content version & other
	 * properties; ignore obj records
	 */
	err = mp_mdc_rewind(cinfo->mmi_mdc);
	if (err) {
		mp_pr_err("mpool %s, MDC0 init for read properties failed", err, mp->pds_name);
		return err;
	}

	while (true) {
		err = mp_mdc_read(cinfo->mmi_mdc, cinfo->mmi_recbuf, buflen, &rlen);
		if (err) {
			mp_pr_err("mpool %s, MDC0 read next failed %lu",
				  err, mp->pds_name, (ulong)rlen);
			break;
		}
		if (rlen == 0)
			/* Hit end of log */
			break;

		/*
		 * skip object-related mdcrec in mdc0; not ready to unpack
		 * these yet
		 */
		if (omf_mdcrec_isobj_le(cinfo->mmi_recbuf))
			continue;

		err = omf_mdcrec_unpack_letoh(&(cinfo->mmi_mdcver), mp, &cdr, cinfo->mmi_recbuf);
		if (err) {
			mp_pr_err("mpool %s, MDC0 property unpack failed", err, mp->pds_name);
			break;
		}

		if (cdr.omd_rtype == OMF_MDR_MCCONFIG) {
			struct omf_devparm_descriptor *src;

			src = &cdr.u.dev.omd_parm;
			assert(src->odp_mclassp < MP_MED_NUMBER);

			memcpy(&netdev[src->odp_mclassp], src, sizeof(*src));
			continue;
		}

		if (cdr.omd_rtype == OMF_MDR_MCSPARE) {
			mclassp = cdr.u.mcs.omd_mclassp;
			if (mclass_isvalid(mclassp)) {
				spzone[mclassp] = cdr.u.mcs.omd_spzone;
			} else {
				err = merr(EINVAL);

				/* Should never happen */
				mp_pr_err("mpool %s, MDC0 mclass spare record, invalid mclassp %u",
					  err, mp->pds_name, mclassp);
				break;
			}
			continue;
		}

		if (cdr.omd_rtype == OMF_MDR_VERSION) {
			cinfo->mmi_mdcver = cdr.u.omd_version;
			if (omfu_mdcver_cmp(&cinfo->mmi_mdcver, ">", omfu_mdcver_cur())) {
				char   buf1[MAX_MDCVERSTR];
				char   buf2[MAX_MDCVERSTR];

				omfu_mdcver_to_str(&cinfo->mmi_mdcver, buf1, sizeof(buf1));
				omfu_mdcver_to_str(omfu_mdcver_cur(), buf2, sizeof(buf2));

				err = merr(EOPNOTSUPP);
				mp_pr_err("mpool %s, MDC0 version %s, binary version %s",
					  err, mp->pds_name, buf1, buf2);
				break;
			}
			continue;
		}

		if (cdr.omd_rtype == OMF_MDR_MPCONFIG)
			mp->pds_cfg = cdr.u.omd_cfg;
	}

	if (ev(err))
		return err;

	/* Reconcile net drive list with those in mpool descriptor */
	for (i = 0; i < mp->pds_pdvcnt; i++)
		zombie[i] = true;

	for (i = 0; i < MP_MED_NUMBER; i++) {
		struct omf_devparm_descriptor *omd;
		int    j;

		omd = &netdev[i];

		if (mpool_uuid_is_null(&omd->odp_devid))
			continue;

		j = mp->pds_pdvcnt;
		while (j--) {
			if (mpool_uuid_compare(&mp->pds_pdv[j].pdi_devid, &omd->odp_devid) == 0)
				break;
		}

		if (j >= 0) {
			zombie[j] = false;
			err = pmd_cmp_drv_mdc0(mp, j, omd);
			if (ev(err))
				break;
		} else {
			err = mpool_desc_unavail_add(mp, omd);
			if (ev(err))
				break;
			zombie[mp->pds_pdvcnt - 1] = false;
		}
	}

	/* Check for zombie drives and recompute uacnt[] */
	if (!err) {
		for (i = 0; i < MP_MED_NUMBER; i++) {
			mc = &mp->pds_mc[i];
			mc->mc_uacnt = 0;
		}

		for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
			struct mpool_dev_info  *pd;

			mc = &mp->pds_mc[mp->pds_pdv[pdh].pdi_mclass];
			pd = &mp->pds_pdv[pdh];
			if (zombie[pdh]) {
				char uuid_str[40];

				mpool_unparse_uuid(&pd->pdi_devid, uuid_str);
				err = merr(ENXIO);

				if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL)
					mp_pr_err("mpool %s, drive %s %s %s", err, mp->pds_name,
						   uuid_str, pd->pdi_name, msg_unavail1);
				else
					mp_pr_err("mpool %s, drive %s %s %s", err, mp->pds_name,
						  uuid_str, pd->pdi_name, msg_unavail2);
				break;
			} else if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL) {
				mc->mc_uacnt += 1;
			}
		}
	}

	/*
	 * Now it is possible to update the percent spare because all
	 * the media classes of the mpool have been created because all
	 * the mpool PDs have been added in their classes.
	 */
	if (!err) {
		for (mclassp = 0; mclassp < MP_MED_NUMBER; mclassp++) {
			if (spzone[mclassp] >= 0) {
				err = mc_set_spzone(mp, mclassp, spzone[mclassp]);
				/*
				 * Should never happen, it should exist a class
				 * with perf. level mclassp with a least 1 PD.
				 */
				if (ev(err))
					break;
			}
		}
		if (err)
			mp_pr_err("mpool %s, can't set spare %u because the class %u has no PD",
				  err, mp->pds_name, spzone[mclassp], mclassp);
	}

	return err;
}

static merr_t pmd_objs_load(struct mpool_descriptor *mp, u8 cslot)
{
	u64                         argv[2] = { 0 };
	struct omf_mdcrec_data      cdr;
	struct pmd_mdc_info        *cinfo;
	struct rb_node             *node;
	const char                 *msg;
	merr_t                      err;
	size_t                      recbufsz;
	char                       *recbuf;
	u64                         mdcmax;

	/* Note: single threaded here so don't need any locks */

	recbufsz = OMF_MDCREC_PACKLEN_MAX;
	memset(&cdr, 0, sizeof(cdr));
	msg = "(no detail)";
	mdcmax = 0;

	cinfo = &mp->pds_mda.mdi_slotv[cslot];

	/* Initialize mdc if not mdc0. */
	if (cslot) {
		u64 logid1 = logid_make(2 * cslot, 0);
		u64 logid2 = logid_make(2 * cslot + 1, 0);

		/* Freed in pmd_mda_free() */
		cinfo->mmi_recbuf = kmalloc(recbufsz, GFP_KERNEL);
		if (!cinfo->mmi_recbuf) {
			msg = "MDC recbuf alloc failed";
			err = merr(ENOMEM);
			goto errout;
		}

		err = mp_mdc_open(mp, logid1, logid2, MDC_OF_SKIP_SER, &cinfo->mmi_mdc);
		if (ev(err)) {
			msg = "mdc open failed";
			goto errout;
		}
	}

	/* Read mdc and capture net result of object data records. */
	err = mp_mdc_rewind(cinfo->mmi_mdc);
	if (ev(err)) {
		msg = "mdc rewind failed";
		goto errout;
	}

	/* Cache these pointers to simplify the ensuing code. */
	recbuf = cinfo->mmi_recbuf;

	while (true) {
		struct pmd_layout *layout, *found;

		size_t rlen = 0;
		u64 objid;

		err = mp_mdc_read(cinfo->mmi_mdc, recbuf, recbufsz, &rlen);
		if (ev(err)) {
			msg = "mdc read data failed";
			break;
		}
		if (rlen == 0)
			break; /* Hit end of log */

		/*
		 * Version record, if present, must be first.
		 */
		if (omf_mdcrec_unpack_type_letoh(recbuf) == OMF_MDR_VERSION) {
			omf_mdcver_unpack_letoh(&cdr, recbuf);
			cinfo->mmi_mdcver = cdr.u.omd_version;

			if (omfu_mdcver_cmp(&cinfo->mmi_mdcver, ">", omfu_mdcver_cur())) {

				char	buf1[MAX_MDCVERSTR];
				char	buf2[MAX_MDCVERSTR];

				omfu_mdcver_to_str(&cinfo->mmi_mdcver, buf1, sizeof(buf1));
				omfu_mdcver_to_str(omfu_mdcver_cur(), buf2, sizeof(buf2));

				err = merr(EOPNOTSUPP);
				mp_pr_err("mpool %s, MDC%u version %s, binary version %s",
					  err, mp->pds_name, cslot, buf1, buf2);
				break;
			}
			continue;
		}

		/* Skip non object-related mdcrec in mdc0; i.e., property
		 * records.
		 */
		if (!cslot && !omf_mdcrec_isobj_le(recbuf))
			continue;

		err = omf_mdcrec_unpack_letoh(&cinfo->mmi_mdcver, mp, &cdr, recbuf);
		if (ev(err)) {
			msg = "mlog record unpack failed";
			break;
		}

		objid = cdr.u.obj.omd_objid;

		if (objid_slot(objid) != cslot) {
			msg = "mlog record wrong slot";
			err = merr(EBADSLT);
			break;
		}

		if (cdr.omd_rtype == OMF_MDR_OCREATE) {
			layout = cdr.u.obj.omd_layout;
			layout->eld_state = PMD_LYT_COMMITTED;

			found = pmd_co_insert(cinfo, layout);
			if (found) {
				msg = "OCREATE duplicate object ID";
				pmd_obj_put(mp, layout);
				err = merr(EEXIST);
				break;
			}

			atomic_inc(&cinfo->mmi_pco_cnt.pcc_cr);
			atomic_inc(&cinfo->mmi_pco_cnt.pcc_cobj);

			continue;
		}

		if (cdr.omd_rtype == OMF_MDR_ODELETE) {
			found = pmd_co_find(cinfo, objid);
			if (!found) {
				msg = "ODELETE object not found";
				err = merr(ENOENT);
				break;
			}

			pmd_co_remove(cinfo, found);
			pmd_obj_put(mp, found);

			atomic_inc(&cinfo->mmi_pco_cnt.pcc_del);
			atomic_dec(&cinfo->mmi_pco_cnt.pcc_cobj);

			continue;
		}

		if (cdr.omd_rtype == OMF_MDR_OIDCKPT) {
			/*
			 * objid == mmi_lckpt == 0 is legit. Such records
			 * are appended by mpool MDC compaction due to a
			 * mpool metadata upgrade on an empty mpool.
			 */
			if ((objid_uniq(objid) || objid_uniq(cinfo->mmi_lckpt))
				&& (objid_uniq(objid) <= objid_uniq(cinfo->mmi_lckpt))) {
				msg = "OIDCKPT cdr ckpt %lu <= cinfo ckpt %lu";
				argv[0] = objid_uniq(objid);
				argv[1] = objid_uniq(cinfo->mmi_lckpt);
				err = merr(EINVAL);
				break;
			}

			cinfo->mmi_lckpt = objid;
			continue;
		}

		if (cdr.omd_rtype == OMF_MDR_OERASE) {
			layout = pmd_co_find(cinfo, objid);
			if (!layout) {
				msg = "OERASE object not found";
				err = merr(ENOENT);
				break;
			}

			/* Note: OERASE gen can equal layout gen after a compaction. */
			if (cdr.u.obj.omd_gen < layout->eld_gen) {
				msg = "OERASE cdr gen %lu < layout gen %lu";
				argv[0] = cdr.u.obj.omd_gen;
				argv[1] = layout->eld_gen;
				err = merr(EINVAL);
				break;
			}

			layout->eld_gen = cdr.u.obj.omd_gen;

			atomic_inc(&cinfo->mmi_pco_cnt.pcc_er);
			continue;
		}

		if (cdr.omd_rtype == OMF_MDR_OUPDATE) {
			layout = cdr.u.obj.omd_layout;

			found = pmd_co_find(cinfo, objid);
			if (!found) {
				msg = "OUPDATE object not found";
				pmd_obj_put(mp, layout);
				err = merr(ENOENT);
				break;
			}

			pmd_co_remove(cinfo, found);
			pmd_obj_put(mp, found);

			layout->eld_state = PMD_LYT_COMMITTED;
			pmd_co_insert(cinfo, layout);

			atomic_inc(&cinfo->mmi_pco_cnt.pcc_up);

			continue;
		}
	}

	if (ev(err))
		goto errout;

	/*
	 * Add all existing objects to space map.
	 * Also add/update per-mpool space usage stats
	 */
	pmd_co_foreach(cinfo, node) {
		struct pmd_layout *layout;

		layout = rb_entry(node, typeof(*layout), eld_nodemdc);

		/* Remember objid and gen in case of error... */
		cdr.u.obj.omd_objid = layout->eld_objid;
		cdr.u.obj.omd_gen = layout->eld_gen;

		if (objid_slot(layout->eld_objid) != cslot) {
			msg = "layout wrong slot";
			err = merr(EBADSLT);
			break;
		}

		err = pmd_smap_insert(mp, layout);
		if (ev(err)) {
			msg = "smap insert failed";
			break;
		}

		pmd_update_mdc_stats(mp, layout, cinfo, PMD_OBJ_LOAD);

		/* For mdc0 track last logical mdc created. */
		if (!cslot)
			mdcmax = max(mdcmax, (objid_uniq(layout->eld_objid) >> 1));
	}

	if (ev(err))
		goto errout;

	cdr.u.obj.omd_objid = 0;
	cdr.u.obj.omd_gen = 0;

	if (!cslot) {
		/* MDC0: finish initializing mda */
		cinfo->mmi_luniq = mdcmax;
		mp->pds_mda.mdi_slotvcnt = mdcmax + 1;

		/* MDC0 only: validate other mdc metadata; may make adjustments to mp.mda. */
		err = pmd_mdc0_validate(mp, 1);
		if (ev(err))
			msg = "MDC0 validation failed";
	} else {
		/*
		 * other mdc: set luniq to guaranteed max value
		 * previously used and ensure next objid allocation
		 * will be checkpointed; supports realloc of
		 * uncommitted objects after a crash
		 */
		cinfo->mmi_luniq = objid_uniq(cinfo->mmi_lckpt) + OBJID_UNIQ_DELTA - 1;
	}

errout:
	if (err) {
		char msgbuf[64];

		snprintf(msgbuf, sizeof(msgbuf), msg, argv[0], argv[1]);

		mp_pr_err("mpool %s, %s: cslot %u, ckpt %lx, %lx/%lu",
			  err, mp->pds_name, msgbuf, cslot, (ulong)cinfo->mmi_lckpt,
			  (ulong)cdr.u.obj.omd_objid, (ulong)cdr.u.obj.omd_gen);
	}

	return err;
}

/**
 * pmd_objs_load_worker() -
 * @ws:
 *
 * worker thread for loading user MDC 1~N
 * Each worker instance will do the following (not counting errors):
 * * grab an MDC number atomically from olw->olw_progress
 * * If the MDC number is invalid, exit
 * * load the objects from that MDC
 *
 * If an error occurs in this or any other worker, don't load any more MDCs
 */
static void pmd_objs_load_worker(struct work_struct *ws)
{
	struct pmd_obj_load_work       *olw;
	int                             sidx;
	merr_t                          err;

	olw = container_of(ws, struct pmd_obj_load_work, olw_work);

	while (atomic64_read(olw->olw_err) == 0) {
		sidx = atomic_fetch_add(1, olw->olw_progress);
		if (sidx >= olw->olw_mp->pds_mda.mdi_slotvcnt)
			break; /* No more MDCs to load */

		err = pmd_objs_load(olw->olw_mp, sidx);
		if (ev(err))
			atomic64_set(olw->olw_err, err);
	}
}

/**
 * pmd_objs_load_parallel() - load MDC 1~N in parallel
 * @mp:
 *
 * By loading user MDCs in parallel, we can reduce the mpool activate
 * time, since the jobs of loading MDC 1~N are independent.
 * On the other hand, we don't want to start all the jobs at once.
 * If any one fails, we don't have to start others.
 */
static merr_t pmd_objs_load_parallel(struct mpool_descriptor *mp)
{
	struct pmd_obj_load_work   *olwv;

	atomic64_t  err = ATOMIC64_INIT(0);
	atomic_t    progress = ATOMIC_INIT(1);
	uint        njobs, inc, cpu, i;

	if (mp->pds_mda.mdi_slotvcnt < 2)
		return 0; /* No user MDCs allocated */

	njobs = mp->pds_params.mp_objloadjobs;
	njobs = clamp_t(uint, njobs, 1, mp->pds_mda.mdi_slotvcnt - 1);

	if (mp->pds_mda.mdi_slotvcnt / njobs >= 4 && num_online_cpus() > njobs)
		njobs *= 2;

	olwv = kcalloc(njobs, sizeof(*olwv), GFP_KERNEL);
	if (!olwv)
		return merr(ENOMEM);

	inc = (num_online_cpus() / njobs) & ~1u;
	cpu = raw_smp_processor_id();

	/*
	 * Each of njobs workers will atomically grab MDC numbers from &progress
	 * and load them, until all valid user MDCs have been loaded.
	 */
	for (i = 0; i < njobs; ++i) {
		INIT_WORK(&olwv[i].olw_work, pmd_objs_load_worker);
		olwv[i].olw_progress = &progress;
		olwv[i].olw_err = &err;
		olwv[i].olw_mp = mp;

		/*
		 * Try to distribute work across all NUMA nodes.
		 * queue_work_node() would be preferable, but
		 * it's not available on older kernels.
		 */
		cpu = (cpu + inc) % nr_cpumask_bits;
		cpu = cpumask_next_wrap(cpu, cpu_online_mask, nr_cpumask_bits, false);
		queue_work_on(cpu, mp->pds_workq, &olwv[i].olw_work);
	}

	/* Wait for all worker threads to complete */
	flush_workqueue(mp->pds_workq);

	kfree(olwv);

	return atomic64_read(&err);
}

merr_t
pmd_mpool_activate(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *mdc01,
	struct pmd_layout          *mdc02,
	int                         create,
	u32                         flags)
{
	merr_t  err;

	mp_pr_debug("mdc01: %lu mdc02: %lu", 0, (ulong)mdc01->eld_objid, (ulong)mdc02->eld_objid);

	/* Activation is intense; serialize it when have multiple mpools */
	mutex_lock(&pmd_s_lock);

	/* Init metadata array for mpool */
	pmd_mda_init(mp);

	/* Initialize mdc0 for mpool */
	err = pmd_mdc0_init(mp, mdc01, mdc02);
	if (ev(err)) {
		/*
		 * pmd_mda_free() will dealloc mdc01/2 on subsequent
		 * activation failures
		 */
		pmd_obj_put(mp, mdc01);
		pmd_obj_put(mp, mdc02);
		goto exit;
	}

	/* Load mpool properties from mdc0 including drive list and states */
	if (!create) {
		err = pmd_props_load(mp);
		if (ev(err))
			goto exit;
	}

	/*
	 * initialize smaps for all drives in mpool (now that list
	 * is finalized)
	 */
	err = smap_mpool_init(mp);
	if (ev(err))
		goto exit;

	/* Load mdc layouts from mdc0 and finalize mda initialization */
	err = pmd_objs_load(mp, 0);
	if (ev(err))
		goto exit;

	/* Load user object layouts from all other mdc */
	err = pmd_objs_load_parallel(mp);
	if (ev(err)) {
		mp_pr_err("mpool %s, failed to load user MDCs", err, mp->pds_name);
		goto exit;
	}

	/*
	 * If the format of the mpool metadata read from media during activate
	 * is not the latest, it is time to write the metadata on media with
	 * the latest format.
	 */
	if (!create) {
		err = pmd_write_meta_to_latest_version(mp, true);
		if (ev(err)) {
			mp_pr_err("mpool %s, failed to compact MDCs (metadata conversion)",
				  err, mp->pds_name);
			goto exit;
		}
	}
exit:
	if (err) {
		/* Activation failed; cleanup */
		pmd_mda_free(mp);
		smap_mpool_free(mp);
	}

	mutex_unlock(&pmd_s_lock);
	return err;
}

void pmd_mpool_deactivate(struct mpool_descriptor *mp)
{
	/* Deactivation is intense; serialize it when have multiple mpools */
	mutex_lock(&pmd_s_lock);

	/* Close all open user (non-mdc) mlogs */
	mlogutil_closeall(mp);

	pmd_mda_free(mp);
	smap_mpool_free(mp);

	mutex_unlock(&pmd_s_lock);
}

/**
 * pmd_precompact() - precompact an mpool MDC
 * @work:
 *
 * The goal of this thread is to minimize the application objects commit time.
 * This thread pre compacts the MDC1/255. As a consequence MDC1/255 compaction
 * does not occurs in the context of an application object commit.
 */
static void pmd_precompact(struct work_struct *work)
{
	struct pre_compact_ctrl    *pco;
	struct mpool_descriptor    *mp;
	struct pmd_mdc_info        *cinfo;

	char    msgbuf[128];
	uint    nmtoc, delay;
	bool    compact;
	u8      cslot;

	pco = container_of(work, typeof(*pco), pco_dwork.work);
	mp = pco->pco_mp;

	nmtoc = atomic_fetch_add(1, &pco->pco_nmtoc);

	/* Only compact MDC1/255 not MDC0. */
	cslot = (nmtoc % (mp->pds_mda.mdi_slotvcnt - 1)) + 1;

	/*
	 * Check if the next mpool mdc to compact needs compaction.
	 *
	 * Note that this check is done without taking any lock.
	 * This is safe because the mpool MDCs don't go away as long as
	 * the mpool is activated. The mpool can't deactivate before
	 * this thread exit.
	 */
	compact = pmd_need_compact(mp, cslot, NULL, 0);
	if (compact) {
		cinfo = &mp->pds_mda.mdi_slotv[cslot];

		/*
		 * Check a second time while we hold the compact lock
		 * to avoid doing a useless compaction.
		 */
		pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);
		compact = pmd_need_compact(mp, cslot, msgbuf, sizeof(msgbuf));
		if (compact)
			pmd_mdc_compact(mp, cslot);
		pmd_mdc_unlock(&cinfo->mmi_compactlock);

		if (compact)
			mp_pr_info("mpool %s, MDC%u %s", mp->pds_name, cslot, msgbuf);
	}

	/* If running low on MDC space create new MDCs */
	if (pmd_mdc_needed(mp))
		pmd_mdc_alloc_set(mp);

	pmd_update_credit(mp);

	delay = clamp_t(uint, mp->pds_params.mp_pcoperiod, 1, 3600);

	queue_delayed_work(mp->pds_workq, &pco->pco_dwork, msecs_to_jiffies(delay * 1000));
}

void pmd_precompact_start(struct mpool_descriptor *mp)
{
	struct pre_compact_ctrl *pco;

	pco = &mp->pds_pco;
	pco->pco_mp = mp;
	atomic_set(&pco->pco_nmtoc, 0);

	INIT_DELAYED_WORK(&pco->pco_dwork, pmd_precompact);
	queue_delayed_work(mp->pds_workq, &pco->pco_dwork, 1);
}

void pmd_precompact_stop(struct mpool_descriptor *mp)
{
	cancel_delayed_work_sync(&mp->pds_pco.pco_dwork);
}

static merr_t pmd_log_delete(struct mpool_descriptor *mp, u64 objid)
{
	struct omf_mdcrec_data  cdr;

	cdr.omd_rtype = OMF_MDR_ODELETE;
	cdr.u.obj.omd_objid = objid;
	return pmd_mdc_addrec(mp, objid_slot(objid), &cdr);
}

static merr_t pmd_log_create(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct omf_mdcrec_data  cdr;

	cdr.omd_rtype = OMF_MDR_OCREATE;
	cdr.u.obj.omd_layout = layout;
	return pmd_mdc_addrec(mp, objid_slot(layout->eld_objid), &cdr);
}

static merr_t pmd_log_erase(struct mpool_descriptor *mp, u64 objid, u64 gen)
{
	struct omf_mdcrec_data  cdr;

	cdr.omd_rtype = OMF_MDR_OERASE;
	cdr.u.obj.omd_objid = objid;
	cdr.u.obj.omd_gen = gen;
	return pmd_mdc_addrec(mp, objid_slot(objid), &cdr);
}

static merr_t pmd_log_idckpt(struct mpool_descriptor *mp, u64 objid)
{
	struct omf_mdcrec_data  cdr;

	cdr.omd_rtype = OMF_MDR_OIDCKPT;
	cdr.u.obj.omd_objid = objid;
	return pmd_mdc_addrec(mp, objid_slot(objid), &cdr);
}

struct pmd_layout *pmd_obj_find_get(struct mpool_descriptor *mp, u64 objid, int which)
{
	struct pmd_mdc_info    *cinfo;
	struct pmd_layout      *found;
	u8                      cslot;

	if (!objtype_user(objid_type(objid)))
		return NULL;

	cslot = objid_slot(objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	found = NULL;

	/*
	 * which < 0  - search uncommitted tree only
	 * which > 0  - search tree only
	 * which == 0 - search both trees
	 */
	if (which <= 0) {
		pmd_uc_lock(cinfo, cslot);
		found = pmd_uc_find(cinfo, objid);
		if (found)
			kref_get(&found->eld_ref);
		pmd_uc_unlock(cinfo);
	}

	if (!found && which >= 0) {
		pmd_co_rlock(cinfo, cslot);
		found = pmd_co_find(cinfo, objid);
		if (found)
			kref_get(&found->eld_ref);
		pmd_co_runlock(cinfo);
	}

	return found;
}

merr_t
pmd_obj_alloc(
	struct mpool_descriptor    *mp,
	enum obj_type_omf           otype,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclassp,
	struct pmd_layout         **layoutp)
{
	return pmd_obj_alloc_cmn(mp, 0, otype, ocap, mclassp, 0, true, layoutp);
}

merr_t
pmd_obj_realloc(
	struct mpool_descriptor    *mp,
	u64                         objid,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclassp,
	struct pmd_layout         **layoutp)
{
	if (!pmd_objid_isuser(objid)) {
		*layoutp = NULL;
		return merr(EINVAL);
	}

	return pmd_obj_alloc_cmn(mp, objid, objid_type(objid), ocap, mclassp, 1, true, layoutp);
}

merr_t pmd_obj_commit(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_mdc_info    *cinfo;
	struct pmd_layout      *found;
	merr_t                  err;
	u8                      cslot;

	if (!objtype_user(objid_type(layout->eld_objid)))
		return merr(EINVAL);

	pmd_obj_wrlock(layout);
	if (layout->eld_state & PMD_LYT_COMMITTED) {
		pmd_obj_wrunlock(layout);
		return 0;
	}

	/*
	 * must log create before marking object committed to guarantee it will
	 * exist after a crash; must hold cinfo.compactclock while log create,
	 * update layout.state, and add to list of committed objects to prevent
	 * a race with mdc compaction
	 */
	cslot = objid_slot(layout->eld_objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];

	pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);

	err = pmd_log_create(mp, layout);
	if (!ev(err)) {
		pmd_uc_lock(cinfo, cslot);
		found = pmd_uc_remove(cinfo, layout);
		pmd_uc_unlock(cinfo);

		pmd_co_wlock(cinfo, cslot);
		found = pmd_co_insert(cinfo, layout);
		if (!found)
			layout->eld_state |= PMD_LYT_COMMITTED;
		pmd_co_wunlock(cinfo);

		if (found) {
			err = merr(EEXIST);

			/*
			 * if objid exists in committed object list this is a
			 * SERIOUS bug; need to log a warning message; should
			 * never happen. Note in this case we are stuck because
			 * we just logged a second create for an existing
			 * object.  If mdc compaction runs before a restart this
			 * extraneous create record will be eliminated,
			 * otherwise pmd_objs_load() will see the conflict and
			 * fail the next mpool activation.  We could make
			 * pmd_objs_load() tolerate this but for now it is
			 * better to get an activation failure so that
			 * it's obvious this bug occurred. Best we can do is put
			 * the layout back in the uncommitted object list so the
			 * caller can abort after getting the commit failure.
			 */
			mp_pr_crit("mpool %s, obj 0x%lx collided during commit",
				   err, mp->pds_name, (ulong)layout->eld_objid);

			/* Put the object back in the uncommited objects tree */
			pmd_uc_lock(cinfo, cslot);
			pmd_uc_insert(cinfo, layout);
			pmd_uc_unlock(cinfo);
		} else {
			atomic_inc(&cinfo->mmi_pco_cnt.pcc_cr);
			atomic_inc(&cinfo->mmi_pco_cnt.pcc_cobj);
		}
	}

	pmd_mdc_unlock(&cinfo->mmi_compactlock);
	pmd_obj_wrunlock(layout);

	if (!err)
		pmd_update_mdc_stats(mp, layout, cinfo, PMD_OBJ_COMMIT);

	return err;
}

static void pmd_obj_erase_cb(struct work_struct *work)
{
	struct pmd_obj_erase_work  *oef;
	struct mpool_descriptor    *mp;
	struct pmd_layout          *layout;

	oef = container_of(work, struct pmd_obj_erase_work, oef_wqstruct);
	mp = oef->oef_mp;
	layout = oef->oef_layout;

	pmd_layout_erase(mp, layout);

	if (oef->oef_cache)
		kmem_cache_free(oef->oef_cache, oef);

	pmd_layout_unprovision(mp, layout);
}

static void pmd_obj_erase_start(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_obj_erase_work   oefbuf, *oef;
	bool                        async = true;

	oef = kmem_cache_zalloc(pmd_obj_erase_work_cache, GFP_KERNEL);
	if (!oef) {
		oef = &oefbuf;
		async = false;
	}

	/* If async oef will be freed in pmd_obj_erase_and_free() */
	oef->oef_mp = mp;
	oef->oef_layout = layout;
	oef->oef_cache = async ? pmd_obj_erase_work_cache : NULL;
	INIT_WORK(&oef->oef_wqstruct, pmd_obj_erase_cb);

	queue_work(mp->pds_erase_wq, &oef->oef_wqstruct);

	if (!async)
		flush_work(&oef->oef_wqstruct);
}

merr_t pmd_obj_abort(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_mdc_info    *cinfo;
	struct pmd_layout      *found;
	long                    refcnt;
	u8                      cslot;

	if (!objtype_user(objid_type(layout->eld_objid)))
		return merr(EINVAL);

	cslot = objid_slot(layout->eld_objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	found = NULL;

	pmd_obj_wrlock(layout);

	pmd_uc_lock(cinfo, cslot);
	refcnt = kref_read(&layout->eld_ref);
	if (refcnt == 2) {
		found = pmd_uc_remove(cinfo, layout);
		if (found)
			found->eld_state |= PMD_LYT_REMOVED;
	}
	pmd_uc_unlock(cinfo);

	pmd_obj_wrunlock(layout);

	if (!found)
		return merr(refcnt > 2 ? EBUSY : EINVAL);

	pmd_update_mdc_stats(mp, layout, cinfo, PMD_OBJ_ABORT);
	pmd_obj_erase_start(mp, layout);

	/* Drop caller's reference... */
	pmd_obj_put(mp, layout);

	return 0;
}

merr_t pmd_obj_delete(struct mpool_descriptor *mp, struct pmd_layout *layout)
{
	struct pmd_mdc_info    *cinfo;
	struct pmd_layout      *found;

	long    refcnt;
	u64     objid;
	u8      cslot;
	merr_t  err;

	if (!objtype_user(objid_type(layout->eld_objid)))
		return merr(EINVAL);

	objid = layout->eld_objid;
	cslot = objid_slot(objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];
	found = NULL;

	/*
	 * Must log delete record before removing object for crash recovery.
	 * Must hold cinfo.compactlock while logging delete record and
	 * removing object from the list of committed objects to prevent
	 * race with MDC compaction
	 */
	pmd_obj_wrlock(layout);
	pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);

	pmd_co_wlock(cinfo, cslot);
	refcnt = kref_read(&layout->eld_ref);
	if (refcnt == 2) {
		found = pmd_co_remove(cinfo, layout);
		if (found)
			found->eld_state |= PMD_LYT_REMOVED;
	}
	pmd_co_wunlock(cinfo);

	if (!found) {
		pmd_mdc_unlock(&cinfo->mmi_compactlock);
		pmd_obj_wrunlock(layout);

		return merr(refcnt > 2 ? EBUSY : EINVAL);
	}

	err = pmd_log_delete(mp, objid);
	if (err) {
		pmd_co_wlock(cinfo, cslot);
		pmd_co_insert(cinfo, found);
		found->eld_state &= ~PMD_LYT_REMOVED;
		found = NULL;
		pmd_co_wunlock(cinfo);
	}

	pmd_mdc_unlock(&cinfo->mmi_compactlock);
	pmd_obj_wrunlock(layout);

	if (!found) {
		mp_pr_rl("mpool %s, objid 0x%lx, pmd_log_del failed",
			 err, mp->pds_name, (ulong)objid);
		return err;
	}

	atomic_inc(&cinfo->mmi_pco_cnt.pcc_del);
	atomic_dec(&cinfo->mmi_pco_cnt.pcc_cobj);
	pmd_update_mdc_stats(mp, layout, cinfo, PMD_OBJ_DELETE);
	pmd_obj_erase_start(mp, layout);

	/* Drop caller's reference... */
	pmd_obj_put(mp, layout);

	return 0;
}

merr_t pmd_obj_erase(struct mpool_descriptor *mp, struct pmd_layout *layout, u64 gen)
{
	merr_t err;
	u64    objid = layout->eld_objid;

	if ((pmd_objid_type(objid) != OMF_OBJ_MLOG) ||
	     (!(layout->eld_state & PMD_LYT_COMMITTED)) ||
	     (layout->eld_state & PMD_LYT_REMOVED) || (gen <= layout->eld_gen)) {
		mp_pr_warn("mpool %s, object erase failed to start, objid 0x%lx state 0x%x gen %lu",
			   mp->pds_name, (ulong)objid, layout->eld_state, (ulong)gen);

		return merr(EINVAL);
	}

	/*
	 * Must log the higher gen number for the old active mlog before
	 * updating object state (layout->eld_gen of the old active mlog).
	 * It is to guarantee that a activate after crash will know which is the
	 * new active mlog.
	 */

	if (objid_mdc0log(objid)) {
		/* Compact lock is held by the caller */

		/*
		 * Change MDC0 metadata image in RAM
		 */
		if (objid == MDC0_OBJID_LOG1)
			mp->pds_sbmdc0.osb_mdc01gen = gen;
		else
			mp->pds_sbmdc0.osb_mdc02gen = gen;

		/*
		 * Write the updated MDC0 metadata in the super blocks of the
		 * drives holding MDC0 metadata.
		 * Note: for 1.0, there is only one drive.
		 */
		err = pmd_mdc0_meta_update(mp, layout);
		if (!ev(err))
			/*
			 * Update in-memory eld_gen, only if on-media
			 * gen gets successfully updated
			 */
			layout->eld_gen = gen;
	} else {
		struct pmd_mdc_info *cinfo;
		u8                   cslot;

		/*
		 * Take the MDC0 (or mlog MDCi for user MDC) compact lock to
		 * avoid a race with MDC0 (or mlog MDCi) compaction).
		 */
		cslot = objid_slot(layout->eld_objid);
		cinfo = &mp->pds_mda.mdi_slotv[cslot];

		pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);

		err = pmd_log_erase(mp, layout->eld_objid, gen);
		if (!ev(err)) {
			layout->eld_gen = gen;
			if (cslot)
				atomic_inc(&cinfo->mmi_pco_cnt.pcc_er);

		}
		pmd_mdc_unlock(&cinfo->mmi_compactlock);
	}

	return err;
}

/**
 * pmd_alloc_idgen() - generate an id for an allocated object.
 * @mp:
 * @otype:
 * @objid: outpout
 *
 * Does a round robin on the MDC1/255 avoiding the ones that are candidate
 * for pre compaction.
 *
 * The round robin has a bias toward the MDCs with the smaller number of
 * objects. This is to recover from rare and very big allocation bursts.
 * During an allocation, the MDC[s] candidate for pre compaction are avoided.
 * If the allocation is a big burst, the result is that these MDC[s] have much
 * less objects in them as compared to the other ones.
 * After the burst if a relatively constant allocation rate takes place, the
 * deficit in objects of the MDCs avoided during the burst, is never recovered.
 * The bias in the round robin allows to recover. After a while all MDCs ends
 * up again with about the same number of objects.
 */
static merr_t pmd_alloc_idgen(struct mpool_descriptor *mp, enum obj_type_omf otype, u64 *objid)
{
	struct pmd_mdc_info    *cinfo = NULL;

	merr_t  err = 0;
	u8      cslot;
	u32     tidx;

	if (mp->pds_mda.mdi_slotvcnt < 2) {
		/* No mdc available to assign object to; cannot use mdc0 */
		err = merr(ENOSPC);
		mp_pr_err("mpool %s, no MDCi with i>0", err, mp->pds_name);
		*objid = 0;
		return err;
	}

	/* Get next mdc for allocation */
	tidx = atomic_inc_return(&mp->pds_mda.mdi_sel.mds_tbl_idx) % MDC_TBL_SZ;
	assert(tidx <= MDC_TBL_SZ);

	cslot = mp->pds_mda.mdi_sel.mds_tbl[tidx];
	cinfo = &mp->pds_mda.mdi_slotv[cslot];

	pmd_mdc_lock(&cinfo->mmi_uqlock, cslot);
	*objid = objid_make(cinfo->mmi_luniq + 1, otype, cslot);
	if (objid_ckpt(*objid)) {

		/*
		 * Must checkpoint objid before assigning it to an object
		 * to guarantee it will not reissue objid after a crash.
		 * Must hold cinfo.compactlock while log checkpoint to mdc
		 * to prevent a race with mdc compaction.
		 */
		pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);
		err = pmd_log_idckpt(mp, *objid);
		if (!err)
			cinfo->mmi_lckpt = *objid;
		pmd_mdc_unlock(&cinfo->mmi_compactlock);
	}

	if (!err)
		cinfo->mmi_luniq = cinfo->mmi_luniq + 1;
	pmd_mdc_unlock(&cinfo->mmi_uqlock);

	if (ev(err)) {
		mp_pr_rl("mpool %s, checkpoint append for objid 0x%lx failed",
			 err, mp->pds_name, (ulong)*objid);
		*objid = 0;
		return err;
	}

	return 0;
}

static merr_t pmd_realloc_idvalidate(struct mpool_descriptor *mp, u64 objid)
{
	merr_t                  err = 0;
	u8                      cslot = objid_slot(objid);
	u64                     uniq = objid_uniq(objid);
	struct pmd_mdc_info    *cinfo = NULL;

	/* We never realloc objects in mdc0 */
	if (!cslot) {
		err = merr(EINVAL);
		mp_pr_err("mpool %s, can't re-allocate an object 0x%lx associated to MDC0",
			  err, mp->pds_name, (ulong)objid);
		return err;
	}

	spin_lock(&mp->pds_mda.mdi_slotvlock);
	if (cslot >= mp->pds_mda.mdi_slotvcnt)
		err = merr(EINVAL);
	spin_unlock(&mp->pds_mda.mdi_slotvlock);

	if (err) {
		mp_pr_err("mpool %s, realloc failed, slot number %u is too big %u 0x%lx",
			  err, mp->pds_name, cslot, mp->pds_mda.mdi_slotvcnt, (ulong)objid);
	} else {
		cinfo = &mp->pds_mda.mdi_slotv[cslot];
		pmd_mdc_lock(&cinfo->mmi_uqlock, cslot);
		if (uniq > cinfo->mmi_luniq)
			err = merr(EINVAL);
		pmd_mdc_unlock(&cinfo->mmi_uqlock);

		if (err) {
			mp_pr_err("mpool %s, realloc failed, unique id %lu too big %lu 0x%lx",
				  err, mp->pds_name, (ulong)uniq,
				  (ulong)cinfo->mmi_luniq, (ulong)objid);
		}
	}
	return err;
}

static merr_t
pmd_obj_alloc_cmn(
	struct mpool_descriptor    *mp,
	u64                         objid,
	enum obj_type_omf           otype,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclass,
	int                         realloc,
	bool                        needref,
	struct pmd_layout         **layoutp)
{
	struct mpool_uuid       uuid;
	struct pmd_mdc_info    *cinfo;
	struct pmd_layout      *layout;
	struct media_class     *mc;

	int     retries, flush;
	u64     zcnt = 0;
	u8      cslot;
	merr_t  err;

	*layoutp = NULL;

	err = pmd_alloc_argcheck(mp, objid, otype, ocap, mclass);
	if (ev(err))
		return err;

	if (!objid) {
		/*
		 * alloc: generate objid, checkpoint as needed to
		 * support realloc of uncommitted objects after crash and to
		 * guarantee objids never reuse
		 */
		err = pmd_alloc_idgen(mp, otype, &objid);
	} else if (realloc) {
		/* realloc: validate objid */
		err = pmd_realloc_idvalidate(mp, objid);
	}
	if (err)
		return ev(err);

	if (otype == OMF_OBJ_MLOG)
		mpool_generate_uuid(&uuid);

	/*
	 * Retry from 128 to 256ms with a flush every 1/8th of the retries.
	 * This is a workaround for the async mblock trim problem.
	 */
	retries = 1024;
	flush   = retries >> 3;

retry:
	down_read(&mp->pds_pdvlock);

	mc = &mp->pds_mc[mclass];
	if (mc->mc_pdmc < 0) {
		up_read(&mp->pds_pdvlock);
		return merr(ENOENT);
	}

	/* Calculate the height (zcnt) of layout. */
	pmd_layout_calculate(mp, ocap, mc, &zcnt, otype);

	layout = pmd_layout_alloc(mp, &uuid, objid, 0, 0, zcnt);
	if (!layout) {
		up_read(&mp->pds_pdvlock);
		return merr(ENOMEM);
	}

	/* Try to allocate zones from drives in media class */
	err = pmd_layout_provision(mp, ocap, layout, mc, zcnt);
	up_read(&mp->pds_pdvlock);

	if (err) {
		pmd_obj_put(mp, layout);

		/* TODO: Retry only if mperasewq is busy... */
		if (retries-- > 0) {
			usleep_range(128, 256);

			if (flush && (retries % flush == 0))
				flush_workqueue(mp->pds_erase_wq);

			goto retry;
		}

		mp_pr_rl("mpool %s, layout alloc failed: objid 0x%lx %lu %u",
			 err, mp->pds_name, (ulong)objid, (ulong)zcnt, otype);

		return err;
	}

	cslot = objid_slot(objid);
	cinfo = &mp->pds_mda.mdi_slotv[cslot];

	pmd_update_mdc_stats(mp, layout, cinfo, PMD_OBJ_ALLOC);

	if (needref)
		kref_get(&layout->eld_ref);

	/*
	 * If realloc, we MUST confirm (while holding the uncommited obj
	 * tree lock) that objid is not in the committed obj tree in order
	 * to protect against an invalid *_realloc() call.
	 */
	pmd_uc_lock(cinfo, cslot);
	if (realloc) {
		pmd_co_rlock(cinfo, cslot);
		if (pmd_co_find(cinfo, objid))
			err = merr(EEXIST);
		pmd_co_runlock(cinfo);
	}

	/*
	 * For both alloc and realloc, confirm that objid is not in the
	 * uncommitted obj tree and insert it.  Note that a reallocated
	 * objid can collide, but a generated objid should never collide.
	 */
	if (!err && pmd_uc_insert(cinfo, layout))
		err = merr(EEXIST);
	pmd_uc_unlock(cinfo);

	if (err) {
		mp_pr_err("mpool %s, %sallocated obj 0x%lx should not be in the %scommitted tree",
			  err, mp->pds_name, realloc ? "re-" : "",
			  (ulong)objid, realloc ? "" : "un");

		if (needref)
			pmd_obj_put(mp, layout);

		/*
		 * Since object insertion failed, we need to undo the
		 * per-mdc stats update we did earlier in this routine
		 */
		pmd_update_mdc_stats(mp, layout, cinfo, PMD_OBJ_ABORT);
		pmd_layout_unprovision(mp, layout);
		layout = NULL;
	}

	*layoutp = layout;

	return err;
}

static merr_t pmd_write_meta_to_latest_version(struct mpool_descriptor *mp, bool permitted)
{
	struct pmd_mdc_info *cinfo;
	struct pmd_mdc_info *cinfo_converted = NULL;

	char   buf1[MAX_MDCVERSTR] __maybe_unused;
	char   buf2[MAX_MDCVERSTR] __maybe_unused;
	merr_t err;
	u32    cslot;

	/*
	 * Compact MDC0 first (before MDC1-255 compaction appends in MDC0) to
	 * avoid having a potential mix of new and old records in MDC0.
	 */
	for (cslot = 0; cslot < mp->pds_mda.mdi_slotvcnt; cslot++) {
		cinfo = &mp->pds_mda.mdi_slotv[cslot];

		/*
		 * At that point the version on media should be smaller or
		 * equal to the latest version supported by this binary.
		 * If it is not the case, the activate fails earlier.
		 */
		if (omfu_mdcver_cmp(&cinfo->mmi_mdcver, "==", omfu_mdcver_cur()))
			continue;

		omfu_mdcver_to_str(&cinfo->mmi_mdcver, buf1, sizeof(buf1));
		omfu_mdcver_to_str(omfu_mdcver_cur(), buf2, sizeof(buf2));

		if (!permitted) {
			err = merr(EPERM);
			mp_pr_err("mpool %s, MDC%u upgrade needed from version %s to %s",
				  err, mp->pds_name, cslot, buf1, buf2);
			return err;
		}

		mp_pr_info("mpool %s, MDC%u upgraded from version %s to %s",
			   mp->pds_name, cslot, buf1, buf2);

		cinfo_converted = cinfo;

		pmd_mdc_lock(&cinfo->mmi_compactlock, cslot);
		err = pmd_mdc_compact(mp, cslot);
		pmd_mdc_unlock(&cinfo->mmi_compactlock);

		if (ev(err)) {
			mp_pr_err("mpool %s, failed to compact MDC %u post upgrade from %s to %s",
				  err, mp->pds_name, cslot, buf1, buf2);
			return err;
		}
	}

	if (cinfo_converted != NULL)
		mp_pr_info("mpool %s, converted MDC from version %s to %s", mp->pds_name,
			   omfu_mdcver_to_str(&cinfo_converted->mmi_mdcver, buf1, sizeof(buf1)),
			   omfu_mdcver_to_str(omfu_mdcver_cur(), buf2, sizeof(buf2)));

	return 0;
}

merr_t pmd_mdc_alloc(struct mpool_descriptor *mp, u64 mincap, u32 iter)
{
	struct pmd_obj_capacity ocap;
	enum mp_media_classp    mclassp;
	struct pmd_mdc_info    *cinfo, *cinew;
	struct pmd_layout      *layout1, *layout2;
	const char             *msg = "(no detail)";

	merr_t err;
	u64    mdcslot, logid1, logid2;
	u32    pdcnt;
	bool   reverse = false;

	/*
	 * serialize to prevent gap in mdc slot space in event of failure
	 */
	mutex_lock(&pmd_s_lock);

	/*
	 * recover previously failed mdc alloc if needed; cannot continue
	 * if fails
	 * note: there is an unlikely corner case where we logically delete an
	 * mlog from a previously failed mdc alloc but a background op is
	 * preventing its full removal; this will show up later in this
	 * fn as a failed alloc.
	 */
	err = pmd_mdc0_validate(mp, 0);
	if (err) {
		mutex_unlock(&pmd_s_lock);

		mp_pr_err("mpool %s, allocating an MDC, inconsistent MDC0", err, mp->pds_name);
		return err;
	}

	/* MDC0 exists by definition; created as part of mpool creation */
	cinfo = &mp->pds_mda.mdi_slotv[0];

	pmd_mdc_lock(&cinfo->mmi_uqlock, 0);
	mdcslot = cinfo->mmi_luniq;
	pmd_mdc_unlock(&cinfo->mmi_uqlock);

	if (mdcslot >= MDC_SLOTS - 1) {
		mutex_unlock(&pmd_s_lock);

		err = merr(ENOSPC);
		mp_pr_err("mpool %s, allocating an MDC, too many %lu",
			  err, mp->pds_name, (ulong)mdcslot);
		return err;
	}
	mdcslot = mdcslot + 1;

	/*
	 * Alloc rec buf for new mdc slot; not visible so don't need to
	 * lock fields.
	 */
	cinew = &mp->pds_mda.mdi_slotv[mdcslot];
	cinew->mmi_recbuf = kzalloc(OMF_MDCREC_PACKLEN_MAX, GFP_KERNEL);
	if (!cinew->mmi_recbuf) {
		mutex_unlock(&pmd_s_lock);

		mp_pr_warn("mpool %s, MDC%lu pack/unpack buf alloc failed %lu",
			   mp->pds_name, (ulong)mdcslot, (ulong)OMF_MDCREC_PACKLEN_MAX);
		return merr(ENOMEM);
	}
	cinew->mmi_credit.ci_slot = mdcslot;

	mclassp = MP_MED_CAPACITY;
	pdcnt = 1;

	/*
	 * Create new mdcs with same parameters and on same media class
	 * as mdc0.
	 */
	ocap.moc_captgt = mincap;
	ocap.moc_spare  = false;

	logid1 = logid_make(2 * mdcslot, 0);
	logid2 = logid_make(2 * mdcslot + 1, 0);

	if (!(pdcnt & 0x1) && ((iter * 2 / pdcnt) & 0x1)) {
		/*
		 * Reverse the allocation order.
		 * The goal is to have active mlogs on all the mpool PDs.
		 * If 2 PDs, no parity, no reserve, the active mlogs
		 * will be on PDs 0,1,0,1,0,1,0,1 etc
		 * instead of 0,0,0,0,0 etc without reversing.
		 * No need to reverse if the number of PDs is odd.
		 */
		reverse = true;
	}

	/*
	 * Each mlog must meet mincap since only one is active at a
	 * time.
	 */
	layout1 = NULL;
	err = pmd_obj_alloc_cmn(mp, reverse ? logid2 : logid1, OMF_OBJ_MLOG,
				&ocap, mclassp, 0, false, &layout1);
	if (ev(err)) {
		if (merr_errno(err) != ENOENT)
			msg = "allocation of first mlog failed";
		goto exit;
	}

	layout2 = NULL;
	err = pmd_obj_alloc_cmn(mp, reverse ? logid1 : logid2, OMF_OBJ_MLOG,
				&ocap, mclassp, 0, false, &layout2);
	if (ev(err)) {
		pmd_obj_abort(mp, layout1);
		if (merr_errno(err) != ENOENT)
			msg = "allocation of second mlog failed";
		goto exit;
	}

	/*
	 * Must erase before commit to guarantee new mdc logs start
	 * empty; mlogs not committed so pmd_obj_erase()
	 * not needed to make atomic.
	 */
	pmd_obj_wrlock(layout1);
	err = pmd_layout_erase(mp, layout1);
	pmd_obj_wrunlock(layout1);

	if (err) {
		msg = "erase of first mlog failed";
	} else {
		pmd_obj_wrlock(layout2);
		err = pmd_layout_erase(mp, layout2);
		pmd_obj_wrunlock(layout2);

		if (err)
			msg = "erase of second mlog failed";
	}
	if (ev(err)) {
		pmd_obj_abort(mp, layout1);
		pmd_obj_abort(mp, layout2);
		goto exit;
	}

	/*
	 * don't need to commit logid1 and logid2 atomically; mdc0
	 * validation deletes non-paired mdc logs to handle failing part
	 * way through this process
	 */
	err = pmd_obj_commit(mp, layout1);
	if (ev(err)) {
		pmd_obj_abort(mp, layout1);
		pmd_obj_abort(mp, layout2);
		msg = "commit of first mlog failed";
		goto exit;
	} else {
		err = pmd_obj_commit(mp, layout2);
		if (ev(err)) {
			pmd_obj_delete(mp, layout1);
			pmd_obj_abort(mp, layout2);
			msg = "commit of second mlog failed";
			goto exit;
		}
	}

	/*
	 * Finalize new mdc slot before making visible; don't need to
	 * lock fields.
	 */
	err = mp_mdc_open(mp, logid1, logid2, MDC_OF_SKIP_SER, &cinew->mmi_mdc);
	if (ev(err)) {
		msg = "mdc open failed";

		/* Failed open so just delete logid1/2; don't
		 * need to delete atomically since mdc0 validation
		 * will cleanup any detritus
		 */
		pmd_obj_delete(mp, layout1);
		pmd_obj_delete(mp, layout2);
		goto exit;
	}

	/*
	 * Append the version record.
	 */
	if (omfu_mdcver_cmp2(omfu_mdcver_cur(), ">=", 1, 0, 0, 1)) {
		err = pmd_mdc_addrec_version(mp, mdcslot);
		if (ev(err)) {
			msg = "error adding the version record";
			/*
			 * No version record in a MDC will trigger a MDC
			 * compaction if a activate is attempted later with this
			 * empty MDC.
			 * The compaction will add the version record in that
			 * empty MDC.
			 * Same error handling as above.
			 */
			pmd_obj_delete(mp, layout1);
			pmd_obj_delete(mp, layout2);
			goto exit;
		}
	}

	/* Make new mdc visible */
	pmd_mdc_lock(&cinfo->mmi_uqlock, 0);

	spin_lock(&mp->pds_mda.mdi_slotvlock);
	cinfo->mmi_luniq = mdcslot;
	mp->pds_mda.mdi_slotvcnt = mdcslot + 1;
	spin_unlock(&mp->pds_mda.mdi_slotvlock);

	pmd_mdc_unlock(&cinfo->mmi_uqlock);

exit:
	if (err) {
		kfree(cinew->mmi_recbuf);
		cinew->mmi_recbuf = NULL;
	}

	mutex_unlock(&pmd_s_lock);

	mp_pr_debug("new mdc logid1 %llu logid2 %llu",
		    0, (unsigned long long)logid1, (unsigned long long)logid2);

	if (err) {
		mp_pr_err("mpool %s, MDC%lu: %s", err, mp->pds_name, (ulong)mdcslot, msg);

	} else {
		mp_pr_debug("mpool %s, delta slotvcnt from %u to %llu", 0, mp->pds_name,
			    mp->pds_mda.mdi_slotvcnt, (unsigned long long)mdcslot + 1);

	}
	return err;
}

/**
 * pmd_mdc_alloc_set() - allocates a set of MDCs
 * @mp: mpool descriptor
 *
 * Creates MDCs in multiple of MPOOL_MDC_SET_SZ. If allocation had
 * failed in prior iteration allocate MDCs to make it even multiple
 * of MPOOL_MDC_SET_SZ.
 *
 * Locking: lock should not be held when calling this function.
 */
static void pmd_mdc_alloc_set(struct mpool_descriptor *mp)
{
	u8       mdc_cnt, sidx;
	merr_t   err;

	/*
	 * MDCs are created in multiple of MPOOL_MDC_SET_SZ.
	 * However, if past allocation had failed there may not be an
	 * even multiple of MDCs in that case create any remaining
	 * MDCs to get an even multiple.
	 */
	mdc_cnt =  MPOOL_MDC_SET_SZ - ((mp->pds_mda.mdi_slotvcnt - 1) % MPOOL_MDC_SET_SZ);

	mdc_cnt = min(mdc_cnt, (u8)(MDC_SLOTS - (mp->pds_mda.mdi_slotvcnt)));

	for (sidx = 1; sidx <= mdc_cnt; sidx++) {
		err = pmd_mdc_alloc(mp, mp->pds_params.mp_mdcncap, 0);
		if (err) {
			mp_pr_err("mpool %s, only %u of %u MDCs created",
				  err, mp->pds_name, sidx-1, mdc_cnt);

			/*
			 * For MDCN creation failure ignore the error.
			 * Attempt to create any remaining MDC next time
			 * next time new mdcs are required.
			 */
			err = 0;
			break;
		}
	}
}

/**
 * pmd_mdc0_validate() -
 * @mp:
 * @activation:
 *
 * Called during mpool activation and mdc alloc because a failed
 * mdc alloc can result in extraneous mdc mlog objects which if
 * found we attempt to clean-up here. when called during activation
 * we may need to adjust mp.mda. this is not so when called from
 * mdc alloc and in fact decreasing slotvcnt post activation would
 * violate a key invariant.
 */
static merr_t pmd_mdc0_validate(struct mpool_descriptor *mp, int activation)
{
	u8                      lcnt[MDC_SLOTS] = { 0 };
	struct pmd_mdc_info    *cinfo;
	struct pmd_layout      *layout;
	struct rb_node         *node;
	merr_t                  err = 0, err1, err2;
	u64                     mdcn, mdcmax = 0;
	u64                     logid1, logid2;
	u16                     slotvcnt;
	int                     i;

	/*
	 * Activation is single-threaded and mdc alloc is serialized
	 * so the number of active mdc (slotvcnt) will not change.
	 */
	spin_lock(&mp->pds_mda.mdi_slotvlock);
	slotvcnt = mp->pds_mda.mdi_slotvcnt;
	spin_unlock(&mp->pds_mda.mdi_slotvlock);

	if (!slotvcnt) {
		/* Must be at least mdc0 */
		err = merr(EINVAL);
		mp_pr_err("mpool %s, no MDC0", err, mp->pds_name);
		return err;
	}

	cinfo = &mp->pds_mda.mdi_slotv[0];

	pmd_co_rlock(cinfo, 0);

	pmd_co_foreach(cinfo, node) {
		layout = rb_entry(node, typeof(*layout), eld_nodemdc);

		mdcn = objid_uniq(layout->eld_objid) >> 1;
		if (mdcn < MDC_SLOTS) {
			lcnt[mdcn] = lcnt[mdcn] + 1;
			mdcmax = max(mdcmax, mdcn);
		}
		if (mdcn >= MDC_SLOTS || lcnt[mdcn] > 2 ||
		    objid_type(layout->eld_objid) != OMF_OBJ_MLOG ||
		    objid_slot(layout->eld_objid)) {
			err = merr(EINVAL);
			mp_pr_err("mpool %s, MDC0 number of MDCs %lu %u or bad otype, objid 0x%lx",
				  err, mp->pds_name, (ulong)mdcn,
				  lcnt[mdcn], (ulong)layout->eld_objid);
			break;
		}
	}

	pmd_co_runlock(cinfo);

	if (ev(err))
		return err;

	if (!mdcmax) {
		/*
		 * trivial case of mdc0 only; no mdc alloc failure to
		 * clean-up
		 */
		if (lcnt[0] != 2 || slotvcnt != 1) {
			err = merr(EINVAL);
			mp_pr_err("mpool %s, inconsistent number of MDCs or slots %d %d",
				  err, mp->pds_name, lcnt[0], slotvcnt);
			return err;
		}

		return 0;
	}

	if ((mdcmax != (slotvcnt - 1)) && mdcmax != slotvcnt) {
		err = merr(EINVAL);

		/*
		 * mdcmax is normally slotvcnt-1; can be slotvcnt if
		 * mdc alloc failed
		 */
		mp_pr_err("mpool %s, inconsistent max number of MDCs %lu %u",
			  err, mp->pds_name, (ulong)mdcmax, slotvcnt);
		return err;
	}

	/* Both logs must always exist below mdcmax */
	for (i = 0; i < mdcmax; i++) {
		if (lcnt[i] != 2) {
			err = merr(ENOENT);
			mp_pr_err("mpool %s, MDC0 missing mlogs %lu %d %u",
				  err, mp->pds_name, (ulong)mdcmax, i, lcnt[i]);
			return err;
		}
	}

	/* Clean-up from failed mdc alloc if needed */
	if (lcnt[mdcmax] != 2 || mdcmax == slotvcnt) {
		/* Note: if activation then mdcmax == slotvcnt-1 always */
		err1 = 0;
		err2 = 0;
		logid1 = logid_make(2 * mdcmax, 0);
		logid2 = logid_make(2 * mdcmax + 1, 0);

		layout = pmd_obj_find_get(mp, logid1, 1);
		if (layout) {
			err1 = pmd_obj_delete(mp, layout);
			if (err1)
				mp_pr_err("mpool %s, MDC0 %d, can't delete mlog %lu %lu %u %u",
					  err1, mp->pds_name, activation, (ulong)logid1,
					  (ulong)mdcmax, lcnt[mdcmax], slotvcnt);
		}

		layout = pmd_obj_find_get(mp, logid2, 1);
		if (layout) {
			err2 = pmd_obj_delete(mp, layout);
			if (err2)
				mp_pr_err("mpool %s, MDC0 %d, can't delete mlog %lu %lu %u %u",
					  err2, mp->pds_name, activation, (ulong)logid2,
					  (ulong)mdcmax, lcnt[mdcmax], slotvcnt);
		}

		if (activation) {
			/*
			 * Mpool activation can ignore mdc alloc clean-up
			 * failures; single-threaded; don't need slotvlock
			 * or uqlock to adjust mda
			 */
			cinfo->mmi_luniq = mdcmax - 1;
			mp->pds_mda.mdi_slotvcnt = mdcmax;
			mp_pr_warn("mpool %s, MDC0 alloc recovery: uniq %llu slotvcnt %d",
				   mp->pds_name, (unsigned long long)cinfo->mmi_luniq,
				   mp->pds_mda.mdi_slotvcnt);
		} else {
			/* MDC alloc cannot tolerate clean-up failures */
			if (err1)
				err = err1;
			else if (err2)
				err = err2;

			if (err)
				mp_pr_err("mpool %s, MDC0 alloc recovery, cleanup failed %lu %u %u",
					  err, mp->pds_name, (ulong)mdcmax, lcnt[mdcmax], slotvcnt);
			else
				mp_pr_warn("mpool %s, MDC0 alloc recovery", mp->pds_name);

		}
	}

	return err;
}

