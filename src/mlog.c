// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/mm.h>
#include <linux/log2.h>
#include <linux/blk_types.h>
#include <asm/page.h>

#include "assert.h"
#include "mpool_printk.h"

#include "omf_if.h"
#include "mpcore.h"
#include "mlog_utils.h"

/**
 * mlog_alloc_cmn() - Allocate mlog with specified parameters using new or specified objid.
 *
 * Returns: 0 if successful, -errno otherwise
 */
static int mlog_alloc_cmn(struct mpool_descriptor *mp, u64 objid,
			  struct mlog_capacity *capreq, enum mp_media_classp mclassp,
			  struct mlog_props *prop, struct mlog_descriptor **mlh)
{
	struct pmd_obj_capacity ocap;
	struct pmd_layout *layout;
	int rc;

	layout = NULL;
	*mlh = NULL;

	ocap.moc_captgt = capreq->lcp_captgt;
	ocap.moc_spare  = capreq->lcp_spare;

	if (!objid) {
		rc = pmd_obj_alloc(mp, OMF_OBJ_MLOG, &ocap, mclassp, &layout);
		if (rc || !layout) {
			if (rc != -ENOENT)
				mp_pr_err("mpool %s, allocating mlog failed", rc, mp->pds_name);
		}
	} else {
		rc = pmd_obj_realloc(mp, objid, &ocap, mclassp, &layout);
		if (rc || !layout) {
			if (rc != -ENOENT)
				mp_pr_err("mpool %s, re-allocating mlog 0x%lx failed",
					  rc, mp->pds_name, (ulong)objid);
		}
	}
	if (rc)
		return rc;

	/*
	 * Mlogs rarely created and usually committed immediately so erase in-line;
	 * mlog not committed so pmd_obj_erase() not needed to make atomic
	 */
	pmd_obj_wrlock(layout);
	rc = pmd_layout_erase(mp, layout);
	if (!rc)
		mlog_getprops_cmn(mp, layout, prop);
	pmd_obj_wrunlock(layout);

	if (rc) {
		pmd_obj_abort(mp, layout);
		mp_pr_err("mpool %s, mlog 0x%lx alloc, erase failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	*mlh = layout2mlog(layout);

	return 0;
}

/**
 * mlog_alloc() - Allocate mlog with the capacity params specified in capreq.
 *
 * Allocate mlog with the capacity params specified in capreq on drives in a
 * media class mclassp.
 * If successful mlh is a handle for the mlog and prop contains its properties.
 *
 * Note: mlog is not persistent until committed; allocation can be aborted.
 *
 * Returns: 0 if successful, -errno otherwise
 */
int mlog_alloc(struct mpool_descriptor *mp, struct mlog_capacity *capreq,
	       enum mp_media_classp mclassp, struct mlog_props *prop,
	       struct mlog_descriptor **mlh)
{
	return mlog_alloc_cmn(mp, 0, capreq, mclassp, prop, mlh);
}


/**
 * mlog_realloc() - Allocate mlog with specified objid to support crash recovery.
 *
 * Allocate mlog with specified objid to support crash recovery; otherwise
 * is equivalent to mlog_alloc().
 *
 * Returns: 0 if successful, -errno otherwise
 * One of the possible errno values:
 * -EEXISTS - if objid exists
 */
int mlog_realloc(struct mpool_descriptor *mp, u64 objid,
		 struct mlog_capacity *capreq, enum mp_media_classp mclassp,
		 struct mlog_props *prop, struct mlog_descriptor **mlh)
{
	if (!mlog_objid(objid))
		return -EINVAL;

	return mlog_alloc_cmn(mp, objid, capreq, mclassp, prop, mlh);
}

/**
 * mlog_find_get() - Get handle and properties for existing mlog with specified objid.
 *
 * Returns: 0 if successful, -errno otherwise
 */
int mlog_find_get(struct mpool_descriptor *mp, u64 objid, int which,
		  struct mlog_props *prop, struct mlog_descriptor **mlh)
{
	struct pmd_layout *layout;

	*mlh = NULL;

	if (!mlog_objid(objid))
		return -EINVAL;

	layout = pmd_obj_find_get(mp, objid, which);
	if (!layout)
		return -ENOENT;

	if (prop) {
		pmd_obj_rdlock(layout);
		mlog_getprops_cmn(mp, layout, prop);
		pmd_obj_rdunlock(layout);
	}

	*mlh = layout2mlog(layout);

	return 0;
}

/**
 * mlog_put() - Put a reference for mlog with specified objid.
 */
void mlog_put(struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout;

	layout = mlog2layout(mlh);
	if (layout)
		pmd_obj_put(layout);
}

/**
 * mlog_lookup_rootids() - Return OIDs of mpctl root MDC.
 * @id1: (output): OID of one of the mpctl root MDC mlogs.
 * @id2: (output): OID of the other mpctl root MDC mlogs.
 */
void mlog_lookup_rootids(u64 *id1, u64 *id2)
{
	if (id1)
		*id1 = UROOT_OBJID_LOG1;

	if (id2)
		*id2 = UROOT_OBJID_LOG2;
}

/**
 * mlog_commit() - Make allocated mlog persistent.
 *
 * If fails mlog still exists in an uncommitted state so can retry commit or abort.
 *
 * Returns: 0 if successful, -errno otherwise
 */
int mlog_commit(struct mpool_descriptor *mp, struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout;

	layout = mlog2layout(mlh);
	if (!layout)
		return -EINVAL;

	return pmd_obj_commit(mp, layout);
}

/**
 * mlog_abort() - Discard uncommitted mlog; if successful mlh is invalid after call.
 *
 * Returns: 0 if successful, -errno otherwise
 */
int mlog_abort(struct mpool_descriptor *mp, struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout;

	layout = mlog2layout(mlh);
	if (!layout)
		return -EINVAL;

	return pmd_obj_abort(mp, layout);
}

/**
 * mlog_delete() - Delete committed mlog.

 * If successful mlh is invalid after call; if fails mlog is closed.
 *
 * Returns: 0 if successful, -errno otherwise
 */
int mlog_delete(struct mpool_descriptor *mp, struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout;

	layout = mlog2layout(mlh);
	if (!layout)
		return -EINVAL;

	/* Remove from open list and discard buffered log data */
	pmd_obj_wrlock(layout);
	oml_layout_lock(mp);
	oml_layout_remove(mp, layout->eld_objid);
	oml_layout_unlock(mp);

	mlog_stat_free(layout);
	pmd_obj_wrunlock(layout);

	return pmd_obj_delete(mp, layout);
}

/**
 * mlog_logrecs_validate() - Validate records in lstat.rbuf relative to lstat state.
 *
 * Validate records in lstat.rbuf relative to lstat state where midrec
 * indicates if mid data record from previous log block; updates lstate to
 * reflect valid markers found (if any).
 *
 * Returns:
 *   0 if successful; -errno otherwise
 *
 *   In the output param, i.e., midrec, we store:
 *   1 if log records are valid and ended mid data record
 *   0 if log records are valid and did NOT end mid data record
 */
static int mlog_logrecs_validate(struct mlog_stat *lstat, int *midrec, u16 rbidx, u16 lbidx)
{
	struct omf_logrec_descriptor lrd;
	u64 recnum = 0;
	int recoff;
	int rc = 0;
	char *rbuf;
	u16 sectsz = 0;

	sectsz = MLOG_SECSZ(lstat);
	rbuf   = lstat->lst_rbuf[rbidx] + lbidx * sectsz;

	recoff = omf_logblock_header_len_le(rbuf);
	if (recoff < 0)
		return -ENODATA;

	while (sectsz - recoff >= OMF_LOGREC_DESC_PACKLEN) {
		omf_logrec_desc_unpack_letoh(&lrd, &rbuf[recoff]);

		if (lrd.olr_rtype == OMF_LOGREC_CSTART) {
			if (!lstat->lst_csem || lstat->lst_rsoff || recnum) {
				rc = -ENODATA;

				/* No compaction or not first rec in first log block */
				mp_pr_err("no compact marker nor first rec %u %ld %u %u %lu",
					  rc, lstat->lst_csem, lstat->lst_rsoff,
					  rbidx, lbidx, (ulong)recnum);
				return rc;
			}
			lstat->lst_cstart = 1;
			*midrec = 0;
		} else if (lrd.olr_rtype == OMF_LOGREC_CEND) {
			if (!lstat->lst_csem || !lstat->lst_cstart || lstat->lst_cend || *midrec) {
				rc = -ENODATA;

				/*
				 * No compaction or cend before cstart or more than one cend
				 * or cend mid-record.
				 */
				mp_pr_err("inconsistent compaction recs %u %u %u %d", rc,
					  lstat->lst_csem, lstat->lst_cstart, lstat->lst_cend,
					  *midrec);
				return rc;
			}
			lstat->lst_cend = 1;
		} else if (lrd.olr_rtype == OMF_LOGREC_EOLB) {
			if (*midrec || !recnum) {
				/* EOLB mid-record or first record. */
				rc = -ENODATA;
				mp_pr_err("end of log block marker at wrong place %d %lu",
					  rc, *midrec, (ulong)recnum);
				return rc;
			}
			/* No more records in log buffer */
			break;
		} else if (lrd.olr_rtype == OMF_LOGREC_DATAFULL) {
			if (*midrec && recnum) {
				rc = -ENODATA;

				/*
				 * Can occur mid data rec only if is first rec in log block
				 * indicating partial data rec at end of last log block
				 * which is a valid failure mode; otherwise is a logging
				 * error.
				 */
				mp_pr_err("data full marker at wrong place %d %lu",
					  rc, *midrec, (ulong)recnum);
				return rc;
			}
			*midrec = 0;
		} else if (lrd.olr_rtype == OMF_LOGREC_DATAFIRST) {
			if (*midrec && recnum) {
				rc = -ENODATA;

				/* See comment for DATAFULL */
				mp_pr_err("data first marker at wrong place %d %lu",
					  rc, *midrec, (ulong)recnum);
				return rc;
			}
			*midrec = 1;
		} else if (lrd.olr_rtype == OMF_LOGREC_DATAMID) {
			if (!*midrec) {
				rc = -ENODATA;

				/* Must occur mid data record. */
				mp_pr_err("data mid marker at wrong place %d %lu",
					  rc, *midrec, (ulong)recnum);
				return rc;
			}
		} else if (lrd.olr_rtype == OMF_LOGREC_DATALAST) {
			if (!(*midrec)) {
				rc = -ENODATA;

				/* Must occur mid data record */
				mp_pr_err("data last marker at wrong place %d %lu",
					  rc, *midrec, (ulong)recnum);
				return rc;
			}
			*midrec = 0;
		} else {
			rc = -ENODATA;
			mp_pr_err("unknown record type %d %lu", rc, lrd.olr_rtype, (ulong)recnum);
			return rc;
		}

		recnum = recnum + 1;
		recoff = recoff + OMF_LOGREC_DESC_PACKLEN + lrd.olr_rlen;
	}

	return rc;
}

static inline void max_cfsetid(struct omf_logblock_header *lbh,
			       struct pmd_layout *layout, u32 *fsetid)
{
	if (!mpool_uuid_compare(&lbh->olh_magic, &layout->eld_uuid) &&
	    (lbh->olh_gen == layout->eld_gen))
		*fsetid  = max_t(u32, *fsetid, lbh->olh_cfsetid);
}

/**
 * mlog_logpage_validate() - Validate log records at log page index 'rbidx' in the read buffer.
 * @mlh:        mlog_descriptor
 * @lstat:      mlog_stat
 * @rbidx:      log page index in the read buffer to validate
 * @nseclpg:    number of sectors in the log page @rbidx
 * @midrec:     refer to mlog_logrecs_validate
 * @leol_found: true, if LEOL found. false, if LEOL not found/log full (output)
 * @fsetidmax:  maximum flush set ID found in the log (output)
 * @pfsetid:    previous flush set ID, if LEOL found (output)
 */
static int mlog_logpage_validate(struct mlog_descriptor *mlh, struct mlog_stat *lstat,
				 u16 rbidx, u16 nseclpg, int *midrec,
				 bool *leol_found, u32 *fsetidmax, u32 *pfsetid)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	char *rbuf;
	u16 lbidx;
	u16 sectsz;

	sectsz = MLOG_SECSZ(lstat);
	rbuf   = lstat->lst_rbuf[rbidx];

	/* Loop through nseclpg sectors in the log page @rbidx. */
	for (lbidx = 0; lbidx < nseclpg; lbidx++) {
		struct omf_logblock_header lbh;
		int rc;

		memset(&lbh, 0, sizeof(lbh));

		(void)omf_logblock_header_unpack_letoh(&lbh, rbuf);

		/*
		 * If LEOL is already found, then this loop determines
		 * fsetidmax, i.e., scans through the sectors to determine
		 * any stale flush set id from a prior failed CFS flush.
		 */
		if (*leol_found) {
			max_cfsetid(&lbh, layout, fsetidmax);
			rbuf += sectsz;
			continue;
		}

		/*
		 * Check for LEOL based on prev and cur flush set ID.
		 * If LEOL is detected, then no need to validate this and
		 * the log blocks that follow.
		 *
		 * We issue DISCARD commands to erase mlogs. However the data
		 * read from a discarded block is non-determinstic. It could be
		 * all 0s, all 1s or last written data.
		 *
		 * We could read following 5 types of data from mlog:
		 * 1) Garbage
		 * 2) Stale logs with different log block gen
		 * 3) Stale logs with different flushset ID
		 * 4) Stale logs with different magic (UUID)
		 * 5) Valid logs
		 */
		if (mpool_uuid_compare(&lbh.olh_magic, &layout->eld_uuid) ||
		    (lbh.olh_gen != layout->eld_gen) || (lbh.olh_pfsetid != *fsetidmax)) {
			*leol_found = true;
			*pfsetid    = *fsetidmax;
			rbuf       += sectsz;
			max_cfsetid(&lbh, layout, fsetidmax);
			continue;
		}

		*fsetidmax = lbh.olh_cfsetid;

		/* Validate the log block at lbidx. */
		rc = mlog_logrecs_validate(lstat, midrec, rbidx, lbidx);
		if (rc) {
			mp_pr_err("mlog %p,, midrec %d, log pg idx %u, sector idx %u",
				  rc, mlh, *midrec, rbidx, lbidx);

			return rc;
		}

		++lstat->lst_wsoff;
		rbuf += sectsz;
	}

	return 0;
}

/**
 * mlog_read_and_validate() - Read and validate mlog records
 * @mp:     mpool descriptor
 * @layout: layout descriptor
 * @lempty: is the log empty? (output)
 *
 * Called by mlog_open() to read and validate log records in the mlog.
 * In addition, determine the previous and current flush
 * set ID to be used by the next flush.
 *
 * Note: this function reads the entire mlog. Doing so allows us to confirm that
 * the mlog's contents are completely legit, and also to recognize the case
 * where a compaction started but failed to complete (CSTART with no CEND) -
 * for which the recovery is to use the other mlog of the mlpair.
 * If the mlog is huge, or if there are a bazillion of them, this could be an
 * issue to revisit in future performance or functionality optimizations.
 *
 * Transactional logs are expensive; this does some "extra" reading at open
 * time, with some serious benefits.
 *
 * Caller must hold the write lock on the layout, which protects the mutation
 * of the read buffer.
 */
static int mlog_read_and_validate(struct mpool_descriptor *mp,
				  struct pmd_layout *layout, bool *lempty)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	off_t leol_off = 0, rsoff;
	int midrec = 0, remsec;
	bool leol_found = false;
	bool fsetid_loop = false;
	bool skip_ser = false;
	u32 fsetidmax = 0;
	u32 pfsetid = 0;
	u16 maxsec, nsecs;
	u16 nlpgs, nseclpg;
	int rc = 0;

	remsec = MLOG_TOTSEC(lstat);
	maxsec = MLOG_NSECMB(lstat);
	rsoff  = lstat->lst_wsoff;

	while (remsec > 0) {
		u16 rbidx;

		nseclpg = MLOG_NSECLPG(lstat);
		nsecs   = min_t(u32, maxsec, remsec);

		rc = mlog_populate_rbuf(mp, layout, &nsecs, &rsoff, skip_ser);
		if (rc) {
			mp_pr_err("mpool %s, mlog 0x%lx validate failed, nsecs: %u, rsoff: 0x%lx",
				  rc, mp->pds_name, (ulong)layout->eld_objid, nsecs, rsoff);

			goto exit;
		}

		nlpgs = (nsecs + nseclpg - 1) / nseclpg;
		lstat->lst_rsoff = rsoff;

		/* Validate the read buffer, one log page at a time. */
		for (rbidx = 0; rbidx < nlpgs; rbidx++) {

			/* No. of sectors in the last log page. */
			if (rbidx == nlpgs - 1) {
				nseclpg = nsecs % nseclpg;
				nseclpg = nseclpg > 0 ? nseclpg : MLOG_NSECLPG(lstat);
			}

			/* Validate the log block(s) in the log page @rbidx. */
			rc = mlog_logpage_validate(layout2mlog(layout), lstat, rbidx, nseclpg,
						   &midrec, &leol_found, &fsetidmax, &pfsetid);
			if (rc) {
				mp_pr_err("mpool %s, mlog 0x%lx rbuf validate failed, leol: %d, fsetidmax: %u, pfsetid: %u",
					  rc, mp->pds_name, (ulong)layout->eld_objid, leol_found,
					  fsetidmax, pfsetid);

				mlog_free_rbuf(lstat, rbidx, nlpgs - 1);
				goto exit;
			}

			mlog_free_rbuf(lstat, rbidx, rbidx);

			/*
			 * If LEOL is found, then note down the LEOL offset
			 * and kick off the scan to identify any stale flush
			 * set id from a prior failed flush. If there's one,
			 * then the next flush set ID must be set one greater
			 * than the stale fsetid.
			 */
			if (leol_found && !fsetid_loop) {
				leol_off    = lstat->lst_wsoff;
				fsetid_loop = true;
			}
		}

		remsec -= nsecs;
		if (remsec == 0)
			break;
		ASSERT(remsec > 0);

		if (fsetid_loop) {
			u16    compsec;
			off_t  endoff;
			/*
			 * To determine the new flush set ID, we need to
			 * scan only through the next min(MLOG_NSECMB, remsec)
			 * sectors. This is because of the max flush size being
			 * 1 MB and hence a failed flush wouldn't have touched
			 * any sectors beyond 1 MB from LEOL.
			 */
			endoff  = rsoff + nsecs - 1;
			compsec = endoff - leol_off + 1;
			remsec  = min_t(u32, remsec, maxsec - compsec);
			ASSERT(remsec >= 0);

			rsoff = endoff + 1;
		} else {
			rsoff = lstat->lst_wsoff;
		}
	}

	/* LEOL wouldn't have been set for a full log. */
	if (!leol_found)
		pfsetid = fsetidmax;

	if (pfsetid != 0)
		*lempty = false;

	lstat->lst_pfsetid = pfsetid;
	lstat->lst_cfsetid = fsetidmax + 1;

exit:
	lstat->lst_rsoff = -1;

	return rc;
}

int mlog_open(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, u8 flags, u64 *gen)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	bool lempty, csem, skip_ser;
	int rc = 0;

	lempty = csem = skip_ser = false;
	lstat = NULL;
	*gen = 0;

	if (!layout)
		return -EINVAL;

	pmd_obj_wrlock(layout);

	flags &= MLOG_OF_SKIP_SER | MLOG_OF_COMPACT_SEM;

	if (flags & MLOG_OF_COMPACT_SEM)
		csem = true;

	if (flags & MLOG_OF_SKIP_SER)
		skip_ser = true;

	lstat = &layout->eld_lstat;

	if (lstat->lst_abuf) {
		/* Mlog already open */
		if (csem && !lstat->lst_csem) {
			pmd_obj_wrunlock(layout);

			/* Re-open has inconsistent csem flag */
			rc = -EINVAL;
			mp_pr_err("mpool %s, re-opening of mlog 0x%lx, inconsistent csem %u %u",
				  rc, mp->pds_name, (ulong)layout->eld_objid,
				  csem, lstat->lst_csem);
		} else if (skip_ser && !(layout->eld_flags & MLOG_OF_SKIP_SER)) {
			pmd_obj_wrunlock(layout);

			/* Re-open has inconsistent seralization flag */
			rc = -EINVAL;
			mp_pr_err("mpool %s, re-opening of mlog 0x%lx, inconsistent ser %u %u",
				  rc, mp->pds_name, (ulong)layout->eld_objid, skip_ser,
				  layout->eld_flags & MLOG_OF_SKIP_SER);
		} else {
			*gen = layout->eld_gen;
			pmd_obj_wrunlock(layout);
		}
		return rc;
	}

	if (!(layout->eld_state & PMD_LYT_COMMITTED)) {
		*gen = 0;
		pmd_obj_wrunlock(layout);

		rc = -EINVAL;
		mp_pr_err("mpool %s, mlog 0x%lx, not committed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	if (skip_ser)
		layout->eld_flags |= MLOG_OF_SKIP_SER;

	rc = mlog_stat_init(mp, mlh, csem);
	if (rc) {
		*gen = 0;
		pmd_obj_wrunlock(layout);

		mp_pr_err("mpool %s, mlog 0x%lx, mlog status initialization failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	lempty = true;

	rc = mlog_read_and_validate(mp, layout, &lempty);
	if (rc) {
		mlog_stat_free(layout);
		pmd_obj_wrunlock(layout);

		mp_pr_err("mpool %s, mlog 0x%lx, mlog content validation failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	} else if (!lempty && csem) {
		if (!lstat->lst_cstart) {
			mlog_stat_free(layout);
			pmd_obj_wrunlock(layout);

			rc = -ENODATA;
			mp_pr_err("mpool %s, mlog 0x%lx, compaction start missing",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
			return rc;
		} else if (!lstat->lst_cend) {
			mlog_stat_free(layout);
			pmd_obj_wrunlock(layout);

			/* Incomplete compaction */
			rc = -EMSGSIZE;
			mp_pr_err("mpool %s, mlog 0x%lx, incomplete compaction",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
			return rc;
		}
	}

	*gen = layout->eld_gen;

	/* TODO: Verify that the insert succeeded... */
	oml_layout_lock(mp);
	oml_layout_insert(mp, &layout->eld_mlpriv);
	oml_layout_unlock(mp);

	pmd_obj_wrunlock(layout);

	return rc;
}

/**
 * mlog_close() - Flush and close log and release resources; no op if log is not open.
 *
 * Returns: 0 on success; -errno otherwise
 */
int mlog_close(struct mpool_descriptor *mp, struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	bool skip_ser = false;
	int rc = 0;

	if (!layout)
		return -EINVAL;

	/*
	 * Inform pre-compaction that there is no need to try to compact
	 * an mpool MDC that would contain this mlog because it is closed.
	 */
	pmd_precompact_alsz(mp, layout->eld_objid, 0, 0);

	pmd_obj_wrlock(layout);

	lstat = &layout->eld_lstat;
	if (!lstat->lst_abuf) {
		pmd_obj_wrunlock(layout);

		return 0; /* Log already closed */
	}

	/* Flush log if potentially dirty and remove layout from open list */
	if (lstat->lst_abdirty) {
		rc = mlog_logblocks_flush(mp, layout, skip_ser);
		lstat->lst_abdirty = false;
		if (rc)
			mp_pr_err("mpool %s, mlog 0x%lx close, log block flush failed",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
	}

	oml_layout_lock(mp);
	oml_layout_remove(mp, layout->eld_objid);
	oml_layout_unlock(mp);

	mlog_stat_free(layout);

	/* Reset Mlog flags */
	layout->eld_flags &= (~MLOG_OF_SKIP_SER);

	pmd_obj_wrunlock(layout);

	return rc;
}

/**
 * mlog_gen() - Get generation number for log; log can be open or closed.
 *
 * Returns: 0 if successful; -errno otherwise
 */
int mlog_gen(struct mlog_descriptor *mlh, u64 *gen)
{
	struct pmd_layout *layout = mlog2layout(mlh);

	*gen = 0;

	if (!layout)
		return -EINVAL;

	pmd_obj_rdlock(layout);
	*gen = layout->eld_gen;
	pmd_obj_rdunlock(layout);

	return 0;
}

/**
 * mlog_empty() - Determine if log is empty; log must be open.
 *
 * Returns: 0 if successful; -errno otherwise
 */
int mlog_empty(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, bool *empty)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	int rc = 0;

	*empty = false;

	if (!layout)
		return -EINVAL;

	pmd_obj_rdlock(layout);

	lstat = &layout->eld_lstat;
	if (lstat->lst_abuf) {
		if ((!lstat->lst_wsoff &&
		     (lstat->lst_aoff == OMF_LOGBLOCK_HDR_PACKLEN)))
			*empty = true;
	} else {
		rc = -ENOENT;
	}

	pmd_obj_rdunlock(layout);

	if (rc)
		mp_pr_err("mpool %s, mlog 0x%lx empty: no mlog status",
			  rc, mp->pds_name, (ulong)layout->eld_objid);

	return rc;
}

/**
 * mlog_len() - Returns the raw mlog bytes consumed. log must be open.
 *
 * Need to account for both metadata and user bytes while computing the log length.
 */
static int mlog_len(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, u64 *len)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	int rc = 0;

	if (!layout)
		return -EINVAL;

	pmd_obj_rdlock(layout);

	lstat = &layout->eld_lstat;
	if (lstat->lst_abuf)
		*len = ((u64) lstat->lst_wsoff * MLOG_SECSZ(lstat)) + lstat->lst_aoff;
	else
		rc = -ENOENT;

	pmd_obj_rdunlock(layout);

	if (rc)
		mp_pr_err("mpool %s, mlog 0x%lx bytes consumed: no mlog status",
			  rc, mp->pds_name, (ulong)layout->eld_objid);

	return rc;
}

/**
 * mlog_erase() - Erase log setting generation number to max(current gen + 1, mingen).
 *
 * Log can be open or closed, but must be committed; operation is idempotent
 * and can be retried if fails.
 *
 * Returns: 0 on success; -errno otherwise
 */
int mlog_erase(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, u64 mingen)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat = NULL;
	u64 newgen = 0;
	int rc = 0;

	if (!layout)
		return -EINVAL;

	pmd_obj_wrlock(layout);

	/* Must be committed to log erase start/end markers */
	if (!(layout->eld_state & PMD_LYT_COMMITTED)) {
		pmd_obj_wrunlock(layout);

		rc = -EINVAL;
		mp_pr_err("mpool %s, erasing mlog 0x%lx, mlog not committed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	newgen = max(layout->eld_gen + 1, mingen);

	/* If successful updates state and gen in layout */
	rc = pmd_obj_erase(mp, layout, newgen);
	if (rc) {
		pmd_obj_wrunlock(layout);

		mp_pr_err("mpool %s, erasing mlog 0x%lx, logging erase start failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	rc = pmd_layout_erase(mp, layout);
	if (rc) {
		/*
		 * Log the failure as a debugging message, but ignore the
		 * failure, since discarding blocks here is only advisory
		 */
		mp_pr_debug("mpool %s, erasing mlog 0x%lx, erase failed ",
			    rc, mp->pds_name, (ulong)layout->eld_objid);
		rc = 0;
	}

	/* If successful updates state in layout */
	lstat = &layout->eld_lstat;
	if (lstat->lst_abuf) {
		/* Log is open so need to update lstat info */
		mlog_free_abuf(lstat, 0, lstat->lst_abidx);
		mlog_free_rbuf(lstat, 0, MLOG_NLPGMB(lstat) - 1);

		mlog_stat_init_common(layout, lstat);
	}

	pmd_obj_wrunlock(layout);

	return rc;
}

/**
 * mlog_append_marker() - Append a marker (log rec with zero-length data field) of type mtype.
 *
 * Returns: 0 on success; -errno otherwise
 * One of the possible errno values:
 * -EFBIG - if no room in log
 */
static int mlog_append_marker(struct mpool_descriptor *mp, struct pmd_layout *layout,
			      enum logrec_type_omf mtype)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	struct omf_logrec_descriptor lrd;
	u16 sectsz, abidx, aoff;
	u16 asidx, nseclpg;
	bool skip_ser = false;
	char *abuf;
	off_t lpgoff;
	int rc;

	sectsz  = MLOG_SECSZ(lstat);
	nseclpg = MLOG_NSECLPG(lstat);

	if (mlog_append_dmax(layout) == -1) {
		/* Mlog is already full, flush whatever we can */
		if (lstat->lst_abdirty) {
			(void)mlog_logblocks_flush(mp, layout, skip_ser);
			lstat->lst_abdirty = false;
		}

		return -EFBIG;
	}

	rc = mlog_update_append_idx(mp, layout, skip_ser);
	if (rc)
		return rc;

	abidx  = lstat->lst_abidx;
	abuf   = lstat->lst_abuf[abidx];
	asidx  = lstat->lst_wsoff - ((nseclpg * abidx) + lstat->lst_asoff);
	lpgoff = asidx * sectsz;
	aoff   = lstat->lst_aoff;

	lrd.olr_tlen  = 0;
	lrd.olr_rlen  = 0;
	lrd.olr_rtype = mtype;

	ASSERT(abuf != NULL);

	rc = omf_logrec_desc_pack_htole(&lrd, &abuf[lpgoff + aoff]);
	if (!rc) {
		lstat->lst_aoff = aoff + OMF_LOGREC_DESC_PACKLEN;

		rc = mlog_logblocks_flush(mp, layout, skip_ser);
		lstat->lst_abdirty = false;
		if (rc)
			mp_pr_err("mpool %s, mlog 0x%lx log block flush failed",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
	} else {
		mp_pr_err("mpool %s, mlog 0x%lx log record descriptor packing failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
	}

	return rc;
}

/**
 * mlog_append_cstart() - Append compaction start marker; log must be open with csem flag true.
 *
 * Returns: 0 on success; -errno otherwise
 * One of the possible errno values:
 * -EFBIG - if no room in log
 */
int mlog_append_cstart(struct mpool_descriptor *mp, struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	int rc = 0;

	if (!layout)
		return -EINVAL;

	pmd_obj_wrlock(layout);

	lstat = &layout->eld_lstat;
	if (!lstat->lst_abuf) {
		pmd_obj_wrunlock(layout);

		rc = -ENOENT;
		mp_pr_err("mpool %s, in mlog 0x%lx, inconsistency: no mlog status",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	if (!lstat->lst_csem || lstat->lst_cstart) {
		pmd_obj_wrunlock(layout);

		rc = -EINVAL;
		mp_pr_err("mpool %s, in mlog 0x%lx, inconsistent state %u %u",
			  rc, mp->pds_name,
			  (ulong)layout->eld_objid, lstat->lst_csem, lstat->lst_cstart);
		return rc;
	}

	rc = mlog_append_marker(mp, layout, OMF_LOGREC_CSTART);
	if (rc) {
		pmd_obj_wrunlock(layout);

		mp_pr_err("mpool %s, in mlog 0x%lx, marker append failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	lstat->lst_cstart = 1;
	pmd_obj_wrunlock(layout);

	return 0;
}

/**
 * mlog_append_cend() - Append compaction start marker; log must be open with csem flag true.
 *
 * Returns: 0 on success; -errno otherwise
 * One of the possible errno values:
 * -EFBIG - if no room in log
 */
int mlog_append_cend(struct mpool_descriptor *mp, struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	int rc = 0;

	if (!layout)
		return -EINVAL;

	pmd_obj_wrlock(layout);

	lstat = &layout->eld_lstat;
	if (!lstat->lst_abuf) {
		pmd_obj_wrunlock(layout);

		rc = -ENOENT;
		mp_pr_err("mpool %s, mlog 0x%lx, inconsistency: no mlog status",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	if (!lstat->lst_csem || !lstat->lst_cstart || lstat->lst_cend) {
		pmd_obj_wrunlock(layout);

		rc = -EINVAL;
		mp_pr_err("mpool %s, mlog 0x%lx, inconsistent state %u %u %u",
			  rc, mp->pds_name, (ulong)layout->eld_objid, lstat->lst_csem,
			  lstat->lst_cstart, lstat->lst_cend);
		return rc;
	}

	rc = mlog_append_marker(mp, layout, OMF_LOGREC_CEND);
	if (rc) {
		pmd_obj_wrunlock(layout);

		mp_pr_err("mpool %s, mlog 0x%lx, marker append failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
		return rc;
	}

	lstat->lst_cend = 1;
	pmd_obj_wrunlock(layout);

	return 0;
}

/**
 * memcpy_from_iov() - Moves contents from an iovec to one or more destination buffers.
 * @iov    : One or more source buffers in the form of an iovec
 * @buf    : Destination buffer
 * @buflen : The length of either source or destination whichever is minimum
 * @nextidx: The next index in iov if the copy requires multiple invocations
 *           of memcpy_from_iov.
 *
 * No bounds check is done on iov. The caller is expected to give the minimum
 * of source and destination buffers as the length (buflen) here.
 */
static void memcpy_from_iov(struct kvec *iov, char *buf, size_t buflen, int *nextidx)
{
	int i = *nextidx, cp;

	if ((buflen > 0) && (iov[i].iov_len == 0))
		i++;

	while (buflen > 0) {
		cp = (buflen < iov[i].iov_len) ? buflen : iov[i].iov_len;

		if (iov[i].iov_base)
			memcpy(buf, iov[i].iov_base, cp);

		iov[i].iov_len  -= cp;
		iov[i].iov_base += cp;
		buflen          -= cp;
		buf             += cp;

		if (iov[i].iov_len == 0)
			i++;
	}

	*nextidx = i;
}

/**
 * mlog_append_data_internal() - Append data record with buflen data bytes from buf.
 * @mp:       mpool descriptor
 * @mlh:      mlog descriptor
 * @iov:      iovec containing user data
 * @buflen:   length of the user buffer
 * @sync:     if true, then we do not return until data is on media
 * @skip_ser: client guarantees serialization
 *
 * Log must be open; if log opened with csem true then a compaction
 * start marker must be in place;
 *
 * Returns: 0 on success; -errno otherwise
 * One of the possible errno values:
 * -EFBIG - if no room in log
 */
static int mlog_append_data_internal(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
				     struct kvec *iov, u64 buflen, int sync, bool skip_ser)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat = &layout->eld_lstat;
	struct omf_logrec_descriptor lrd;
	int rc = 0, dfirst, cpidx;
	u32 datasec;
	u64 bufoff, rlenmax;
	u16 aoff, abidx, asidx;
	u16 nseclpg, sectsz;
	off_t lpgoff;
	char *abuf;

	mlog_extract_fsetparms(lstat, &sectsz, &datasec, NULL, &nseclpg);

	bufoff = 0;
	dfirst = 1;
	cpidx  = 0;

	lrd.olr_tlen = buflen;

	while (true) {
		if ((bufoff != buflen) && (mlog_append_dmax(layout) == -1)) {

			/* Mlog is full and there's more to write;
			 * mlog_append_dmax() should prevent this, but it lied.
			 */
			mp_pr_warn("mpool %s, mlog 0x%lx append, mlog free space incorrect",
				   mp->pds_name, (ulong)layout->eld_objid);

			return -EFBIG;
		}

		rc = mlog_update_append_idx(mp, layout, skip_ser);
		if (rc)
			return rc;

		abidx  = lstat->lst_abidx;
		abuf   = lstat->lst_abuf[abidx];
		asidx  = lstat->lst_wsoff - ((nseclpg * abidx) + lstat->lst_asoff);
		lpgoff = asidx * sectsz;
		aoff   = lstat->lst_aoff;

		ASSERT(abuf != NULL);

		rlenmax = min((u64)(sectsz - aoff - OMF_LOGREC_DESC_PACKLEN),
			      (u64)OMF_LOGREC_DESC_RLENMAX);

		if (buflen - bufoff <= rlenmax) {
			lrd.olr_rlen = buflen - bufoff;
			if (dfirst)
				lrd.olr_rtype = OMF_LOGREC_DATAFULL;
			else
				lrd.olr_rtype = OMF_LOGREC_DATALAST;
		} else {
			lrd.olr_rlen = rlenmax;
			if (dfirst) {
				lrd.olr_rtype = OMF_LOGREC_DATAFIRST;
				dfirst = 0;
			} else {
				lrd.olr_rtype = OMF_LOGREC_DATAMID;
			}
		}

		rc = omf_logrec_desc_pack_htole(&lrd, &abuf[lpgoff + aoff]);
		if (rc) {
			mp_pr_err("mpool %s, mlog 0x%lx, log record packing failed",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
			break;
		}

		lstat->lst_abdirty = true;

		aoff = aoff + OMF_LOGREC_DESC_PACKLEN;
		if (lrd.olr_rlen) {
			memcpy_from_iov(iov, &abuf[lpgoff + aoff], lrd.olr_rlen, &cpidx);
			aoff   = aoff + lrd.olr_rlen;
			bufoff = bufoff + lrd.olr_rlen;
		}
		lstat->lst_aoff = aoff;

		/*
		 * Flush log block if sync and no more to write (or)
		 * if the CFS is full.
		 */
		if ((sync && buflen == bufoff) ||
			(abidx == MLOG_NLPGMB(lstat) - 1 && asidx == nseclpg - 1 &&
			 sectsz - aoff < OMF_LOGREC_DESC_PACKLEN)) {

			rc = mlog_logblocks_flush(mp, layout, skip_ser);
			lstat->lst_abdirty = false;
			if (rc) {
				mp_pr_err("mpool %s, mlog 0x%lx, log block flush failed",
					  rc, mp->pds_name, (ulong)layout->eld_objid);
				break;
			}
		}

		ASSERT(rc == 0);

		if (bufoff == buflen)
			break;
	}

	return rc;
}

static int mlog_append_datav(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
			     struct kvec *iov, u64 buflen, int sync)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	s64 dmax = 0;
	bool skip_ser = false;
	int rc = 0;

	if (!layout)
		return -EINVAL;

	if (layout->eld_flags & MLOG_OF_SKIP_SER)
		skip_ser = true;

	if (!skip_ser)
		pmd_obj_wrlock(layout);

	lstat = &layout->eld_lstat;
	if (!lstat->lst_abuf) {
		rc = -ENOENT;
		mp_pr_err("mpool %s, mlog 0x%lx, inconsistency: no mlog status",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
	} else if (lstat->lst_csem && !lstat->lst_cstart) {
		rc = -EINVAL;
		mp_pr_err("mpool %s, mlog 0x%lx, inconsistent state %u %u", rc, mp->pds_name,
			  (ulong)layout->eld_objid, lstat->lst_csem, lstat->lst_cstart);
	} else {
		dmax = mlog_append_dmax(layout);
		if (dmax < 0 || buflen > dmax) {
			rc = -EFBIG;
			mp_pr_debug("mpool %s, mlog 0x%lx mlog full %ld",
				    rc, mp->pds_name, (ulong)layout->eld_objid, (long)dmax);

			/* Flush whatever we can. */
			if (lstat->lst_abdirty) {
				(void)mlog_logblocks_flush(mp, layout, skip_ser);
				lstat->lst_abdirty = false;
			}
		}
	}

	if (rc) {
		if (!skip_ser)
			pmd_obj_wrunlock(layout);
		return rc;
	}

	rc = mlog_append_data_internal(mp, mlh, iov, buflen, sync, skip_ser);
	if (rc) {
		mp_pr_err("mpool %s, mlog 0x%lx append failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);

		/* Flush whatever we can. */
		if (lstat->lst_abdirty) {
			(void)mlog_logblocks_flush(mp, layout, skip_ser);
			lstat->lst_abdirty = false;
		}
	}

	if (!skip_ser)
		pmd_obj_wrunlock(layout);

	return rc;
}

int mlog_append_data(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
		     char *buf, u64 buflen, int sync)
{
	struct kvec iov;

	iov.iov_base = buf;
	iov.iov_len  = buflen;

	return mlog_append_datav(mp, mlh, &iov, buflen, sync);
}

/**
 * mlog_read_data_init() - Initialize iterator for reading data records from log.
 *
 * Log must be open; skips non-data records (markers).
 *
 * Returns: 0 on success; merr_t otherwise
 */
int mlog_read_data_init(struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_stat *lstat;
	struct mlog_read_iter *lri;
	int rc = 0;

	if (!layout)
		return -EINVAL;

	pmd_obj_wrlock(layout);

	lstat = &layout->eld_lstat;
	if (!lstat->lst_abuf) {
		rc = -ENOENT;
	} else {
		lri = &lstat->lst_citr;

		mlog_read_iter_init(layout, lstat, lri);
	}

	pmd_obj_wrunlock(layout);

	return rc;
}

/**
 * mlog_read_data_next_impl() -
 * @mp:
 * @mlh:
 * @skip:
 * @buf:
 * @buflen:
 * @rdlen:
 *
 * Return:
 *   -EOVERFLOW: the caller must retry with a larger receive buffer,
 *   the length of an adequate receive buffer is returned in "rdlen".
 */
static int mlog_read_data_next_impl(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
				    bool skip, char *buf, u64 buflen, u64 *rdlen)
{
	struct omf_logrec_descriptor lrd;
	struct mlog_read_iter *lri = NULL;
	struct pmd_layout *layout;
	struct mlog_stat *lstat;

	u64 bufoff = 0, midrec = 0;
	bool recfirst = false;
	bool skip_ser = false;
	char *inbuf = NULL;
	u32 sectsz = 0;
	int rc = 0;

	layout = mlog2layout(mlh);
	if (!layout)
		return -EINVAL;

	if (!mlog_objid(layout->eld_objid))
		return -EINVAL;

	if (layout->eld_flags & MLOG_OF_SKIP_SER)
		skip_ser = true;
	/*
	 * Need write lock because loading log block to read updates lstat.
	 * Currently have no use case requiring support for concurrent readers.
	 */
	if (!skip_ser)
		pmd_obj_wrlock(layout);

	lstat = &layout->eld_lstat;
	if (lstat->lst_abuf) {
		sectsz = MLOG_SECSZ(lstat);
		lri    = &lstat->lst_citr;

		if (!lri->lri_valid) {
			if (!skip_ser)
				pmd_obj_wrunlock(layout);

			rc = -EINVAL;
			mp_pr_err("mpool %s, mlog 0x%lx, invalid iterator",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
			return rc;
		}
	}

	if (!lstat || !lri) {
		rc = -ENOENT;
		mp_pr_err("mpool %s, mlog 0x%lx, inconsistency: no mlog status",
			  rc, mp->pds_name, (ulong)layout->eld_objid);
	} else if (lri->lri_gen != layout->eld_gen ||
		   lri->lri_soff > lstat->lst_wsoff ||
		   (lri->lri_soff == lstat->lst_wsoff && lri->lri_roff > lstat->lst_aoff) ||
		   lri->lri_roff > sectsz) {

		rc = -EINVAL;
		mp_pr_err("mpool %s, mlog 0x%lx, invalid args gen %lu %lu offsets %ld %ld %u %u %u",
			  rc, mp->pds_name, (ulong)layout->eld_objid, (ulong)lri->lri_gen,
			  (ulong)layout->eld_gen, lri->lri_soff, lstat->lst_wsoff, lri->lri_roff,
			  lstat->lst_aoff, sectsz);
	} else if (lri->lri_soff == lstat->lst_wsoff && lri->lri_roff == lstat->lst_aoff) {
		/* Hit end of log - do not error count */
		rc = -ENOMSG;
	}

	if (rc) {
		if (!skip_ser)
			pmd_obj_wrunlock(layout);
		if (rc == -ENOMSG) {
			rc = 0;
			if (rdlen)
				*rdlen = 0;
		}

		return rc;
	}

	bufoff = 0;
	midrec = 0;

	while (true) {
		/* Get log block referenced by lri which can be accumulating buffer */
		rc = mlog_logblock_load(mp, lri, &inbuf, &recfirst);
		if (rc) {
			if (rc == -ENOMSG) {
				if (!skip_ser)
					pmd_obj_wrunlock(layout);
				rc = 0;
				if (rdlen)
					*rdlen = 0;

				return rc;
			}

			mp_pr_err("mpool %s, mlog 0x%lx, getting log block failed",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
			break;
		}

		if ((sectsz - lri->lri_roff) < OMF_LOGREC_DESC_PACKLEN) {
			/* No more records in current log block */
			if (lri->lri_soff < lstat->lst_wsoff) {

				/* Move to next log block */
				lri->lri_soff = lri->lri_soff + 1;
				lri->lri_roff = 0;
				continue;
			} else {
				/*
				 * hit end of log; return EOF even in case
				 * of a partial data record which is a valid
				 * failure mode and must be ignored
				 */
				if (bufoff)
					rc = -ENODATA;

				bufoff = 0;	/* Force EOF on partials! */
				break;
			}
		}

		/* Parse next record in log block */
		omf_logrec_desc_unpack_letoh(&lrd, &inbuf[lri->lri_roff]);

		if (logrec_type_datarec(lrd.olr_rtype)) {
			/* Data record */
			if (lrd.olr_rtype == OMF_LOGREC_DATAFULL ||
			    lrd.olr_rtype == OMF_LOGREC_DATAFIRST) {
				if (midrec && !recfirst) {
					rc = -ENODATA;

					/*
					 * Can occur mid data rec only if is first rec in log
					 * block indicating partial data rec at end of last
					 * block which is a valid failure mode,
					 * Otherwise is a logging error
					 */
					mp_pr_err("mpool %s, mlog 0x%lx, inconsistent 1 data rec",
						  rc, mp->pds_name, (ulong)layout->eld_objid);
					break;
				}
				/*
				 * Reset copy-out; set midrec which is needed for DATAFIRST
				 */
				bufoff = 0;
				midrec = 1;
			} else if (lrd.olr_rtype == OMF_LOGREC_DATAMID ||
				   lrd.olr_rtype == OMF_LOGREC_DATALAST) {
				if (!midrec) {
					rc = -ENODATA;

					/* Must occur mid data record. */
					mp_pr_err("mpool %s, mlog 0x%lx, inconsistent 2 data rec",
						  rc, mp->pds_name, (ulong)layout->eld_objid);
					break;
				}
			}

			/*
			 * This is inside a loop, but it is invariant;
			 * (and it cannot be done until after the unpack)
			 *
			 * Return the necessary length to caller.
			 */
			if (buflen < lrd.olr_tlen) {
				if (rdlen)
					*rdlen = lrd.olr_tlen;

				rc = -EOVERFLOW;
				break;
			}

			/* Copy-out data */
			lri->lri_roff = lri->lri_roff + OMF_LOGREC_DESC_PACKLEN;

			if (!skip)
				memcpy(&buf[bufoff], &inbuf[lri->lri_roff], lrd.olr_rlen);

			lri->lri_roff = lri->lri_roff + lrd.olr_rlen;
			bufoff = bufoff + lrd.olr_rlen;

			if (lrd.olr_rtype == OMF_LOGREC_DATAFULL ||
			    lrd.olr_rtype == OMF_LOGREC_DATALAST)
				break;
		} else {
			/*
			 * Non data record; just skip unless midrec which is a logging error
			 */
			if (midrec) {
				rc = -ENODATA;
				mp_pr_err("mpool %s, mlog 0x%lx, inconsistent non-data record",
					  rc, mp->pds_name, (ulong)layout->eld_objid);
				break;
			}
			if (lrd.olr_rtype == OMF_LOGREC_EOLB)
				lri->lri_roff = sectsz;
			else
				lri->lri_roff = lri->lri_roff + OMF_LOGREC_DESC_PACKLEN +
					lrd.olr_rlen;
		}
	}
	if (!rc && rdlen)
		*rdlen = bufoff;
	else if (rc != -EOVERFLOW && rc != -ENOMEM)
		/* Handle only remains valid if buffer too small */
		lri->lri_valid = 0;

	if (!skip_ser)
		pmd_obj_wrunlock(layout);

	return rc;
}

/**
 * mlog_read_data_next() - Read next data record into buffer buf of length buflen bytes.
 *
 * Log must be open; skips non-data records (markers).
 *
 * Iterator lri must be re-init if returns any error except ENOMEM
 * in merr_t
 *
 * Returns:
 *   0 on success; merr_t with the following errno values on failure:
 *   -EOVERFLOW if buflen is insufficient to hold data record; can retry
 *   errno otherwise
 *
 *   Bytes read on success in the output param rdlen (can be 0 if appended a
 *   zero-length data record)
 */
int mlog_read_data_next(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
			char *buf, u64 buflen, u64 *rdlen)
{
	return mlog_read_data_next_impl(mp, mlh, false, buf, buflen, rdlen);
}

/**
 * mlog_get_props() - Return basic mlog properties in prop.
 *
 * Returns: 0 if successful; merr_t otherwise
 */
static int mlog_get_props(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
			  struct mlog_props *prop)
{
	struct pmd_layout *layout = mlog2layout(mlh);

	if (!layout)
		return -EINVAL;

	pmd_obj_rdlock(layout);
	mlog_getprops_cmn(mp, layout, prop);
	pmd_obj_rdunlock(layout);

	return 0;
}

/**
 * mlog_get_props_ex() - Return extended mlog properties in prop.
 *
 * Returns: 0 if successful; merr_t otherwise
 */
int mlog_get_props_ex(struct mpool_descriptor *mp, struct mlog_descriptor  *mlh,
		      struct mlog_props_ex *prop)
{
	struct pmd_layout *layout;
	struct pd_prop *pdp;

	layout = mlog2layout(mlh);
	if (!layout)
		return -EINVAL;

	pdp = &mp->pds_pdv[layout->eld_ld.ol_pdh].pdi_prop;

	pmd_obj_rdlock(layout);
	mlog_getprops_cmn(mp, layout, &prop->lpx_props);
	prop->lpx_zonecnt  = layout->eld_ld.ol_zcnt;
	prop->lpx_state    = layout->eld_state;
	prop->lpx_secshift = PD_SECTORSZ(pdp);
	prop->lpx_totsec   = pmd_layout_cap_get(mp, layout) >> prop->lpx_secshift;
	pmd_obj_rdunlock(layout);

	return 0;
}

void mlog_precompact_alsz(struct mpool_descriptor *mp, struct mlog_descriptor *mlh)
{
	struct mlog_props prop;
	u64 len;
	int rc;

	rc = mlog_get_props(mp, mlh, &prop);
	if (rc)
		return;

	rc = mlog_len(mp, mlh, &len);
	if (rc)
		return;

	pmd_precompact_alsz(mp, prop.lpr_objid, len, prop.lpr_alloc_cap);
}
