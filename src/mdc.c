// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/slab.h>
#include <linux/string.h>

#include <mpcore/mpcore_printk.h>
#include <mpcore/mdc.h>
#include <mpcore/assert.h>
#include <mpcore/mpcore.h>
#include <mpcore/mlog.h>
#include <mpcore/qos.h>
#include <mpcore/evc.h>

#define mdc_logerr(_mpname, _msg, _mlh, _objid, _gen1, _gen2, _err)     \
	mp_pr_err("mpool %s, mdc open, %s "			        \
		  "mlog %p objid 0x%lx gen1 %lu gen2 %lu",		\
		  (_err), (_mpname), (_msg),		                \
		  (_mlh), (ulong)(_objid), (ulong)(_gen1),		\
		  (ulong)(_gen2))					\

#define OP_COMMIT      0
#define OP_DELETE      1

/**
 * mdc_acquire() - Validate mdc handle and acquire mdc_lock
 *
 * @mlh: MDC handle
 * @rw:  read/append?
 */
static inline merr_t mdc_acquire(struct mp_mdc *mdc, bool rw)
{
	if (!mdc || mdc->mdc_magic != MPC_MDC_MAGIC || !mdc->mdc_valid)
		return merr(EINVAL);

	if (rw && (mdc->mdc_flags & MDC_OF_SKIP_SER))
		return 0;

	/* Validate again after acquiring lock */
	mutex_lock(&mdc->mdc_lock);
	if (mdc->mdc_valid)
		return 0;

	mutex_unlock(&mdc->mdc_lock);

	return merr(EINVAL);
}

/**
 * mdc_release() - Release mdc_lock
 *
 * @mlh: MDC handle
 * @rw:  read/append?
 */
static inline void mdc_release(struct mp_mdc *mdc, bool rw)
{
	if (rw && (mdc->mdc_flags & MDC_OF_SKIP_SER))
		return;

	mutex_unlock(&mdc->mdc_lock);
}

/**
 * mdc_invalidate() - Invalidates MDC handle by resetting the magic
 *
 * @mdc: MDC handle
 */
static inline void mdc_invalidate(struct mp_mdc *mdc)
{
	mdc->mdc_magic = MPC_NO_MAGIC;
}

/**
 * mdc_get_mpname() - Get mpool name from mpool descriptor
 *
 * @mp:     mpool descriptor
 * @mpname: buffer to store the mpool name (output)
 * @mplen:  buffer len
 */
static merr_t
mdc_get_mpname(struct mpool_descriptor *mp, char *mpname, size_t mplen)
{
	if (!mp || !mpname)
		return merr(EINVAL);

	return mpool_get_mpname(mp, mpname, mplen);
}

/**
 * mdc_find_get() - Wrapper around get for mlog pair.
 */
static void
mdc_find_get(
	struct mpool_descriptor     *mp,
	u64                         *logid,
	bool                         do_put,
	struct mlog_props           *props,
	struct mlog_descriptor     **mlh,
	merr_t                      *ferr)
{
	merr_t err;
	int    i;

	for (i = 0; i < 2; i++) {
		ferr[i] = 0;
		err = mlog_find_get(mp, logid[i], 0, &props[i], &mlh[i]);
		if (ev(err))
			ferr[i] = err;
	}

	if (do_put && ((ferr[0] && !ferr[1]) || (ferr[1] && !ferr[0]))) {
		if (ferr[0])
			mlog_put(mp, mlh[1]);
		else
			mlog_put(mp, mlh[0]);
	}
}

/**
 * mdc_resolve() - Wrapper around resolve for mlog pair.
 */
static void
mdc_resolve(
	struct mpool_descriptor     *mp,
	u64                         *logid,
	struct mlog_props           *props,
	struct mlog_descriptor     **mlh,
	merr_t                      *ferr)
{
	merr_t err;
	int    i;

	for (i = 0; i < 2; i++) {
		ferr[i] = 0;
		err = mlog_find_get(mp, logid[i], 0, &props[i], &mlh[i]);
		if (ev(err))
			ferr[i] = err;
		else
			mlog_put(mp, mlh[i]);
	}
}


/**
 * mdc_put() - Wrapper around put for mlog pair.
 */
static merr_t
mdc_put(
	struct mpool_descriptor    *mp,
	struct mlog_descriptor     *mlh1,
	struct mlog_descriptor     *mlh2)
{
	mlog_put(mp, mlh1);
	mlog_put(mp, mlh2);

	return 0;
}

uint64_t
mp_mdc_alloc(
	struct mpool_descriptor    *mp,
	u64                        *logid1,
	u64                        *logid2,
	enum mp_media_classp        mclassp,
	const struct mdc_capacity  *capreq,
	struct mdc_props           *props)
{
	struct mlog_capacity        mlcap;
	struct mlog_props           mlprops;
	struct mlog_descriptor     *mlh[2];

	merr_t err;
	merr_t err2;
	bool   beffort;

	if (!mp || !logid1 || !logid2 || !capreq)
		return merr(EINVAL);

	if (ev(!mpool_mc_isvalid(mclassp)))
		return merr(EINVAL);

	memset(&mlcap, 0, sizeof(mlcap));
	mlcap.lcp_captgt = capreq->mdt_captgt;
	mlcap.lcp_spare  = capreq->mdt_spare;

	beffort = mpool_mc_isbe(mclassp);
	mclassp = mpool_mc_first_get(mclassp);
	assert(mclassp < MP_MED_NUMBER);

	err2 = 0;
	do {
		if (ev(err2 && ++mclassp >= MP_MED_NUMBER))
			return err2;

		err = mlog_alloc(mp, &mlcap, mclassp, &mlprops, &mlh[0]);
		if (err && (!beffort || (merr_errno(err) != ENOENT &&
					 merr_errno(err) != ENOSPC)))
			return ev(err);

		err2 = err;
		if (!err)
			*logid1 = mlprops.lpr_objid;
		else
			continue;

		err = mlog_alloc(mp, &mlcap, mclassp, &mlprops, &mlh[1]);
		if (err)
			mlog_abort(mp, mlh[0]);

		if (err && (!beffort || (merr_errno(err) != ENOENT &&
					 merr_errno(err) != ENOSPC)))
			return ev(err);

		err2 = err;
		if (!err) {
			*logid2 = mlprops.lpr_objid;
			break;
		}
	} while (beffort);

	if (props) {
		props->mdc_objid1    = *logid1;
		props->mdc_objid2    = *logid2;
		props->mdc_alloc_cap = mlprops.lpr_alloc_cap;
		props->mdc_mclassp   = mclassp;
	}

	return 0;
}

uint64_t mp_mdc_commit(struct mpool_descriptor *mp, u64 logid1, u64 logid2)
{
	struct mlog_descriptor     *mlh[2];
	struct mlog_props           props[2];

	merr_t err;
	char   mpname[MPOOL_NAME_LEN_MAX];
	u64    id[2];
	merr_t ferr[2] = {0};

	if (!mp)
		return merr(EINVAL);

	mdc_get_mpname(mp, mpname, sizeof(mpname));

	/* We already have the reference from alloc */
	id[0] = logid1;
	id[1] = logid2;
	mdc_resolve(mp, id, props, mlh, ferr);
	if (ev(ferr[0] || ferr[1]))
		return ferr[0] ? : ferr[1];

	err = mlog_commit(mp, mlh[0]);
	if (err) {
		mlog_abort(mp, mlh[0]);
		mlog_abort(mp, mlh[1]);

		return err;
	}

	err = mlog_commit(mp, mlh[1]);
	if (err) {
		mlog_delete(mp, mlh[0]);
		mlog_abort(mp, mlh[1]);

		return err;
	}

	/*
	 * Now drop the alloc reference. The calls that follow will need
	 * a get until an mdc handle is established by mp_mdc_open(). This
	 * comes from the API limitation that MDC commit and destroy operate
	 * on object IDs and not on handles. This will be cleaned in near
	 * future.
	 */
	err = mdc_put(mp, mlh[0], mlh[1]);
	if (ev(err))
		return err;

	return 0;
}

uint64_t mp_mdc_destroy(struct mpool_descriptor *mp, u64 logid1, u64 logid2)
{
	struct mlog_descriptor     *mlh[2];
	struct mlog_props           props[2];

	char   mpname[MPOOL_NAME_LEN_MAX];
	int    i;
	u64    id[2];
	merr_t ferr[2] = {0};
	merr_t rval = 0;

	if (!mp)
		return merr(EINVAL);

	mdc_get_mpname(mp, mpname, sizeof(mpname));

	/*
	 * This mdc_find_get can go away once mp_mdc_destroy is modified to
	 * operate on handles.
	 */
	id[0] = logid1;
	id[1] = logid2;
	mdc_find_get(mp, id, false, props, mlh, ferr);

	/*
	 * If mdc_find_get encountered an error for both mlogs, then return
	 * the non-ENOENT merr first.
	 */
	if (ev(ferr[0] && ferr[1]))
		return (merr_errno(ferr[0]) != ENOENT) ? ferr[0] : ferr[1];

	/*
	 * Delete uses the ref from get irrespective of whether it's called
	 * from alloc thread's context or post crash. This works today as we
	 * drop the alloc reference explicitly, post commit.
	 */
	for (i = 0; i < 2; i++) {
		merr_t err;

		if (ferr[i])
			continue;

		if (props[i].lpr_iscommitted)
			err = mlog_delete(mp, mlh[i]);
		else
			err = mlog_abort(mp, mlh[i]);

		if (err)
			rval = err;
	}

	/*
	 * If mdc_find_get encountered an error for either mlogs, then return
	 * that error.
	 */
	if (ev(ferr[0] || ferr[1]))
		return ferr[0] ?: ferr[1];

	return rval;
}

uint64_t
mp_mdc_open(
	struct mpool_descriptor     *mp,
	u64                          logid1,
	u64                          logid2,
	u8                           flags,
	struct mp_mdc              **mdc_out)
{
	struct mlog_props           props[2];
	struct mlog_descriptor     *mlh[2];
	struct mp_mdc              *mdc;

	merr_t  err = 0, err1 = 0, err2 = 0;
	u64     gen1 = 0, gen2 = 0;
	merr_t  ferr[2] = {0};
	bool    empty = false;
	u8      mlflags = 0;
	u64     id[2];
	char   *mpname;

	if (!mp || !mdc_out)
		return merr(EINVAL);

	mdc = kzalloc(sizeof(*mdc), GFP_KERNEL);
	if (!mdc)
		return merr(ENOMEM);

	mdc->mdc_valid = 0;
	mdc->mdc_mp    = mp;
	mdc_get_mpname(mp, mdc->mdc_mpname, sizeof(mdc->mdc_mpname));

	mpname = mdc->mdc_mpname;

	if (logid1 == logid2) {
		err = merr(EINVAL);
		goto exit;
	}

	/*
	 * This mdc_find_get can go away once mp_mdc_open is modified to
	 * operate on handles.
	 */
	id[0] = logid1;
	id[1] = logid2;
	mdc_find_get(mp, id, true, props, mlh, ferr);
	if (ev(ferr[0] || ferr[1])) {
		err = ferr[0] ? : ferr[1];
		goto exit;
	}
	mdc->mdc_logh1 = mlh[0];
	mdc->mdc_logh2 = mlh[1];

	if (flags & MDC_OF_SKIP_SER)
		mlflags |= MLOG_OF_SKIP_SER;

	mlflags |= MLOG_OF_COMPACT_SEM;

	err1 = mlog_open(mp, mdc->mdc_logh1, mlflags, &gen1);
	err2 = mlog_open(mp, mdc->mdc_logh2, mlflags, &gen2);

	if (ev(err1) && merr_errno(err1) != EMSGSIZE &&
	    merr_errno(err1) != EBUSY) {
		err = err1;
	} else if (ev(err2) && merr_errno(err2) != EMSGSIZE &&
		   merr_errno(err2) != EBUSY) {
		err = err2;
	} else if ((err1 && err2) ||
			(!err1 && !err2 && gen1 && gen1 == gen2)) {

		err = merr(EINVAL);

		/*
		 * bad pair; both have failed erases/compactions or equal
		 * non-0 gens
		 */
		mp_pr_err(
			"mpool %s, mdc open, bad mlog handle, mlog1 %p logid1 0x%lx errno %d gen1 %lu, mlog2 %p logid2 0x%lx errno %d gen2 %lu",
			err, mpname, mdc->mdc_logh1, (ulong)logid1,
			merr_errno(err1), (ulong)gen1, mdc->mdc_logh2,
			(ulong)logid2, merr_errno(err2), (ulong)gen2);
	} else {
		/* active log is valid log with smallest gen */
		if (err1 || (!err2 && gen2 < gen1)) {
			mdc->mdc_alogh = mdc->mdc_logh2;
			if (!err1) {
				err = mlog_empty(mp, mdc->mdc_logh1, &empty);
				if (err)
					mdc_logerr(mpname,
						   "mlog1 empty check failed",
						   mdc->mdc_logh1, logid1,
						   gen1, gen2, err);
			}
			if (!err && (err1 || !empty)) {
				err = mlog_erase(mp, mdc->mdc_logh1, gen2 + 1);
				if (!err) {
					err = mlog_open(mp, mdc->mdc_logh1,
						mlflags, &gen1);
					if (err)
						mdc_logerr(mpname,
						"mlog1 open failed",
						mdc->mdc_logh1,
						logid1, gen1, gen2, err);
				} else {
					mdc_logerr(mpname,
						"mlog1 erase failed",
						mdc->mdc_logh1,
						logid1, gen1, gen2, err);
				}
			}
		} else {
			mdc->mdc_alogh = mdc->mdc_logh1;
			if (!err2) {
				err = mlog_empty(mp, mdc->mdc_logh2, &empty);
				if (err)
					mdc_logerr(mpname,
						   "mlog2 empty check failed",
						   mdc->mdc_logh2, logid2,
						   gen1, gen2, err);
			}
			if (!err && (err2 || gen2 == gen1 || !empty)) {
				err = mlog_erase(mp, mdc->mdc_logh2, gen1 + 1);
				if (!err) {
					err = mlog_open(mp, mdc->mdc_logh2,
							mlflags, &gen2);
					if (err)
						mdc_logerr(mpname,
						"mlog2 open failed",
						mdc->mdc_logh2,
						logid2, gen1, gen2, err);
				} else {
					mdc_logerr(mpname,
						   "mlog2 erase failed",
						   mdc->mdc_logh2,
						   logid2, gen1, gen2, err);
				}
			}
		}

		if (!err) {
			err = mlog_empty(mp, mdc->mdc_alogh, &empty);
			if (!err && empty) {
				/*
				 * first use of log pair so need to add
				 * cstart/cend recs; above handles case of
				 * failure between adding cstart and cend
				 */
				err = mlog_append_cstart(mp, mdc->mdc_alogh);
				if (!err) {
					err = mlog_append_cend(mp,
							       mdc->mdc_alogh);
					if (err)
						mdc_logerr(mpname,
							   "adding cend to active mlog failed",
							   mdc->mdc_alogh,
							   mdc->mdc_alogh ==
							   mdc->mdc_logh1 ?
							   logid1 : logid2,
							   gen1, gen2, err);
				} else {
					mdc_logerr(mpname,
						   "adding cstart to active mlog failed",
						   mdc->mdc_alogh,
						   mdc->mdc_alogh ==
						   mdc->mdc_logh1 ? logid1 :
						   logid2, gen1, gen2, err);
				}

			} else if (err) {
				mdc_logerr(mpname,
					   "active mlog empty check failed",
					   mdc->mdc_alogh,
					   mdc->mdc_alogh == mdc->mdc_logh1 ?
					   logid1 : logid2, gen1, gen2, err);
			}
		}
	}

	if (!err) {
		/*
		 * Inform pre-compaction of the size of the active
		 * mlog and how much is used. This is applicable
		 * only for mpool core's internal MDCs.
		 */
		mlog_precompact_alsz(mp, mdc->mdc_alogh);

		mdc->mdc_valid = 1;
		mdc->mdc_magic = MPC_MDC_MAGIC;
		mdc->mdc_flags = flags;
		mutex_init(&mdc->mdc_lock);

		*mdc_out = mdc;
	} else {
		err1 = mlog_close(mp, mdc->mdc_logh1);
		err2 = mlog_close(mp, mdc->mdc_logh2);

		mdc_put(mp, mdc->mdc_logh1, mdc->mdc_logh2);
	}

exit:
	if (err)
		kfree(mdc);

	return err;
}

uint64_t mp_mdc_cstart(struct mp_mdc *mdc)
{
	struct mpool_descriptor    *mp;
	struct mlog_descriptor     *tgth = NULL;

	merr_t err;
	bool   rw = false;

	if (!mdc)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	mp = mdc->mdc_mp;

	if (mdc->mdc_alogh == mdc->mdc_logh1)
		tgth = mdc->mdc_logh2;
	else
		tgth = mdc->mdc_logh1;

	err = mlog_append_cstart(mp, tgth);
	if (!err) {
		mdc->mdc_alogh = tgth;
	} else {
		mdc_release(mdc, rw);

		mp_pr_err("mpool %s, mdc %p cstart failed, mlog %p",
			  err, mdc->mdc_mpname, mdc, tgth);

		(void)mp_mdc_close(mdc);

		return err;
	}

	mdc_release(mdc, rw);

	return err;
}

uint64_t mp_mdc_cend(struct mp_mdc *mdc)
{
	struct mpool_descriptor    *mp;
	struct mlog_descriptor     *srch = NULL;
	struct mlog_descriptor     *tgth = NULL;

	merr_t err;
	u64    gentgt = 0;
	bool   rw = false;

	if (!mdc)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	mp = mdc->mdc_mp;

	if (mdc->mdc_alogh == mdc->mdc_logh1) {
		tgth = mdc->mdc_logh1;
		srch = mdc->mdc_logh2;
	} else {
		tgth = mdc->mdc_logh2;
		srch = mdc->mdc_logh1;
	}

	err = mlog_append_cend(mp, tgth);
	if (!ev(err)) {
		err = mlog_gen(mp, tgth, &gentgt);
		if (!ev(err)) {
			err = mlog_erase(mp, srch, gentgt + 1);
			ev(err);
		}
	}

	if (err) {
		mdc_release(mdc, rw);

		mp_pr_err("mpool %s, mdc %p cend failed, mlog %p",
			  err, mdc->mdc_mpname, mdc, tgth);

		mp_mdc_close(mdc);

		return err;
	}

	mdc_release(mdc, rw);

	return err;
}

uint64_t mp_mdc_close(struct mp_mdc *mdc)
{
	struct mpool_descriptor   *mp;

	merr_t err = 0;
	merr_t rval = 0;
	bool   rw = false;

	if (!mdc)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	mp = mdc->mdc_mp;

	mdc->mdc_valid = 0;

	err = mlog_close(mp, mdc->mdc_logh1);
	if (err) {
		mp_pr_err("mpool %s, mdc %p close failed, mlog1 %p",
			  err, mdc->mdc_mpname, mdc, mdc->mdc_logh1);
		rval = err;
	}

	err = mlog_close(mp, mdc->mdc_logh2);
	if (err) {
		mp_pr_err("mpool %s, mdc %p close failed, mlog2 %p",
			  err, mdc->mdc_mpname, mdc, mdc->mdc_logh2);
		rval = err;
	}

	/*
	 * This mdc_put can go away once mp_mdc_open is modified to
	 * operate on handles.
	 */
	err = mdc_put(mp, mdc->mdc_logh1, mdc->mdc_logh2);
	if (ev(err)) {
		mdc_release(mdc, rw);
		return err;
	}

	mdc_invalidate(mdc);
	mdc_release(mdc, false);

	kfree(mdc);

	return rval;
}

uint64_t mp_mdc_sync(struct mp_mdc *mdc)
{
	merr_t err;
	bool   rw = false;

	if (!mdc)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	err = mlog_flush(mdc->mdc_mp, mdc->mdc_alogh);
	if (err)
		mp_pr_err("mpool %s, mdc %p sync failed, mlog %p",
			  err, mdc->mdc_mpname, mdc, mdc->mdc_alogh);

	mdc_release(mdc, rw);

	return err;
}

uint64_t mp_mdc_rewind(struct mp_mdc *mdc)
{
	merr_t err;
	bool   rw = false;

	if (!mdc)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	err = mlog_read_data_init(mdc->mdc_mp, mdc->mdc_alogh);
	if (err)
		mp_pr_err("mpool %s, mdc %p rewind failed, mlog %p",
			  err, mdc->mdc_mpname, mdc, mdc->mdc_alogh);

	mdc_release(mdc, rw);

	return err;
}

uint64_t mp_mdc_read(struct mp_mdc *mdc, void *data, size_t len, size_t *rdlen)
{
	merr_t err;
	bool   rw = true;

	if (!mdc || !data)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	err = mlog_read_data_next(mdc->mdc_mp, mdc->mdc_alogh, data,
				  (u64)len, (u64 *)rdlen);
	if ((ev(err)) && (merr_errno(err) != EOVERFLOW))
		mp_pr_err("mpool %s, mdc %p read failed, mlog %p len %lu",
			  err, mdc->mdc_mpname, mdc, mdc->mdc_alogh, len);

	mdc_release(mdc, rw);

	return err;
}

uint64_t mp_mdc_append(struct mp_mdc *mdc, void *data, ssize_t len, bool sync)
{
	merr_t err;
	bool   rw = true;

	if (!mdc || !data)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	err = mlog_append_data(mdc->mdc_mp, mdc->mdc_alogh,
			       data, (u64)len, sync);
	if (err)
		mp_pr_rl("mpool %s, mdc %p append failed, mlog %p, len %lu sync %d",
			  err, mdc->mdc_mpname, mdc,
			  mdc->mdc_alogh, len, sync);

	mdc_release(mdc, rw);

	return err;
}

uint64_t mp_mdc_usage(struct mp_mdc *mdc, size_t *usage)
{
	merr_t err;
	bool   rw = false;

	if (!mdc || !usage)
		return merr(EINVAL);

	err = mdc_acquire(mdc, rw);
	if (ev(err))
		return err;

	err = mlog_len(mdc->mdc_mp, mdc->mdc_alogh, (u64 *)usage);
	if (err)
		mp_pr_err("mpool %s, mdc %p usage failed, mlog %p",
			  err, mdc->mdc_mpname, mdc, mdc->mdc_alogh);

	mdc_release(mdc, rw);

	return err;
}
