/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PMD_H
#define MPOOL_PMD_H

#include <linux/atomic.h>
#include <linux/rbtree.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>

#include "mpool_ioctl.h"
#include "omf_if.h"
#include "pmd_obj.h"

/**
 * DOC: Module info.
 *
 * Pool metadata (pmd) module.
 *
 * Implements functions for mpool metadata management.
 *
 */

struct mpool_descriptor;
struct mpool_dev_info;
struct mp_mdc;
struct pmd_layout;
struct mpool_config;

/**
 * DOC: Object lifecycle
 *
 * +) all mblock/mlog objects are owned by mpool layer users, excepting
 *     mdc mlogs
 * +) users are responsible for object lifecycle mgmt and must not violate it;
 *    e.g. by using an object handle (layout pointer) after deleting that
 *    object
 * +) the mpool layer never independently aborts or deletes user objects
 */

/**
 * DOC: Object ids
 * Object ids for mblocks and mlogs are a unit64 of the form:
 * <uniquifier (52-bits), type (4-bits), slot # (8 bits)>
 *
 */

/**
 * DOC: NOTES
 * + metadata for a given object is stored in the mdc specified by slot #
 * + uniquifiers are only guaranteed unique for a given slot #
 * + metadata for all mdc (except mdc 0) are stored in mdc 0
 * + mdc 0 is a distinguished container whose metadata is stored in superblocks
 * + mdc 0 only stores object metadata for mdc 1-255
 * + mdc N is implemented via mlogs with objids (2N, MLOG, 0) & (2N+1, MLOG, 0)
 * + mdc 0 mlog objids are (0, MLOG, 0) and (1, MLOG, 0) where a slot # of 0
 *   indicates the mlog metadata is stored in mdc 0 whereas it is actually in
 *   superblocks; see comments in pmd_mdc0_init() for how we exploit this.
 */

/**
 * struct pre_compact_ctrs - objects records counters, used for pre compaction of MDC1/255.
 * @pcc_cr:   count of object create records
 * @pcc_up:   count of object update records
 * @pcc_del:  count of object delete records. If the object is shceduled for
 *	deletion in the background, the counter is incremented (while the
 *	delete record has not been written yet).
 * @pcc_er:   count of object erase records
 * @pcc_cobj: count of committed objects (and not deleted).
 * @pcc_cap: In bytes, size of each mlog of the MDC
 * @pcc_len: In bytes, how much is filled the active mlog.
 *
 * One such structure per mpool MDC.
 *
 * Locking:
 *	Updates are serialized by the MDC compact lock.
 *	The reads by the pre-compaction thread are done without holding any
 *	lock. This is why atomic variables are used.
 *	However because the variables are integers, the atomic read translates
 *	into a simple load and the set translate in a simple store.
 *
 * The counters pcc_up, pcc_del, pcc_er are cleared at each compaction.
 *
 * Relaxed access is appropriate for all of these atomics
 */
struct pre_compact_ctrs {
	atomic_t   pcc_cr;
	atomic_t   pcc_up;
	atomic_t   pcc_del;
	atomic_t   pcc_er;
	atomic_t   pcc_cobj;
	atomic64_t pcc_cap;
	atomic64_t pcc_len;
};

/**
 * struct credit_info - mdc selector info
 * @ci_credit:      available credit
 * @ci_free:        available free space
 * @ci_slot:        MDC slot number
 *
 * Contains information about available credit and a balance. Available
 * credit is based on an rate at which records can be written to
 * mdc such that all MDC will fill at the same time.
 */
struct credit_info  {
	u64                 ci_credit;
	u64                 ci_free;
	u8                  ci_slot;
};

/**
 * struct pmd_mdc_stats - per MDC space usage stats
 * @pms_mblock_alen: mblock alloc len
 * @pms_mblock_wlen: mblock write len
 * @pms_mlog_alen: mlog alloc len
 * @pms_mblock_cnt: mblock count
 * @pms_mlog_cnt: mlog count
 */
struct pmd_mdc_stats {
	u64    pms_mblock_alen;
	u64    pms_mblock_wlen;
	u64    pms_mlog_alen;
	u32    pms_mblock_cnt;
	u32    pms_mlog_cnt;
};

/**
 * struct pmd_mdc_info - Metadata container (mdc) info.
 * @mmi_compactlock: compaction lock
 * @mmi_uc_lock:     uncommitted objects tree lock
 * @mmi_uc_root:     uncommitted objects tree root
 * @mmi_co_lock:     committed objects tree lock
 * @mmi_co_root:     committed objects tree root
 * @mmi_uqlock:      uniquifier lock
 * @mmi_luniq:       uniquifier of last object assigned to container
 * @mmi_mdc:         MDC implementing container
 * @mmi_recbuf:      buffer for (un)packing log records
 * @mmi_lckpt:       last objid checkpointed
 * @mmi_stats:       per-MDC usage stats
 * @mmi_stats_lock:  lock for protecting mmi_stats
 * @mmi_pco_cnt:     counters used by the pre compaction of MDC1/255.
 * @mmi_mdcver:      version of the mdc content on media when the mpool was
 *                   activated. That may not be the current version on media
 *                   if a MDC metadata conversion took place during activate.
 * @mmi_credit       MDC credit info
 *
 * LOCKING:
 * + mmi_luniq: protected by uqlock
 * + mmi_mdc, recbuf, lckpt: protected by compactlock
 * + mmi_co_root: protected by co_lock
 * + mmi_uc_root: protected by uc_lock
 * + mmi_stats: protected by mmi_stats_lock
 * + mmi_pco_counters: updates serialized by mmi_compactlock
 *
 * NOTE:
 *  + for mdc0 mmi_luniq is the slot # of the last mdc created
 *  + logging to a mdc cannot execute concurrent with compacting
 *    that mdc;
 *    mmi_compactlock is used to enforce this
 *  + compacting a mdc requires freezing both the list of committed
 *    objects in that mdc and the metadata for those objects;
 *    compactlock facilitates this in a way that avoids locking each
 *    object during compaction; as a result object metadata updates
 *    are serialized, but even without mdc compaction this would be
 *    the case because all such metadata updates must be logged to
 *    the object's mdc and mdc logging is inherently serial
 *  + see struct pmd_layout comments for specifics on how
 *    compactlock is used to freeze metadata for committed objects
 *  + mmi_bgoplock protects the rec count in every committed object
 *    layout in the mdc; it is rarely used so is not a performance
 *    bottleneck and it saves memory by not having a lock per object
 */
struct pmd_mdc_info {
	struct mutex            mmi_compactlock;
	char                   *mmi_recbuf;
	u64                     mmi_lckpt;
	struct mp_mdc          *mmi_mdc;

	____cacheline_aligned
	struct mutex            mmi_uc_lock;
	struct rb_root          mmi_uc_root;

	____cacheline_aligned
	struct rw_semaphore     mmi_co_lock;
	struct rb_root          mmi_co_root;

	____cacheline_aligned
	struct mutex            mmi_uqlock;
	u64                     mmi_luniq;

	____cacheline_aligned
	struct credit_info      mmi_credit;
	struct omf_mdcver       mmi_mdcver;

	____cacheline_aligned
	struct mutex            mmi_stats_lock;
	struct pmd_mdc_stats    mmi_stats;

	struct pre_compact_ctrs mmi_pco_cnt;
};

/**
 * struct pmd_mdc_selector - Object containing MDC slots for allocation
 * @mds_tbl_idx:      idx of the MDC slot selector in the mds_tbl
 * @mds_tbl:          slot table used for MDC selection
 * @mds_mdc:          scratch pad for sorting mdc by free size
 *
 * LOCKING:
 *  + mdi_slotvlock lock will be taken to protect this object.
 *
 */
struct pmd_mdc_selector {
	atomic_t    mds_tbl_idx;
	u8          mds_tbl[MDC_TBL_SZ];
	void       *mds_smdc[MDC_SLOTS];
};

/**
 * struct pmd_mda_info - Metadata container array (mda).
 * @mdi_slotvlock:   it is assumed that this spinlock is NOT taken from interrupt context
 * @mdi_slotvcnt:    number of active slotv entries
 * @mdi_slotv:       per mdc info
 * @mdi_sel:         MDC allocation selector
 *
 * LOCKING:
 *  + mdi_slotvcnt: protected by mdi_slotvlock
 *
 * NOTE:
 *  + mdi_slotvcnt only ever increases so mdi_slotv[x], x < mdi_slotvcnt, is
 *    always active
 *  + all mdi_slotv[] entries are initialized whether or not active so they
 *    can all be accessed w/o locking except as required by pmd_mdc_info struct
 */
struct pmd_mda_info {
	spinlock_t              mdi_slotvlock;
	u16                     mdi_slotvcnt;

	struct pmd_mdc_info     mdi_slotv[MDC_SLOTS];
	struct pmd_mdc_selector mdi_sel;
};

/**
 * struct pmd_obj_load_work - work struct for loading MDC 1~N
 * @olw_work:     work struct
 * @olw_mp:
 * @olw_progress: Progress index. It is an (atomic_t *) so that multiple
 *                pmd_obj_load_work structs can point to a single atomic_t
 *                for grabbing the next MDC number to be processed.
 * @olw_err:
 */
struct pmd_obj_load_work {
	struct work_struct          olw_work;
	struct mpool_descriptor    *olw_mp;
	atomic_t                   *olw_progress; /* relaxed is correct */
	atomic_t                   *olw_err;
};

/**
 * pmd_mpool_activate() - Load all metadata for mpool mp.
 * @mp:
 * @mdc01:
 * @mdc02:
 * @create:
 *
 * Load all metadata for mpool mp; create flag indicates if is a new pool;
 * caller must ensure no other thread accesses mp until activation is complete.
 * note: pmd module owns mdc01/2 memory mgmt whether succeeds or fails
 *
 * Return: %0 if successful, -errno otherwise
 */
int pmd_mpool_activate(struct mpool_descriptor *mp, struct pmd_layout *mdc01,
		       struct pmd_layout *mdc02, int create);

/**
 * pmd_mpool_deactivate() - Deactivate mpool mp.
 * @mp:
 *
 * Free all metadata for mpool mp excepting mp itself; caller must ensure
 * no other thread can access mp during deactivation.
 */
void pmd_mpool_deactivate(struct mpool_descriptor *mp);

/**
 * pmd_mdc_alloc() - Add a metadata container to mpool.
 * @mp:
 * @mincap:
 * @iter: the role of this parameter is to get the active mlogs of the mpool
 *	MDCs uniformely spread on the mpool devices.
 *	When pmd_mdc_alloc() is called in a loop to allocate several mpool MDCs,
 *	iter should be incremented at each subsequent call.
 *
 * Add a metadata container (mdc) to mpool with a minimum capacity of mincap
 * bytes.  Once added an mdc can never be deleted.
 *
 * Return: %0 if successful, -errno otherwise
 */
int pmd_mdc_alloc(struct mpool_descriptor *mp, u64 mincap, u32 iter);

/**
 * pmd_mdc_cap() - Get metadata container (mdc) capacity stats.
 * @mp:
 * @mdcmax:
 * @mdccap:
 * @mdc0cap:
 *
 * Get metadata container (mdc) stats: count, aggregate capacity ex-mdc0 and
 * mdc0 cap
 */
void pmd_mdc_cap(struct mpool_descriptor *mp, u64 *mdcmax, u64 *mdccap, u64 *mdc0cap);

/**
 * pmd_prop_mcconfig() -
 * @mp:
 * @pd:
 * @compacting: if true, called by a compaction.
 *
 * Persist state (new or update) for drive pd; caller must hold mp.pdvlock
 * if pd is an in-use member of mp.pdv.
 *
 * Locking: caller must hold MDC0 compact lock.
 *
 * Return: %0 if successful, -errno otherwise
 */
int pmd_prop_mcconfig(struct mpool_descriptor *mp, struct mpool_dev_info *pd, bool compacting);

/**
 * pmd_prop_mcspare() -
 * @mp:
 * @mclassp:
 * @spzone:
 * @compacting: if true, called by a compaction.
 *
 * Persist spare zone info for drives in media class (new or update).
 *
 * Locking: caller must hold MDC0 compact lock.
 *
 * Return: %0 if successful, -errno otherwise
 */
int pmd_prop_mcspare(struct mpool_descriptor *mp, enum mp_media_classp mclassp,
		     u8 spzone, bool compacting);

int pmd_prop_mpconfig(struct mpool_descriptor *mp, const struct mpool_config *cfg, bool compacting);

/**
 * pmd_precompact_start() - start MDC1/255 precompaction
 * @mp:
 */
void pmd_precompact_start(struct mpool_descriptor *mp);

/**
 * pmd_precompact_stop() - stop MDC1/255 precompaction
 * @mp:
 */
void pmd_precompact_stop(struct mpool_descriptor *mp);

/**
 * pmd_mdc_addrec_version() -add a version record in a mpool MDC.
 * @mp:
 * @cslot:
 */
int pmd_mdc_addrec_version(struct mpool_descriptor *mp, u8 cslot);

int pmd_log_delete(struct mpool_descriptor *mp, u64 objid);

int pmd_log_create(struct mpool_descriptor *mp, struct pmd_layout *layout);

int pmd_log_erase(struct mpool_descriptor *mp, u64 objid, u64 gen);

int pmd_log_idckpt(struct mpool_descriptor *mp, u64 objid);

#define PMD_MDC0_COMPACTLOCK(_mp) \
	pmd_mdc_lock(&((_mp)->pds_mda.mdi_slotv[0].mmi_compactlock), 0)

#define PMD_MDC0_COMPACTUNLOCK(_mp) \
	pmd_mdc_unlock(&((_mp)->pds_mda.mdi_slotv[0].mmi_compactlock))

#endif /* MPOOL_PMD_H */
