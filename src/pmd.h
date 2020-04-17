/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PMD_PRIV_H
#define MPOOL_PMD_PRIV_H

#include <mpcore/mdc.h>

/**
 * DOC: Module info.
 *
 * Pool metadata (pmd) module.
 *
 * Implements functions for mpool metadata management.
 *
 */

enum obj_type_omf;
struct mpool_descriptor;
struct mpool_devrpt;

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


/* MDC_SLOTS is 256 [0,255] to fit in 8-bit slot field in objid.
 */
#define MDC_SLOTS           256
#define MDC_TBL_SZ          (MDC_SLOTS * 4)

#define UROOT_OBJID_LOG1 logid_make(0, 1)
#define UROOT_OBJID_LOG2 logid_make(1, 1)
#define UROOT_OBJID_MAX  1

#define MDC0_OBJID_LOG1 logid_make(0, 0)
#define MDC0_OBJID_LOG2 logid_make(1, 0)


/**
 * enum pmd_obj_op -
 * @PMD_OBJ_LOAD:
 * @PMD_OBJ_ALLOC:
 * @PMD_OBJ_COMMIT:
 * @PMD_OBJ_ABORT:
 * @PMD_OBJ_DELETE:
 */
enum pmd_obj_op {
	PMD_OBJ_LOAD     = 1,
	PMD_OBJ_ALLOC    = 2,
	PMD_OBJ_COMMIT   = 3,
	PMD_OBJ_ABORT    = 4,
	PMD_OBJ_DELETE   = 5,
};

/**
 * struct pmd_obj_capacity -
 * @moc_captgt:  capacity target for object in bytes
 * @moc_spare:   true, if alloc obj from spare space
 */
struct pmd_obj_capacity {
	u64    moc_captgt;
	bool   moc_spare;
};

/**
 * enum pmd_lock_class -
 * @PMD_NONE:
 * @PMD_OBJ_CLIENT:
 *      For layout rwlock,
 *              - Object id contains a non-zero slot number
 * @PMD_MDC_NORMAL:
 *      For layout rwlock,
 *              - Object id contains a zero slot number AND
 *              - Object id is neither of the well-known MDC-0 objids
 *      For pmd_mdc_info.* locks,
 *              - Array index of pmd_mda_info.slov[] is > 0.
 * @PMD_MDC_ZERO:
 *      For layout rwlock,
 *              - Object id contains a zero slot number AND
 *              - Object id is either of the well-known MDC-0 objids
 *      For pmd_mdc_info.* locks,
 *              - Array index of pmd_mda_info.slov[] is == 0.
 *
 * NOTE:
 * - Object layout rw locks must be acquired before any MDC locks.
 * - MDC-0 locks of a given class are below MDC-1/255 locks of those same
 *   classes.
 *
 */
enum pmd_lock_class {
	PMD_NONE       = 0,
	PMD_OBJ_CLIENT = 1,
	PMD_MDC_NORMAL = 2,
	PMD_MDC_ZERO   = 3,
};

/**
 * struct pre_compact_ctrs - objects records counters, used for
 *	pre compaction of MDC1/255.
 *	One such structure per mpool MDC.
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
 * credit is based on an rate at which records can can be written to
 * mdc such that all MDC will fill at the same time.
 */
struct credit_info  {
	u64                 ci_credit;
	u64                 ci_free;
	u8                  ci_slot;
};

/**
 * struct mdc_csm_info - mdc credit set member info
 * @m_slot:      mdc slot number
 * @ci_credit:   available credit
 */
struct mdc_csm_info {
	u8   m_slot;
	u16  m_credit;
};

/**
 * struct mdc_credit_set - mdc credit set
 * @cs_idx:      index of current credit set member
 * @cs_num_csm:  number of credit set members in this credit set
 * @cs_csm:      array of credit set members
 */
struct mdc_credit_set {
	u8                    cs_idx;
	u8                    cs_num_csm;
	struct mdc_csm_info   csm[MPOOL_MDC_SET_SZ];
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
 * @mmi_compactlock:    compaction lock
 * @mmi_uqlock:         uniquifier lock
 * @mmi_colock:         committed objid index lock
 * @mmi_uncolock:       uncommitted objid index lock
 * @mmi_reflock :       ref count lock for all obj in mdc
 * @mmi_luniq:          uniquifier of last object assigned to container
 * @mmi_mdc:            MDC implementing container
 * @mmi_recbuf:         buffer for (un)packing log records
 * @mmi_lckpt:          last objid checkpointed
 * @mmi_obj:            rbtree maps objids to committed
 *                      object layouts
 *                      node: objids_to_layouts_rb
 * @mmi_uncobj:         rbtree maps objids to un-committed
 *                      layouts node: objids_to_layouts_rb
 * @mmi_obj_nb:         number of objects in mmi_obj. Only used for debug.
 * @mmi_uncobj_nb:      number of objects in mmi_uncobj. Only used for debug.
 * @mmi_stats:          per-MDC usage stats
 * @mmi_stats_lock:     lock for protecting mmi_stats
 * @mmi_pco_cnt:        counters used by the pre compaction of MDC1/255.
 * @mmi_mdccver:        version of the mdc content on media when the mpool
 *			was activated. That may not be the current version
 *			on media if a MDC metadata conversion took place
 *			during activate.
 * @mmi_credit          MDC credit info
 *
 * LOCKING:
 * + mmi_luniq: protected by uqlock
 * + mmi_mdc, recbuf, lckpt: protected by compactlock
 * + mmi_obj: protected by colock
 * + mmi_uncobj: protected by uncolock
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
 *  + see struct ecio_layout_descriptor comments for specifics on how
 *    compactlock is used to freeze metdata for committed objects
 *  + mmi_bgoplock protects the rec count in every committed object
 *    layout in the mdc; it is rarely used so is not a performance
 *    bottleneck and it saves memory by not having a lock per object
 */
struct pmd_mdc_info {
	struct mutex            mmi_compactlock;
	struct mutex            mmi_reflock;

	struct rw_semaphore     mmi_colock;
	struct rb_root          mmi_obj;

	____cacheline_aligned
	struct mutex            mmi_uncolock;
	struct rb_root          mmi_uncobj;

	____cacheline_aligned
	struct mutex            mmi_uqlock;
	u64                     mmi_luniq;
	u64                     mmi_lckpt;
	struct mp_mdc          *mmi_mdc;
	char                   *mmi_recbuf;

	struct omf_mdccver      mmi_mdccver;
	struct credit_info      mmi_credit;

	____cacheline_aligned
	struct mutex            mmi_stats_lock;
	struct pmd_mdc_stats    mmi_stats;

	struct pre_compact_ctrs mmi_pco_cnt;
};

/**
 * struct pmd_mdc_selector - Object containing MDC slots for allocation
 *
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
 * @mdi_slotvlock:   it is assumed that this spinlock is NOT taken from
 *	interrupt context
 * @mdi_lslot:       container slot last alloced from excluding mdc0
 * @mdi_slotvcnt_shift:
 * ((mdi_slotvcnt-1) rounded up to next power of 2) == 2^mdi_slotvcnt_shift
 *	Cached here to avoid recomputing it each time ecio_objid2rwidx() is
 *	called. The -1 is to not count MDC0.
 *	If the number of existing/allocated slots among MDC1-255 is a power
 *	of 2, then it is equal to 2^mdi_slotvcnt_shift.
 * @mdi_slotvcnt:    number of active slotv entries
 * @mdi_slotv:       per mdc info
 * @mdi_sel:         MDC allocation selector
 *
 * LOCKING:
 *  + mdi_lslot, mdi_slotvcnt, mdi_slotvcnt_shift: protected by mdi_slotvlock
 *
 * NOTE:
 *  + mdi_slotvcnt only ever increases so mdi_slotv[x], x < mdi_slotvcnt, is
 *    always active
 *  + all mdi_slotv[] entries are initialized whether or not active so they
 *    can all be accessed w/o locking except as required by pmd_mdc_info struct
 */
struct pmd_mda_info {
	spinlock_t              mdi_slotvlock;
	u8                      mdi_lslot;
	u8                      mdi_slotvcnt_shift;
	u16                     mdi_slotvcnt;

	struct pmd_mdc_info     mdi_slotv[MDC_SLOTS];
	struct pmd_mdc_selector mdi_sel;
};

/**
 * struct pmd_obj_erase_work - workqueue job struct for object erase and free
 * @oef_mp:             mpool
 * @oef_layout:         object layout
 * @oef_wqstruct:	workq struct
 */
struct pmd_obj_erase_work {
	struct mpool_descriptor        *oef_mp;
	struct ecio_layout_descriptor  *oef_layout;
	struct work_struct              oef_wqstruct;
};

/**
 * struct pmd_obj_load_work - work struct for loading MDC 1~N
 * @olw_work:     work struct
 * @olw_mp:
 * @olw_progress: Progress index. It is an (atomic_t *) so that multiple
 *                pmd_obj_load_work structs can point to a single atomic_t
 *                for grabbing the next MDC number to be processed.
 * @olw_err:
 * @olw_devrpt:
 */
struct pmd_obj_load_work {
	struct work_struct          olw_work;
	struct mpool_descriptor    *olw_mp;
	atomic_t                   *olw_progress; /* relaxed is correct */
	volatile merr_t            *olw_err;
	struct mpool_devrpt         olw_devrpt;
};

/*
 * objid uniquifier checkpoint interval; used to avoid reissuing an outstanding
 * objid after a crash; supports pmd_{mblock|mlog}_realloc()
 */
#define OBJID_UNIQ_POW2 8
#define OBJID_UNIQ_DELTA (1 << OBJID_UNIQ_POW2)

static inline bool objtype_user(enum obj_type_omf otype)
{
	return (otype == OMF_OBJ_MBLOCK || otype == OMF_OBJ_MLOG);
}

static inline u64 objid_make(u64 uniq, enum obj_type_omf otype, u8 cslot)
{
	return ((uniq << 12) | ((otype & 0xF) << 8) | (cslot & 0xFF));
}

static inline u64 objid_uniq(u64 objid)
{
	return (objid >> 12);
}

static inline u8 objid_slot(u64 objid)
{
	return (objid & 0xFF);
}

static inline u64 logid_make(u64 uniq, u8 cslot)
{
	return objid_make(uniq, OMF_OBJ_MLOG, cslot);
}

static inline bool objid_mdc0log(u64 objid)
{
	return ((objid == MDC0_OBJID_LOG1) || (objid == MDC0_OBJID_LOG2));
}

static inline bool objid_ckpt(u64 objid)
{
	return !(objid_uniq(objid) & (OBJID_UNIQ_DELTA - 1));
}

static inline enum obj_type_omf pmd_objid_type(u64 objid)
{
	enum obj_type_omf otype;

	otype = objid_type(objid);
	if (!objtype_valid(otype))
		return OMF_OBJ_UNDEF;
	else
		return otype;
}

/**
 * pmd_uhandle_type() - return object type of a uhandle
 *
 * If @uhandle is a valid handle, return its type
 * If @uhandle is not a valid handle, return @OMF_OBJ_UNDEF
 */
static inline enum obj_type_omf pmd_uhandle_type(u64 uhandle)
{
	int otype = objid_type(uhandle);

	if (otype & OMF_OBJ_UHANDLE)
		return otype ^ OMF_OBJ_UHANDLE;

	return OMF_OBJ_UNDEF;
}

/* True if objid is an mpool user object (versus mpool metadata object). */
static inline bool pmd_objid_isuser(u64 objid)
{
	return objtype_user(objid_type(objid)) && objid_slot(objid);
}

/**
 * pmd_mpool_activate() - Load all metadata for mpool mp.
 * @mp:
 * @mdc01:
 * @mdc02:
 * @create:
 * @devrpt:
 * @flags: to know if mpool metadata conversion is permitted during activate.
 *
 * Load all metadata for mpool mp; create flag indicates if is a new pool;
 * caller must ensure no other thread accesses mp until activation is complete.
 * note: pmd module owns mdc01/2 memory mgmt whether succeeds or fails
 *
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_mpool_activate(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *mdc01,
	struct ecio_layout_descriptor  *mdc02,
	int                             create,
	struct mpool_devrpt            *devrpt,
	u32				flags);

/**
 * pmd_mpool_deactivate() - Deactivate mpool mp.
 * @mp:
 *
 * Free all metadata for mpool mp excepting mp itself; caller must ensure
 * no other thread can access mp during deactivation.
 */
void pmd_mpool_deactivate(struct mpool_descriptor *mp);

/**
 * pmd_obj_alloc() - Allocate an object.
 * @mp:
 * @otype:
 * @ocap:
 * @mclassp: media class
 * @olayout:
 *
 * Allocate object of type otype with parameters and capacity as specified
 * by ocap on drives in media class mclassp providing a minimum capacity of
 * mincap bytes; if successful returns object layout.
 *
 * Note:
 * Object is not persistent until committed; allocation can be aborted.
 *
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_obj_alloc(
	struct mpool_descriptor        *mp,
	enum obj_type_omf               otype,
	struct pmd_obj_capacity        *ocap,
	enum mp_media_classp            mclassp,
	struct ecio_layout_descriptor **olayout);


/**
 * pmd_obj_realloc() - Re-allocate an object.
 * @mp:
 * @objid:
 * @ocap:
 * @mclassp: media class
 * @olayout:
 *
 * Allocate object with specified objid to support crash recovery; otherwise
 * is equivalent to pmd_obj_alloc(); if successful returns object layout.
 *
 * Note:
 * Object is not persistent until committed; allocation can be aborted.
 *
 * Return: %0 if sucessful; merr_t otherwise
 */
merr_t
pmd_obj_realloc(
	struct mpool_descriptor        *mp,
	u64                             objid,
	struct pmd_obj_capacity        *ocap,
	enum mp_media_classp            mclassp,
	struct ecio_layout_descriptor **olayout);


/**
 * pmd_obj_commit() - Commit an object.
 * @mp:
 * @layout:
 *
 * Make allocated object persistent; if fails object remains uncommitted so
 * can retry commit or abort; object cannot be committed while in erasing or
 * aborting state; caller MUST NOT hold pmd_obj_*lock() on layout.
 *
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_obj_commit(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_abort() - Discard un-committed object.
 * @mp:
 * @layout:
 *
 * Discard uncommitted object; caller MUST NOT hold pmd_obj_*lock() on
 * layout; if successful layout is invalid after call.
 *
 * Return: %0 if sucessful; merr_t otherwise
 */
merr_t
pmd_obj_abort(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_delete() - Delete committed object.
 * @mp:
 * @layout:
 *
 * Delete committed object; caller MUST NOT hold pmd_obj_*lock() on layout;
 * if successful layout is invalid.
 *
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_obj_delete(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_erase() -
 * @mp:
 * @layout:
 * @gen:
 *
 * Log erase for object and set state flag and generation number
 * in layout accordingly; object must be in committed state; caller MUST hold
 * pmd_obj_wrlock() on layout.
 *
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_obj_erase(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout,
	u64                             gen);

/**
 * pmd_obj_erase_done() -
 * @mp:
 * @layout:
 *
 * Log completion of erase for object and set state flag in layout
 * accordingly; caller MUST hold pmd_obj_wrlock() on layout.
 *
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_obj_erase_done(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_get() - Get a reference on a known layout.
 * @mp:
 * @objid:
 *
 * Return: NULL on success, merr_t on failure
 */
merr_t
pmd_obj_get(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_find_get() - Get a reference for a layout for objid.
 * @mp:
 * @objid:
 *
 * Get layout for object with specified objid; return NULL either if not found
 * or if there's a dataset id mismatch.
 *
 * Return: pointer to layout if successful, NULL otherwise
 */
struct ecio_layout_descriptor *
pmd_obj_find_get(struct mpool_descriptor *mp, u64 objid);

/**
 * pmd_obj_put() - Put a reference for a layout for objid.
 * @mp:
 * @layout:
 *
 * Put a ref to a layout
 *
 * Return: pointer to layout if successful, NULL otherwise
 */
void
pmd_obj_put(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_rdlock() - Read-lock object layout with appropriate nesting level.
 * @mp:
 * @layout:
 *
 */
void
pmd_obj_rdlock(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_rdunlock() - Release read lock on object layout.
 * @mp:
 * @layout:
 *
 */
void
pmd_obj_rdunlock(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);
/**
 * pmd_obj_wrlock() - Write-lock object layout with appropriate nesting level.
 * @mp:
 * @layout:
 *
 */
void
pmd_obj_wrlock(
	struct mpool_descriptor         *mp,
	struct ecio_layout_descriptor   *layout);

/**
 * pmd_obj_wrunlock() - Release write lock on object layout.
 * @mp:
 * @layout:
 *
 */
void
pmd_obj_wrunlock(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_objid_to_uhandle()
 *
 * Convert an objid to a uhandle.
 */
u64 pmd_objid_to_uhandle(u64 objid);

/**
 * pmd_uhandle_to_objid()
 *
 * Convert an uhandle to an objid.
 */
u64 pmd_uhandle_to_objid(u64 handle);

int pmd_objid_valid(u64 objid);

int pmd_obj_uhandle_valid(u64 uhandle);


/**
 * pmd_init_credit() - udpates available credit and setup mdc selector table
 * @mp: mpool object
 *
 * Lock: No Lock required
 *
 * Used to initialize credit when new MDCs are added and add the mds to
 * available
 * credit list.
 */
void pmd_update_credit(struct mpool_descriptor *mp);

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
 * Return: %0 if successful, merr_t otherwise
 */
merr_t pmd_mdc_alloc(struct mpool_descriptor *mp, u64 mincap, u32 iter);

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
void
pmd_mdc_cap(
	struct mpool_descriptor    *mp,
	u64                        *mdcmax,
	u64                        *mdccap,
	u64                        *mdc0cap);

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
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_prop_mcconfig(
	struct mpool_descriptor *mp,
	struct mpool_dev_info   *pd,
	bool			 compacting);

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
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_prop_mcspare(
	struct mpool_descriptor *mp,
	enum mp_media_classp     mclassp,
	u8                       spzone,
	bool			 compacting);

/**
 * pmd_prop_mpconfig() -
 * @mp:
 * @cfg:
 * @compacting:
 */
merr_t
pmd_prop_mpconfig(
	struct mpool_descriptor    *mp,
	const struct mpool_config  *cfg,
	bool                        compacting);

/**
 * pmd_layout_free() -
 * @mp:
 * @layout:
 *
 * Free space map entries for layout and dealloc its memory; Handles
 * layouts where some strip descriptors have stype==UNDEF to deal with
 * failure cases where not every strip has an smap allocation.
 */
void
pmd_layout_free(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout);

/**
 * pmd_obj_alloc_cmn() -
 * @mp:
 * @objid:
 * @otype:
 * @ocap:
 * @mclassp: media class
 * @realloc:
 * @layout: output, guaranteed to be not NULL if no error returned.
 *
 * Allocate object of type otype with parameters and capacity as specified
 * by ocap on drives in media class mclassp; if objid is specified then it
 * is used to support realloc and mdc alloc; if successful returns object
 * layout.
 *
 * Return: %0 if successful, merr_t otherwise
 */
merr_t
pmd_obj_alloc_cmn(
	struct mpool_descriptor        *mp,
	u64                             objid,
	enum obj_type_omf               otype,
	struct pmd_obj_capacity        *ocap,
	enum mp_media_classp            mclassp,
	int                             realloc,
	struct ecio_layout_descriptor **layout);

/*
 * pmd_layout_shuffle_pds() -
 * @pdmc: pointer to an array of pd indices
 * @pdcnt: size of array
 *
 * Randomly shuffle an array of pd indices, such that we can
 * randomly select pd for new allocation.
 */
void pmd_layout_shuffle_pds(u16 *pdmc, u16 pdcnt);

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

/*
 * pmd_precompact_alsz() - Inform MDC1/255 pre-compacting about the active
 *	mlog of an mpool MDCi 0<i<=255.
 *	The size and how much is used are passed in.
 *	"alsz" stands for active mlog size.
 * @mp:
 * @objid: objid of the active mlog of the mpool MDCi
 * @len: In bytes, how much of the active mlog is used.
 * @cap: In bytes, size of the active mlog.
 */
void
pmd_precompact_alsz(struct mpool_descriptor *mp, u64 objid, u64 len, u64 cap);

/**
 * pmd_mpool_usage() - calculate per-dataset space usage
 * @mp:
 * @usage:
 */
void pmd_mpool_usage(struct mpool_descriptor *mp, struct mp_usage *usage);

/**
 * pmd_mdc_addrec_version() -add a version record in a mpool MDC.
 * @mp:
 * @cslot:
 */
merr_t pmd_mdc_addrec_version(struct mpool_descriptor *mp, u8 cslot);

/**
 * pmd_mdc_needed() - determines if new MDCns should be created
 * @mp: mpool descriptor
 */
bool pmd_mdc_needed(struct mpool_descriptor *mp);

void pmd_mdc_alloc_set(struct mpool_descriptor *mp);

#endif
