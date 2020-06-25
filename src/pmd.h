/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PMD_PRIV_H
#define MPOOL_PMD_PRIV_H

#include <mpcore/mpool_params.h>

#include "mlog.h"
#include "mdc.h"

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
struct pmd_layout;

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
 * enum pmd_layout_state - object state flags
 *
 * PMD_LYT_COMMITTED: object is committed to media
 * PMD_LYT_REMOVED:   object logically removed (aborted or deleted)
 */
enum pmd_layout_state {
	PMD_LYT_COMMITTED  = 0x01,
	PMD_LYT_REMOVED    = 0x02,
};

/**
 * struct pmd_layout_mlpriv - mlog private data for pmd_layout
 * @mlp_uuid:       unique ID per mlog
 * @mlp_lstat:      mlog status
 * @mlp_nodeoml:    "open mlog" rbtree linkage
 */
struct pmd_layout_mlpriv {
	struct mpool_uuid   mlp_uuid;
	struct rb_node      mlp_nodeoml;
	struct mlog_stat    mlp_lstat;
};

/**
 * union pmd_layout_priv - pmd_layout object type specific private data
 * @mlpriv: mlog private data
 */
union pmd_layout_priv {
	struct pmd_layout_mlpriv    mlpriv;
};

/**
 * struct pmd_layout - object layout (in-memory version)
 *
 * LOCKING:
 * + objid: constant; no locking required
 * + lstat: lstat and *lstat are protected by pmd_obj_*lock()
 * + all other fields: see notes
 *
 * NOTE:
 * + committed object fields (other): to update hold pmd_obj_wrlock()
 *   AND
 *   compactlock for object's mdc; to read hold pmd_obj_*lock()
 *   See the comments associated with struct pmd_mdc_info for
 *   further details.
 *
 * @eld_nodemdc: rbtree node for uncommitted and committed objects
 * @eld_objid:   object ID associated with layout
 * @eld_mblen:   Amount of data written in the mblock in bytes (0 for mlogs)
 * @eld_state:   enum pmd_layout_state
 * @eld_flags:   enum mlog_open_flags for mlogs
 * @eld_gen:     object generation
 * @eld_ld:
 * @eld_ref:     user ref count from alloc/get/put
 * @eld_rwlock:  implements pmd_obj_*lock() for this layout
 * @dle_mlpriv:  mlog private data
 *
 * eld_priv[] contains exactly one element if the object type
 * is and mlog, otherwise it contains exactly zero element.
 */
struct pmd_layout {
	struct rb_node                  eld_nodemdc;
	u64                             eld_objid;
	u32                             eld_mblen;
	u8                              eld_state;
	u8                              eld_flags;
	u64                             eld_gen;
	struct omf_layout_descriptor    eld_ld;

	/* The above fields are read-mostly, while the
	 * following two fields mutate frequently.
	 */
	struct kref                     eld_ref;
	struct rw_semaphore             eld_rwlock;

	union pmd_layout_priv           eld_priv[];
};

/* Shortcuts for mlog private data...
 */
#define eld_mlpriv      eld_priv->mlpriv
#define eld_uuid        eld_mlpriv.mlp_uuid
#define eld_lstat       eld_mlpriv.mlp_lstat
#define eld_nodeoml     eld_mlpriv.mlp_nodeoml

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
 *    compactlock is used to freeze metdata for committed objects
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
 * struct pmd_obj_erase_work - workqueue job struct for object erase and free
 * @oef_mp:             mpool
 * @oef_layout:         object layout
 * @oef_cache:          kmem cache to free work (or NULL)
 * @oef_wqstruct:	workq struct
 */
struct pmd_obj_erase_work {
	struct mpool_descriptor    *oef_mp;
	struct pmd_layout          *oef_layout;
	struct kmem_cache          *oef_cache;
	struct work_struct          oef_wqstruct;
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
	atomic64_t                 *olw_err;
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
	enum obj_type_omf otype = objid_type(objid);

	return objtype_valid(otype) ? otype : OMF_OBJ_UNDEF;
}

/* True if objid is an mpool user object (versus mpool metadata object). */
static inline bool pmd_objid_isuser(u64 objid)
{
	return objtype_user(objid_type(objid)) && objid_slot(objid);
}

/**
 * pmd_mdc_lock() - wrapper to take a lock of an mpool MDC.
 * @lock:
 * @slot:
 *
 * Nesting levels for pmd_mdc_info mutex.
 */
void pmd_mdc_lock(struct mutex *lock, u8 slot);

/**
 * pmd_mdc_unlock() - wrapper to release a lock of an mpool MDC.
 * @lock:
 */
void pmd_mdc_unlock(struct mutex *lock);

#define PMD_MDC0_COMPACTLOCK(_mp) \
	pmd_mdc_lock(&((_mp)->pds_mda.mdi_slotv[0].mmi_compactlock), 0)

#define PMD_MDC0_COMPACTUNLOCK(_mp) \
	pmd_mdc_unlock(&((_mp)->pds_mda.mdi_slotv[0].mmi_compactlock))

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
	struct mpool_descriptor    *mp,
	struct pmd_layout          *mdc01,
	struct pmd_layout          *mdc02,
	int                         create,
	struct mpool_devrpt        *devrpt,
	u32                         flags);

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
 * @layoutp:
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
	struct mpool_descriptor    *mp,
	enum obj_type_omf           otype,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclassp,
	struct pmd_layout         **layoutp);


/**
 * pmd_obj_realloc() - Re-allocate an object.
 * @mp:
 * @objid:
 * @ocap:
 * @mclassp: media class
 * @layoutp:
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
	struct mpool_descriptor    *mp,
	u64                         objid,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclassp,
	struct pmd_layout         **layoutp);


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
merr_t pmd_obj_commit(struct mpool_descriptor *mp, struct pmd_layout *layout);

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
merr_t pmd_obj_abort(struct mpool_descriptor *mp, struct pmd_layout *layout);

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
merr_t pmd_obj_delete(struct mpool_descriptor *mp, struct pmd_layout *layout);

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
merr_t pmd_obj_erase(struct mpool_descriptor *mp, struct pmd_layout *layout, u64 gen);

/**
 * pmd_obj_find_get() - Get a reference for a layout for objid.
 * @mp:
 * @objid:
 * @which:
 *
 * Get layout for object with specified objid; return NULL either if not found
 * or if there's a dataset id mismatch.
 *
 * Return: pointer to layout if successful, NULL otherwise
 */
struct pmd_layout *pmd_obj_find_get(struct mpool_descriptor *mp, u64 objid, int which);

/**
 * pmd_obj_put() - Put a reference for a layout for objid.
 * @mp:
 * @layout:
 *
 * Put a ref to a layout
 *
 * Return: pointer to layout if successful, NULL otherwise
 */
void pmd_obj_put(struct mpool_descriptor *mp, struct pmd_layout *layout);

/**
 * pmd_obj_rdlock() - Read-lock object layout with appropriate nesting level.
 * @layout:
 */
void pmd_obj_rdlock(struct pmd_layout *layout);

/**
 * pmd_obj_rdunlock() - Release read lock on object layout.
 * @layout:
 */
void pmd_obj_rdunlock(struct pmd_layout *layout);

/**
 * pmd_obj_wrlock() - Write-lock object layout with appropriate nesting level.
 * @layout:
 */
void pmd_obj_wrlock(struct pmd_layout *layout);

/**
 * pmd_obj_wrunlock() - Release write lock on object layout.
 * @layout:
 */
void pmd_obj_wrunlock(struct pmd_layout *layout);

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
 * Return: %0 if successful, merr_t otherwise
 */
merr_t pmd_prop_mcconfig(struct mpool_descriptor *mp, struct mpool_dev_info *pd, bool compacting);

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
pmd_prop_mpconfig(struct mpool_descriptor *mp, const struct mpool_config *cfg, bool compacting);

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
void pmd_precompact_alsz(struct mpool_descriptor *mp, u64 objid, u64 len, u64 cap);

/**
 * pmd_mpool_usage() - calculate per-dataset space usage
 * @mp:
 * @usage:
 */
void pmd_mpool_usage(struct mpool_descriptor *mp, struct mpool_usage *usage);

/**
 * pmd_mdc_addrec_version() -add a version record in a mpool MDC.
 * @mp:
 * @cslot:
 */
merr_t pmd_mdc_addrec_version(struct mpool_descriptor *mp, u8 cslot);

/**
 * pmd_layout_alloc() - create and initialize an pmd_layout
 * @mp:     to get the mpool uuid
 * @objid:  mblock/mlog object ID
 * @gen:    generation number
 * @mblen:  mblock written length
 * @zcnt:   number of zones in a strip
 *
 * Alloc and init object layout; non-arg fields and all strip descriptor
 * fields are set to 0/UNDEF/NONE; no auxiliary object info is allocated.
 *
 * Return: NULL if allocation fails.
 */
struct pmd_layout *
pmd_layout_alloc(
	struct mpool_descriptor    *mp,
	struct mpool_uuid          *uuid,
	u64                         objid,
	u64                         gen,
	u64                         mblen,
	u32                         zcnt);

/**
 * pmd_layout_release() - free pmd_layout and internal elements
 * @layout:
 *
 * Deallocate all memory associated with object layout.
 *
 * Return: void
 */
void pmd_layout_release(struct kref *refp);

merr_t
pmd_layout_rw(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	struct kvec                *iov,
	int                         iovcnt,
	u64                         boff,
	int                         flags,
	u8                          rw);

merr_t pmd_layout_erase(struct mpool_descriptor *mp, struct pmd_layout *layout);

u64 pmd_layout_cap_get(struct mpool_descriptor *mp, struct pmd_layout *layout);

#endif /* MPOOL_PMD_PRIV_H */
