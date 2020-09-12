/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PMD_OBJ_H
#define MPOOL_PMD_OBJ_H

#include <linux/sort.h>
#include <linux/rbtree.h>
#include <linux/kref.h>
#include <linux/rwsem.h>
#include <linux/workqueue.h>

#include "uuid.h"
#include "mpool_ioctl.h"
#include "omf_if.h"
#include "mlog.h"

struct mpool_descriptor;
struct pmd_mdc_info;

/*
 * objid uniquifier checkpoint interval; used to avoid reissuing an outstanding
 * objid after a crash; supports pmd_{mblock|mlog}_realloc()
 */
#define OBJID_UNIQ_POW2 8
#define OBJID_UNIQ_DELTA (1 << OBJID_UNIQ_POW2)

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
 * struct pmd_obj_capacity -
 * @moc_captgt:  capacity target for object in bytes
 * @moc_spare:   true, if alloc obj from spare space
 */
struct pmd_obj_capacity {
	u64    moc_captgt;
	bool   moc_spare;
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
 * Return: %0 if successful, -errno otherwise
 */
int pmd_obj_alloc(struct mpool_descriptor *mp, enum obj_type_omf otype,
		  struct pmd_obj_capacity *ocap, enum mp_media_classp mclassp,
		  struct pmd_layout **layoutp);


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
 * Return: %0 if successful; -errno otherwise
 */
int pmd_obj_realloc(struct mpool_descriptor *mp, u64 objid, struct pmd_obj_capacity *ocap,
		    enum mp_media_classp mclassp, struct pmd_layout **layoutp);


/**
 * pmd_obj_commit() - Commit an object.
 * @mp:
 * @layout:
 *
 * Make allocated object persistent; if fails object remains uncommitted so
 * can retry commit or abort; object cannot be committed while in erasing or
 * aborting state; caller MUST NOT hold pmd_obj_*lock() on layout.
 *
 * Return: %0 if successful, -errno otherwise
 */
int pmd_obj_commit(struct mpool_descriptor *mp, struct pmd_layout *layout);

/**
 * pmd_obj_abort() - Discard un-committed object.
 * @mp:
 * @layout:
 *
 * Discard uncommitted object; caller MUST NOT hold pmd_obj_*lock() on
 * layout; if successful layout is invalid after call.
 *
 * Return: %0 if successful; -errno otherwise
 */
int pmd_obj_abort(struct mpool_descriptor *mp, struct pmd_layout *layout);

/**
 * pmd_obj_delete() - Delete committed object.
 * @mp:
 * @layout:
 *
 * Delete committed object; caller MUST NOT hold pmd_obj_*lock() on layout;
 * if successful layout is invalid.
 *
 * Return: %0 if successful, -errno otherwise
 */
int pmd_obj_delete(struct mpool_descriptor *mp, struct pmd_layout *layout);

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
 * Return: %0 if successful, -errno otherwise
 */
int pmd_obj_erase(struct mpool_descriptor *mp, struct pmd_layout *layout, u64 gen);

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
 * pmd_mpool_usage() - calculate per-dataset space usage
 * @mp:
 * @usage:
 */
void pmd_mpool_usage(struct mpool_descriptor *mp, struct mpool_usage *usage);

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
 * pmd_layout_alloc() - create and initialize an pmd_layout
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
	struct mpool_uuid  *uuid,
	u64                 objid,
	u64                 gen,
	u64                 mblen,
	u32                 zcnt);

/**
 * pmd_layout_release() - free pmd_layout and internal elements
 * @layout:
 *
 * Deallocate all memory associated with object layout.
 *
 * Return: void
 */
void pmd_layout_release(struct kref *refp);

int pmd_layout_rw(struct mpool_descriptor *mp, struct pmd_layout *layout,
		  const struct kvec *iov, int iovcnt, u64 boff, int flags, u8 rw);

struct mpool_dev_info *pmd_layout_pd_get(struct mpool_descriptor *mp, struct pmd_layout *layout);

u64 pmd_layout_cap_get(struct mpool_descriptor *mp, struct pmd_layout *layout);

int pmd_layout_erase(struct mpool_descriptor *mp, struct pmd_layout *layout);

int pmd_obj_alloc_cmn(struct mpool_descriptor *mp, u64 objid, enum obj_type_omf otype,
		      struct pmd_obj_capacity *ocap, enum mp_media_classp mclass,
		      int realloc, bool needref, struct pmd_layout **layoutp);

void pmd_update_obj_stats(struct mpool_descriptor *mp, struct pmd_layout *layout,
			  struct pmd_mdc_info *cinfo, enum pmd_obj_op op);

void pmd_obj_rdlock(struct pmd_layout *layout);

void pmd_obj_rdunlock(struct pmd_layout *layout);

void pmd_obj_wrlock(struct pmd_layout *layout);

void pmd_obj_wrunlock(struct pmd_layout *layout);

void pmd_co_rlock(struct pmd_mdc_info *cinfo, u8 slot);

void pmd_co_runlock(struct pmd_mdc_info *cinfo);

struct pmd_layout *pmd_co_find(struct pmd_mdc_info *cinfo, u64 objid);

struct pmd_layout *pmd_co_insert(struct pmd_mdc_info *cinfo, struct pmd_layout *layout);

struct pmd_layout *pmd_co_remove(struct pmd_mdc_info *cinfo, struct pmd_layout *layout);

int pmd_smap_insert(struct mpool_descriptor *mp, struct pmd_layout *layout);

int pmd_init(void) __cold;
void pmd_exit(void) __cold;

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

static inline bool objid_ckpt(u64 objid)
{
	return !(objid_uniq(objid) & (OBJID_UNIQ_DELTA - 1));
}

static inline u64 logid_make(u64 uniq, u8 cslot)
{
	return objid_make(uniq, OMF_OBJ_MLOG, cslot);
}

static inline bool objid_mdc0log(u64 objid)
{
	return ((objid == MDC0_OBJID_LOG1) || (objid == MDC0_OBJID_LOG2));
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

static inline void pmd_obj_put(struct pmd_layout *layout)
{
	kref_put(&layout->eld_ref, pmd_layout_release);
}

/* General mdc locking (has external callers...) */
static inline void pmd_mdc_lock(struct mutex *lock, u8 slot)
{
	mutex_lock_nested(lock, slot > 0 ? PMD_MDC_NORMAL : PMD_MDC_ZERO);
}

static inline void pmd_mdc_unlock(struct mutex *lock)
{
	mutex_unlock(lock);
}

#endif /* MPOOL_PMD_OBJ_H */
