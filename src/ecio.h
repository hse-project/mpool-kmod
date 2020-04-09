/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Erasure coded I/O (ecio) module.
 *
 * Defines functions for reading, writing, and repairing mlogs and mblocks.
 *
 */
#ifndef MPOOL_ECIO_PRIV_H
#define MPOOL_ECIO_PRIV_H

#include "pd.h"

struct mlog_stat;
struct ecio_layout_descriptor;

/*
 * Common defs
 */

/*
 * enum ecio_layout_state - object state flags
 *
 * ECIO_LYT_NONE:      no flags set
 * ECIO_LYT_COMMITTED: object is committed to media
 * ECIO_LYT_REMOVED:   object logically removed (aborted or deleted)
 */
enum ecio_layout_state {
	ECIO_LYT_NONE       = 0,
	ECIO_LYT_COMMITTED  = 1,
	ECIO_LYT_REMOVED    = 2,
};

/*
 * struct ecio_layout_mlo - information used only by mlog objects.
 * "mlo" = mlog only
 * @mlo_lstat:   mlog status
 * @mlo_pcs:     Performance counter set instance, family "MLOG"
 * @mlo_layout:  back pointer to the layout
 * @mlo_nodeoml: links this mlog in the mpool open mlogs tree
 * @mlo_uuid:    unique ID per mlog
 */
struct ecio_layout_mlo {
	struct mlog_stat              *mlo_lstat;
	struct ecio_layout_descriptor *mlo_layout;
	struct rb_node                 mlo_nodeoml;
	struct mpool_uuid              mlo_uuid;
};

/*
 * Object layout descriptor (in-memory version)
 *
 * LOCKING:
 * + objid: constant; no locking required
 * + lstat: lstat and *lstat are protected by pmd_obj_*lock()
 * + refcnt and isdel: protected by mmi_reflock of object's MDC
 * + all other fields: see notes
 */

/* ecio_layout_descriptor lock pool object count (per-numa node)
 */
#define ECIO_RWL_PER_NODE       512

/**
 * struct ecio_layout_descriptor
 *
 * The size of this structure should stay <= 128 bytes.
 * It contains holes that can be used to add new fields/information.
 *
 * NOTE:
 * + committed object fields (other): to update hold pmd_obj_wrlock()
 *   AND
 *   compactlock for object's mdc; to read hold pmd_obj_*lock()
 *   See the comments associated with struct pmd_mdc_info for
 *   further details.
 *
 * @eld_rwlock:  implements pmd_obj_*lock() for this layout
 * @eld_mblen:   Amount of data written in the mblock in bytes (0 for mlogs)
 * @eld_isdel:   true if object is logically deleted
 * @eld_state:   enum ecio_layout_state
 * @eld_flags:   enum mlog_open_flags for mlogs,
 *               enum mblock_layout_flags for mblocks
 * @eld_refcnt:  user ref count from alloc/get/put
 * @eld_nodemdc: for both ucobj and obj rbtrees, obj. only in one tree
 * @eld_objid:   object id associated with layout
 * @eld_mlo:     info. specific to an mlog, NULL for mblocks.
 * @eld_gen:     object generation
 * @eld_ld:
 */
struct ecio_layout_descriptor {
	uintptr_t                       eld_magic;
	u64                             eld_objid;
	struct rw_semaphore            *eld_rwlock;
	u32                             eld_mblen;
	bool                            eld_isdel;
	u8                              eld_state;
	u8                              eld_flags;
	u8                              eld_refcnt;

	struct rb_node                  eld_nodemdc;

	struct ecio_layout_mlo         *eld_mlo;
	u64                             eld_gen;

	struct omf_layout_descriptor    eld_ld;
};

/* Shortcuts */
#define eld_lstat   eld_mlo->mlo_lstat
#define eld_pcs     eld_mlo->mlo_pcs
#define eld_nodeoml eld_mlo->mlo_nodeoml
#define eld_uuid    eld_mlo->mlo_uuid

/*
 * struct ecio_err_report - ecio read/write error report
 *
 * @eer_errs:      total number of errors reading/writing object strips
 * @eer_rwsuc:     successfully read/wrote object strip
 * @eer_pdeio: pd module I/O error reading/writing object strip
 */
struct ecio_err_report {
	u8     eer_errs;
	u32    eer_rwsuc;
	u32    eer_pdeio;
};

/*
 * ecio API functions
 */

/*
 * Error codes: all ecio fns can return one or more of:
 * -EINVAL = invalid fn args
 * -EIO = all other errors
 *
 * NOTE: the ecio error report carries more detailed error information
 */

/**
 * ecio_mblock_stripe_size() - get the stripe size of an mblock
 *
 * Needed for incremental write, which must be full-stripe(s) except
 * for the last write.
 *
 * @layout: struct ecio_layout_descriptor *
 */
u32
ecio_mblock_stripe_size(
		struct mpool_descriptor       *mp,
		struct ecio_layout_descriptor *layout);

/**
 * ecio_mblock_write() - write complete mblock (incl. EC and cksum)
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout_descriptor *
 * @iov:    struct iovec *
 * @iovcnt: int
 * @afp_parent: struct afp_parent *
 * @erpt:   struct ecio_err_report *
 * @nbytes: u64 *
 *
 * Write complete mblock with erasure coding info.
 * Caller MUST hold pmd_obj_wrlock() on layout.
 *
 * If successful, it will set the layout.eld_mblen to the total bytes in iov.
 *
 * NOTE: the ecio error report carries more detailed error information
 *
 * Sets bytes written in tdata
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
ecio_mblock_write(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout,
	struct iovec                   *iov,
	int                             iovcnt,
	struct ecio_err_report         *erpt,
	u64                            *nbytes);

/**
 * ecio_mblock_read() - read mblock
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout_descriptor *
 * @iov:    struct iovec *
 * @iovcnt: int
 * @boff:   u64, offset into the mblock
 * @erpt:   struct ecio_err_report *
 *
 * Read mblock starting at byte offset boff.
 * Transparently handles media failures if possible. boff and read length
 * must be OS page multiples.
 *
 * Note: caller MUST hold pmd_obj_*lock() on layout to be protected against
 * a potential rebuild.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
ecio_mblock_read(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout,
	struct iovec                   *iov,
	int                             iovcnt,
	u64                             boff,
	struct ecio_err_report         *erpt);

/**
 * ecio_mblock_erase() - erase an mblock
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout_descriptor *
 * @erpt:   struct ecio_err_report *
 *
 * Erase mblock; caller MUST hold pmd_obj_wrlock() on layout.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
ecio_mblock_erase(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout,
	struct ecio_err_report         *erpt);
/**
 * ecio_mblock_flush() - Issue flush commands to PDs in layout
 * @mp:
 * @layout:
 * @erpt:
 */
merr_t
ecio_mblock_flush(
	struct mpool_descriptor       *mp,
	struct ecio_layout_descriptor *layout,
	struct ecio_err_report        *erpt);

/**
 * ecio_mlog_write() - write to an mlog
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout_descriptor *
 * @iov:    iovec containing the data to write
 * @iovcnt: number of iovecs
 * @boff:   u64 offset to write at
 * @erpt:   struct ecio_err_report *erpt
 *
 * Write iovecs to byte offset boff, erasure coded
 * per layout; caller MUST hold pmd_obj_wrlock() on layout.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
ecio_mlog_write(
	struct mpool_descriptor       *mp,
	struct ecio_layout_descriptor *layout,
	struct iovec                  *iov,
	int                            iovcnt,
	u64                            boff,
	struct ecio_err_report        *erpt);

/**
 * ecio_mlog_read() - read from an mlog
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout_descriptor *
 * @iov:    iovec to read into
 * @iovcnt: number of iovecs
 * @boff:   u64, offset from which to start read
 * @erpt:   struct ecio_err_report *
 *
 * Read from byte offset boff into the supplied iovecs
 * transparently handles media failures if possible; caller MUST hold
 * pmd_obj_*lock() on layout.
 *
 * Returns: 0 if success, merr_t otherwise
 */
merr_t
ecio_mlog_read(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout,
	struct iovec                   *iov,
	int                             iovcnt,
	u64                             boff,
	struct ecio_err_report         *erpt);

/**
 * ecio_mlog_erase() - erase an mlog
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout_descriptor *
 * @flags:  OR of pd_erase_flags bits
 * @erpt:   struct ecio_err_report *
 *
 * Erase mlog; caller MUST hold pmd_obj_wrlock() on layout.
 *
 * Return: 0 if successful, merr_t if error
 */
merr_t
ecio_mlog_erase(
	struct mpool_descriptor        *mp,
	struct ecio_layout_descriptor  *layout,
	enum pd_erase_flags             flags,
	struct ecio_err_report         *erpt);

/**
 * @ecio_layout_alloc() - allocate an ecio_layout_descriptor
 *
 * @mp:        To get the mpool uuid necessary to hook up performance counters
 *             of the family "MLOG" in preformance counters tree. If passed,
 *             no performance counter will be associated to that layout.
 * @objid:     u64, objid to give to descriptor
 * @gen:       u64, generation for this descriptor
 * @mblen:     u64 for mblock length of data written in it
 * @zcnt:      number of zones in a strip
 * @need_ref:  if true, refcount is set to 1, otherwise, set to 0
 *
 * Alloc and init object layout; non-arg fields and all strip descriptor
 * fields are set to 0/UNDEF/NONE; no auxiliary object info is allocated.
 *
 * Return: NULL if allocation fails.
 */
struct ecio_layout_descriptor *
ecio_layout_alloc(
	struct mpool_descriptor *mp,
	struct mpool_uuid         *uuid,
	u64                      objid,
	u64                      gen,
	u64                      mblen,
	u32                      zcnt,
	bool                     need_ref);

/**
 * ecio_layout_free() - free ecio_layout_descriptor and internal elements
 *
 * @layout: struct ecio_layout_descriptor *)
 *
 * Deallocate all memory associated with object layout.
 *
 * Return: void
 */
void ecio_layout_free(struct ecio_layout_descriptor *layout);

/*
 * ecio internal functions
 */

/**
 * struct iov_cursor
 *
 * This structure is used to traverse source and target iovec lists.
 *
 * @ic_iov:            Pointer to the iovec list
 * @ic_iovcnt:         The number of valid iovecs in the list
 * @ic_iovs_allocated: The number of iovecs that will fit in ic_iov (limited
 *                     by the size allocated, which is normally a single page)
 * @ic_idx:            Persistent index/cursor for traversal of the iovec list.
 *                     Valid range is (0 <= ic_idx <= min(ic_iovcnt,
 *                     ic_iovs_allocated)
 * @ic_pgcachetoken    If page came from reserved pool
 * @ic_soff:           On cursors for target strip I/Os, this field is used
 *                     for the base offset within the strip.
 */
struct iov_cursor {
	struct iovec *ic_iov;            /* iovec list */
	int           ic_iovcnt;         /* number of valid iovecs <= iovcnt */
	int           ic_iovs_allocated; /* allocated number of iovecs */
	int           ic_idx;            /* current iovec (cursor) */
	u32           ic_pgcachetoken;   /* private cache token */
	u64           ic_off;            /* offset into current iovec */
	u64           ic_soff;           /* offset into the strip */
};

/**
 * struct tgt_cursor_set
 *
 * This is a set of iov_cursors, generally one per strip, for executing
 * back-end (pd) I/O.
 *
 * These are built by calling passing a source cursor (built from a caller's
 * iovec list) to the build_strip_cursor_set() function, which builds the
 * appropriate tgt_cursor_set based on the topology of the object (mlog or
 * mblock).
 *
 * @ti_strip_ct: The number of iov_cursors in the set
 * @ti_curslst:  The array of iov_cursors
 */
struct tgt_cursor_set {
	int                ti_strip_ct; /* # of strips == # of cursors */
	struct iov_cursor *ti_curslst;  /* cursor list */
};

extern int mpc_chunker_size;

static inline u32 get_max_iovecs(void)
{
	int max_iovecs = PAGE_SIZE / sizeof(struct iovec);

	int num_iovecs = (READ_ONCE(mpc_chunker_size) + PAGE_SIZE - 1)
			/ PAGE_SIZE;

	if (num_iovecs > 0 && num_iovecs < max_iovecs)
		return num_iovecs;

	return max_iovecs;
}

static inline u32 get_max_mlog_iovecs(void)
{
	return PAGE_SIZE / sizeof(struct iovec);
}

/*
 * Asynchronous completion handling.
 */

/*
 * To save sidx, and the buffer containing the chksums to be written.
 * AKA SIDX_AFAN
 * This information is for a given pd.
 */
#define ECIO_UPL 1


/*
 * Information for the IO completion path (Completion Info).
 * Passed back to ecio on completion path of a read or a write.
 */
struct ecio_rw_af_ci {
	struct mpool_descriptor		*rwi_mp;
	struct ecio_layout_descriptor	*rwi_layout;
};

extern struct shash_desc *mpool_shash_desc_crc32c;
extern struct shash_desc *mpool_shash_desc_sha256;

u32
ecio_zonepg(
	struct mpool_descriptor       *mp,
	struct ecio_layout_descriptor *layout);

u32
ecio_sectorsz(
	struct mpool_descriptor       *mp,
	struct ecio_layout_descriptor *layout);

/**
 * ecio_obj_get_cap_from_layout()
 *
 * @mp:	    mpool descriptor
 * @layout: obj layout
 *
 * Compute the object capacity given its layout.
 *
 * Return: capacity of the object in bytes
 *
 */
u64
ecio_obj_get_cap_from_layout(
	struct mpool_descriptor       *mp,
	struct ecio_layout_descriptor *layout);

static inline void erpt_init(struct ecio_err_report *erpt)
{
	erpt->eer_errs = 0;
	erpt->eer_rwsuc = 0;
	erpt->eer_pdeio = 0;
};

/*
 * Combine the IO errors from the PDs used by the layout.
 *
 * @combiarg: ecio_err_report
 * @a:        positive errno
 * @b:        sidx
 */
static inline
void erpt_result_set(void *combiarg, s32 *combires, uintptr_t a, uintptr_t b)
{
	struct ecio_err_report *erpt = (struct ecio_err_report *)combiarg;
	int rval		     = -(int)a;
	u8 idx                       = (u8)b;

	if (rval)
		erpt->eer_errs = erpt->eer_errs + 1;

	if (!rval)
		erpt->eer_rwsuc = erpt->eer_rwsuc | (1 << idx);
	else if (rval == -EIO)
		erpt->eer_pdeio = erpt->eer_pdeio | (1 << idx);
};

static inline bool erpt_succeeded(struct ecio_err_report *erpt, u8 idx)
{
	return (erpt->eer_rwsuc & (1 << idx));
}

static inline bool erpt_eio(struct ecio_err_report *erpt, u8 idx)
{
	return (erpt->eer_pdeio & (1 << idx));
}

/**
 * ecio_user_layout_alloc() - Allocate a minimal layout descriptor for
 * user space mlogs support
 *
 * @mp:
 * @objid:
 * @gen:
 */
struct ecio_layout_descriptor *
ecio_user_layout_alloc(
	struct mpool_descriptor   *mp,
	struct mpool_uuid           *uuid,
	u64                        objid,
	u64                        gen);

/**
 * ecio_user_layout_free() - Free the layout descriptor used for user-space
 * mlogs
 *
 * @layout:
 */
void ecio_user_layout_free(struct ecio_layout_descriptor *layout);

/**
 * ecio_user_layout_set() - Set the generation and state in the layout. Used
 * only for user space mlog support
 *
 * @layout:
 * @gen:
 * @state:
 */
merr_t
ecio_user_layout_set(struct ecio_layout_descriptor *layout, u64 gen, u8 state);

#endif
