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
struct ecio_layout;

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
 * @layout: struct ecio_layout *
 */
u32
ecio_mblock_stripe_size(
		struct mpool_descriptor    *mp,
		struct ecio_layout         *layout);

/**
 * ecio_mblock_write() - write complete mblock (incl. EC and cksum)
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout *
 * @iov:    struct iovec *
 * @iovcnt: int
 * @afp_parent: struct afp_parent *
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
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout,
	struct iovec               *iov,
	int                         iovcnt,
	u64                        *nbytes);

/**
 * ecio_mblock_read() - read mblock
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout *
 * @iov:    struct iovec *
 * @iovcnt: int
 * @boff:   u64, offset into the mblock
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
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout,
	struct iovec               *iov,
	int                         iovcnt,
	u64                         boff);

/**
 * ecio_mblock_erase() - erase an mblock
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout *
 *
 * Erase mblock; caller MUST hold pmd_obj_wrlock() on layout.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
ecio_mblock_erase(
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout);

/**
 * ecio_mlog_write() - write to an mlog
 *
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout *
 * @iov:    iovec containing the data to write
 * @iovcnt: number of iovecs
 * @boff:   u64 offset to write at
 *
 * Write iovecs to byte offset boff, erasure coded
 * per layout; caller MUST hold pmd_obj_wrlock() on layout.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
ecio_mlog_write(
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout,
	struct iovec               *iov,
	int                         iovcnt,
	u64                         boff);

/**
 * ecio_mlog_read() - read from an mlog
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout *
 * @iov:    iovec to read into
 * @iovcnt: number of iovecs
 * @boff:   u64, offset from which to start read
 *
 * Read from byte offset boff into the supplied iovecs
 * transparently handles media failures if possible; caller MUST hold
 * pmd_obj_*lock() on layout.
 *
 * Returns: 0 if success, merr_t otherwise
 */
merr_t
ecio_mlog_read(
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout,
	struct iovec               *iov,
	int                         iovcnt,
	u64                         boff);

/**
 * ecio_mlog_erase() - erase an mlog
 * @mp:     struct mpool_descriptor *
 * @layout: struct ecio_layout *
 * @flags:  OR of pd_erase_flags bits
 *
 * Erase mlog; caller MUST hold pmd_obj_wrlock() on layout.
 *
 * Return: 0 if successful, merr_t if error
 */
merr_t
ecio_mlog_erase(
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout,
	enum pd_erase_flags         flags);

/*
 * ecio internal functions
 */

extern int mpc_chunker_size;

extern struct shash_desc *mpool_shash_desc_crc32c;
extern struct shash_desc *mpool_shash_desc_sha256;

u32
ecio_zonepg(
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout);

u32
ecio_sectorsz(
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout);

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
	struct mpool_descriptor    *mp,
	struct ecio_layout         *layout);

#endif
