/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPCORE_MDC_H
#define MPOOL_MPCORE_MDC_H

#include <linux/mutex.h>

#include <mpool/mpool_ioctl.h>

#include <mpcore/merr.h>

#define MPC_MDC_MAGIC           0xFEEDFEED
#define MPC_NO_MAGIC            0xFADEFADE

struct mpool_descriptor;
struct mlog_descriptor;

/**
 * struct mp_mdc: MDC handle
 *
 * @mdc_ds:     dataset handle (user client) or mpool desc (kernel client)
 * @mdc_ctxt:   mdc context
 * @mdc_logh1:  mlog 1 handle
 * @mdc_logh2:  mlog 2 handle
 * @mdc_alogh:  active mlog handle
 * @mdc_lock:   mdc mutex
 * @mdc_mpname: mpool name
 * @mdc_valid:  is the handle valid?
 * @mdc_magic:  MDC handle magic
 * @mdc_flags:	MDC flags
 *
 * Ordering:
 *     mdc handle lock (mdc_lock)
 *     mlog handle lock (ml_lock)
 *     dataset handle lock (ds_lock)
 *     mpool core locks
 */
struct mp_mdc {
	struct mpool_descriptor    *mdc_mp;
	struct mlog_descriptor     *mdc_logh1;
	struct mlog_descriptor     *mdc_logh2;
	struct mlog_descriptor     *mdc_alogh;
	struct mutex                mdc_lock;
	char                        mdc_mpname[MPOOL_NAME_LEN_MAX];
	int                         mdc_valid;
	int                         mdc_magic;
	u8                          mdc_flags;
};

/**
 * mdc_open_flags -
 * @MDC_OF_SKIP_SER: appends and reads are guaranteed to be serialized
 *                   outside of the MDC API
 */
enum mdc_open_flags {
	MDC_OF_SKIP_SER  = 0x1,
};

/**
 * mdc_capacity -
 * @mdt_captgt: capacity target for mlog in bytes
 * @mpt_spare:  true if alloc MDC from spare space
 */
struct mdc_capacity {
	uint64_t   mdt_captgt;
	bool       mdt_spare;
};

/**
 * mdc_props -
 * @mdc_objid1:
 * @mdc_objid2:
 * @mdc_alloc_cap:
 * @mdc_mclassp:
 */
struct mdc_props {
	uint64_t               mdc_objid1;
	uint64_t               mdc_objid2;
	uint64_t               mdc_alloc_cap;
	enum mp_media_classp   mdc_mclassp;
};

/* MDC (Metadata Container) APIs
 */

/**
 * mp_mdc_open() - Open MDC by OIDs
 * @ds:       dataset handle
 * @logid1:   Mlog ID 1
 * @logid2:   Mlog ID 2
 * @flags:    MDC Open flags (enum mdc_open_flags)
 * @mdc_out:  MDC handle
 */
uint64_t
mp_mdc_open(
	struct mpool_descriptor     *mp,
	u64                          logid1,
	u64                          logid2,
	u8                           flags,
	struct mp_mdc              **mdc_out);

/**
 * mp_mdc_close() - Close MDC
 * @mdc:      MDC handle
 */
uint64_t
mp_mdc_close(
	struct mp_mdc  *mdc);

/**
 * mp_mdc_rewind() - Rewind MDC to first record
 * @mdc:      MDC handle
 */
uint64_t
mp_mdc_rewind(
	struct mp_mdc  *mdc);

/**
 * mp_mdc_read() - Read next record from MDC
 * @mdc:      MDC handle
 * @data:     buffer to receive data
 * @len:      length of supplied buffer
 * @rdlen:    number of bytes read
 *
 * Return:
 *   If merr_errno() of the return value is EOVERFLOW, then the receive buffer
 *   "data" is too small and must be resized according to the value returned
 *   in "rdlen".
 */
uint64_t
mp_mdc_read(
	struct mp_mdc  *mdc,
	void           *data,
	size_t          len,
	size_t         *rdlen);

/**
 * mp_mdc_append() - append record to MDC
 * @mdc:      MDC handle
 * @data:     data to write
 * @len:      length of data
 * @sync:     flag to defer return until IO is complete
 */
uint64_t
mp_mdc_append(
	struct mp_mdc  *mdc,
	void           *data,
	ssize_t         len,
	bool            sync);

/**
 * mp_mdc_cstart() - Initiate MDC compaction
 * @mdc:      MDC handle
 *
 * Swap active (ostensibly full) and inactive (empty) mlogs
 * Append a compaction start marker to newly active mlog
 */
uint64_t
mp_mdc_cstart(
	struct mp_mdc  *mdc);

/**
 * mp_mdc_cend() - End MDC compactions
 * @mdc:      MDC handle
 *
 * Append a compaction end marker to the active mlog
 */
uint64_t
mp_mdc_cend(
	struct mp_mdc  *mdc);

#endif /* MPOOL_MPCORE_MDC_H */
