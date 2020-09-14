/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MDC_PRIV_H
#define MPOOL_MDC_PRIV_H

#include <linux/mutex.h>

#define MPC_MDC_MAGIC           0xFEEDFEED
#define MPC_NO_MAGIC            0xFADEFADE

struct mpool_descriptor;
struct mlog_descriptor;

/**
 * struct mp_mdc - MDC handle
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
	char                        mdc_mpname[MPOOL_NAMESZ_MAX];
	int                         mdc_valid;
	int                         mdc_magic;
	u8                          mdc_flags;
};

/* MDC (Metadata Container) APIs */

/**
 * mp_mdc_open() - Open MDC by OIDs
 * @ds:       dataset handle
 * @logid1:   Mlog ID 1
 * @logid2:   Mlog ID 2
 * @flags:    MDC Open flags (enum mdc_open_flags)
 * @mdc_out:  MDC handle
 */
uint64_t
mp_mdc_open(struct mpool_descriptor *mp, u64 logid1, u64 logid2, u8 flags, struct mp_mdc **mdc_out);

/**
 * mp_mdc_close() - Close MDC
 * @mdc:      MDC handle
 */
uint64_t mp_mdc_close(struct mp_mdc *mdc);

/**
 * mp_mdc_rewind() - Rewind MDC to first record
 * @mdc:      MDC handle
 */
uint64_t mp_mdc_rewind(struct mp_mdc *mdc);

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
uint64_t mp_mdc_read(struct mp_mdc *mdc, void *data, size_t len, size_t *rdlen);

/**
 * mp_mdc_append() - append record to MDC
 * @mdc:      MDC handle
 * @data:     data to write
 * @len:      length of data
 * @sync:     flag to defer return until IO is complete
 */
uint64_t mp_mdc_append(struct mp_mdc *mdc, void *data, ssize_t len, bool sync);

/**
 * mp_mdc_cstart() - Initiate MDC compaction
 * @mdc:      MDC handle
 *
 * Swap active (ostensibly full) and inactive (empty) mlogs
 * Append a compaction start marker to newly active mlog
 */
uint64_t mp_mdc_cstart(struct mp_mdc *mdc);

/**
 * mp_mdc_cend() - End MDC compactions
 * @mdc:      MDC handle
 *
 * Append a compaction end marker to the active mlog
 */
uint64_t mp_mdc_cend(struct mp_mdc *mdc);

#endif /* MPOOL_MDC_PRIV_H */
