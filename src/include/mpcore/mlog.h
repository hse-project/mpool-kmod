/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/**
 * DOC: mlog module
 *
 * Defines functions for writing, reading, and managing the lifecycle of mlogs.
 *
 */

#ifndef MPOOL_MLOG_H
#define MPOOL_MLOG_H

#include <mpool/mpool_ioctl.h>

/*
 * Opaque handles for clients
 */
struct mpool_descriptor;
struct mlog_descriptor;
struct mpool_obj_layout;

/*
 * mlog API functions
 */

/*
 * Error codes: all mlog fns can return one or more of:
 * -EINVAL = invalid fn args
 * -ENOENT = log not open or logid not found
 * -EFBIG = log full
 * -EMSGSIZE = cstart w/o cend indicating a crash during compaction
 * -ENODATA = malformed or corrupted log
 * -EIO = unable to read/write log on media
 * -ENOMEM = insufficient room in copy-out buffer
 * -EBUSY = log is in erasing state; wait or retry erase
 */

merr_t
mlog_alloc(
	struct mpool_descriptor *mp,
	struct mlog_capacity    *capreq,
	enum   mp_media_classp   mclassp,
	struct mlog_props       *prop,
	struct mlog_descriptor  **mlh);

merr_t
mlog_realloc(
	struct mpool_descriptor *mp,
	u64                      objid,
	struct mlog_capacity    *capreq,
	enum   mp_media_classp   mclassp,
	struct mlog_props       *prop,
	struct mlog_descriptor  **mlh);

merr_t
mlog_find_get(
	struct mpool_descriptor    *mp,
	u64                         objid,
	int                         which,
	struct mlog_props          *prop,
	struct mlog_descriptor    **mlh);

void mlog_put(struct mpool_descriptor *mp, struct mlog_descriptor *layout);

void mlog_lookup_rootids(u64 *id1, u64 *id2);

merr_t mlog_commit(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);

merr_t mlog_abort(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);

merr_t mlog_delete(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);


/**
 * mlog_open()
 *
 * Open committed log, validate contents, and return its generation number;
 * if log is already open just returns gen; if csem is true enforces compaction
 * semantics so that open fails if valid cstart/cend markers are not present.
 * @mp:
 * @mlh:
 * @flags:
 * @gen: output
 *
 * Returns: 0 if successful, merr_t otherwise
 */
merr_t mlog_open(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, u8 flags, u64 *gen);

merr_t mlog_close(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);

merr_t mlog_gen(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, u64 *gen);

merr_t mlog_empty(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, bool *empty);

merr_t mlog_erase(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, u64 mingen);

merr_t mlog_append_cstart(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);

merr_t mlog_append_cend(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);

merr_t
mlog_append_data(
	struct mpool_descriptor    *mp,
	struct mlog_descriptor     *mlh,
	char                       *buf,
	u64                         buflen,
	int                         sync);

merr_t mlog_read_data_init(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);

/**
 * mlog_read_data_next()
 * @mp:
 * @mlh:
 * @buf:
 * @buflen:
 * @rdlen:
 *
 * Returns:
 *   If merr_errno(return value) is EOVERFLOW, then "buf" is too small to
 *   hold the read data. Can be retried with a bigger receive buffer whose
 *   size is returned in rdlen.
 */
merr_t
mlog_read_data_next(
	struct mpool_descriptor    *mp,
	struct mlog_descriptor     *mlh,
	char                       *buf,
	u64                         buflen,
	u64                        *rdlen);

merr_t
mlog_get_props(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, struct mlog_props *prop);

merr_t
mlog_get_props_ex(
	struct mpool_descriptor    *mp,
	struct mlog_descriptor     *mlh,
	struct mlog_props_ex       *prop);

void mlog_precompact_alsz(struct mpool_descriptor *mp, struct mlog_descriptor *mlh);

merr_t
mlog_rw_raw(
	struct mpool_descriptor    *mp,
	struct mlog_descriptor     *mlh,
	struct kvec                *iov,
	int                         iovcnt,
	u64                         boff,
	u8                          rw);

bool mlog_objid(u64 objid);

#endif /* MPOOL_MLOG_H */
