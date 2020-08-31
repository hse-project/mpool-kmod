/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Defines functions for writing, reading, and managing the lifecycle of mlogs.
 */

#ifndef MPOOL_MLOG_UTILS_H
#define MPOOL_MLOG_UTILS_H

/* "open mlog" rbtree operations... */
#define oml_layout_lock(_mp)        mutex_lock(&(_mp)->pds_oml_lock)
#define oml_layout_unlock(_mp)      mutex_unlock(&(_mp)->pds_oml_lock)

struct pmd_layout_mlpriv *
oml_layout_insert(struct mpool_descriptor *mp, struct pmd_layout_mlpriv *item);

struct pmd_layout_mlpriv *oml_layout_remove(struct mpool_descriptor *mp, u64 key);

void mlog_free_abuf(struct mlog_stat *lstat, int start, int end);

void mlog_free_rbuf(struct mlog_stat *lstat, int start, int end);

void
mlog_extract_fsetparms(
	struct mlog_stat   *lstat,
	u16                *sectsz,
	u32                *totsec,
	u16                *nsecmb,
	u16                *nseclpg);

merr_t mlog_stat_init(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, bool csem);

void mlog_stat_free(struct pmd_layout *layout);

void
mlog_read_iter_init(struct pmd_layout *layout, struct mlog_stat *lstat, struct mlog_read_iter *lri);

void mlog_stat_init_common(struct pmd_layout *layout, struct mlog_stat *lstat);

merr_t
mlog_rw(
	struct mpool_descriptor *mp,
	struct mlog_descriptor  *mlh,
	struct kvec             *iov,
	int                      iovcnt,
	u64                      boff,
	u8                       rw,
	bool                     skip_ser);

merr_t
mlog_populate_rbuf(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	u16                        *nsec,
	off_t                      *soff,
	bool                        skip_ser);

merr_t
mlog_alloc_abufpg(struct mpool_descriptor *mp, struct pmd_layout *layout, u16 abidx, bool skip_ser);

void
mlog_getprops_cmn(struct mpool_descriptor *mp, struct pmd_layout *layout, struct mlog_props *prop);

merr_t mlog_logblocks_flush(struct mpool_descriptor *mp, struct pmd_layout *layout, bool skip_ser);

s64 mlog_append_dmax(struct mpool_descriptor *mp, struct pmd_layout *layout);

merr_t
mlog_update_append_idx(struct mpool_descriptor *mp, struct pmd_layout *layout, bool skip_ser);

merr_t
mlog_logblock_load(
	struct mpool_descriptor     *mp,
	struct mlog_read_iter       *lri,
	char                       **buf,
	bool                        *first);

#endif /* MPOOL_MLOG_UTILS_H */
