/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * DOC: Module info.
 *
 * Defines functions for writing, reading, and managing the lifecycle of mlogs.
 *
 */

#ifndef MPOOL_MBLOCK_H
#define MPOOL_MBLOCK_H

#include <mpool/mpool_ioctl.h>
#include <mpcore/mdc.h>
/*
 * Opaque handles for clients
 */
struct mpool_descriptor;
struct mblock_descriptor;
struct mpool_obj_layout;

/*
 * mblock API functions
 */

/**
 * mblock_alloc() - Allocate an mblock.
 * @mp:         mpool descriptor
 * @capreq:     mblock capacity requested
 * @mclassp:    media class
 * @mbh:        mblock handle returned
 * @prop:       mblock properties returned
 *
 * Allocate mblock with erasure code and capacity params as specified in
 * ecparm and capreq on drives in a media class mclassp;
 * if successful mbh is a handle for the mblock and prop contains its
 * properties.
 * Note: mblock is not persistent until committed; allocation can be aborted.
 *
 * Return: %0 if successful, merr_t otherwise...
 */
merr_t
mblock_alloc(
	struct mpool_descriptor	    *mp,
	enum   mp_media_classp       mclassp,
	bool                         spare,
	struct mblock_descriptor   **mbh,
	struct mblock_props         *prop);

/**
 * mblock_realloc() - Re-Allocate an mblock.
 * @mp:        mpool descriptor
 * @objid:     mblock object id to be re-allocated
 * @capreq:    mblock capacity requested
 * @mclassp:   media class performance level requested
 * @mbh:       mblock handle returned
 * @prop:      mblock properties returned
 *
 * Allocate mblock with specified objid to support crash recovery; otherwise
 * is equivalent to mblock_alloc().
 *
 * Return: 0 if successful, merr_t otherwise...
 * EEXIST if objid exists
 */
merr_t
mblock_realloc(
	struct mpool_descriptor     *mp,
	u64                          objid,
	enum   mp_media_classp       mclassp,
	bool                         spare,
	struct mblock_descriptor   **mbh,
	struct mblock_props         *prop);

/**
 * mblock_find_get() -
 * @mp:
 * @objid:
 * @which:
 * @prop:
 * @mbh:
 *
 * Get handle and properties for existing mblock with specified objid.  If
 * successful, the caller holds a ref on the mblock (which must be put
 * eventually)
 *
 * Return: %0 if successful, merr_t otherwise...
 */
merr_t
mblock_find_get(
	struct mpool_descriptor    *mp,
	u64                         objid,
	int                         which,
	struct mblock_props        *prop,
	struct mblock_descriptor  **mbh);

/**
 * mblock_put() - Put (release) a ref on an mblock
 * @mp:
 * @mbh:
 * @prop:
 *
 * Put a ref on a known mblock.
 *
 * Return: %0 if successful, merr_t otherwise...
 */
void mblock_put(struct mpool_descriptor *mp, struct mblock_descriptor *mbh);

/**
 * mblock_commit() -
 * @mp:
 * @mbh:
 *
 * Make allocated mblock persistent; if fails mblock still exists in an
 * uncommitted state so can retry commit or abort except as noted.
 *
 * Return: %0 if successful, merr_t otherwise...
 * EBUSY if must abort
 */
merr_t
mblock_commit(struct mpool_descriptor *mp, struct mblock_descriptor *mbh);

/**
 * mblock_abort() -
 * @mp:
 * @mbh:
 *
 * Discard uncommitted mblock; if successful mbh is invalid after call.
 *
 * Return: %0 if successful, merr_t otherwise...
 *
 */
merr_t mblock_abort(struct mpool_descriptor *mp, struct mblock_descriptor *mbh);

/**
 * mblock_delete() -
 * @mp:
 * @mbh:
 *
 * Delete committed mblock; if successful mbh is invalid after call.
 *
 * Return: %0 if successful, merr_t otherwise...
 */
merr_t
mblock_delete(struct mpool_descriptor *mp, struct mblock_descriptor *mbh);

/**
 * mblock_write() -
 * @mp:
 * @mbh:
 * @iov:
 * @iovcnt:
 *
 * Write iov to mblock.  Mblocks can be written until they are committed, or
 * until they are full.  If a caller needs to issue more than one write call
 * to the same mblock, all but the last write call must be stripe-aligned.
 * The mpr_stripe_len field in struct mblock_props gives the stripe size.
 *
 * Return: %0 if success, merr_t otherwise...
 */
merr_t
mblock_write(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct iovec               *iov,
	int                         iovcnt);

/**
 * mblock_read() -
 * @mp:
 * @mbh:
 * @iov:
 * @iovcnt:
 * @boff:
 *
 * Read data from mblock mbnum in committed mblock into iov starting at
 * byte offset boff; boff and iov buffers must be a multiple of OS page
 * size for the mblock.
 *
 * If fails can call mblock_get_props() to confirm mblock was written.
 *
 * Return: 0 if successful, merr_t otherwise...
 */
merr_t
mblock_read(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct iovec               *iov,
	int                         iovcnt,
	u64                         boff);

/**
 * mblock_get_props() -
 * @mp:
 * @mbh:
 * @prop:
 *
 * Return basic mblock properties in prop.
 *
 * Return: %0 if successful, merr_t otherwise...
 *
 */
merr_t
mblock_get_props(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props        *prop);

/**
 * mblock_get_props_ex() -
 * @mp:
 * @mbh:
 * @prop:
 *
 * Return extended mblock properties in prop.
 *
 * Return: %0 if successful, merr_t otherwise...
 */
merr_t
mblock_get_props_ex(
	struct mpool_descriptor    *mp,
	struct mblock_descriptor   *mbh,
	struct mblock_props_ex     *prop);

bool mblock_objid(u64 objid);

extern void
free_pages_asyncio(
	void           **p,
	struct iovec    *iov_base,
	int              iovcnt,
	int              pagesc,
	int              pagesvsz);

#endif
