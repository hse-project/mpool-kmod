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

#include <linux/uio.h>

#include "mpool_ioctl.h"
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
 * Return: %0 if successful, -errno otherwise...
 */
int mblock_alloc(struct mpool_descriptor *mp, enum mp_media_classp mclassp, bool spare,
		 struct mblock_descriptor **mbh, struct mblock_props *prop);

/**
 * mblock_find_get() - Get handle and properties for existing mblock with specified objid.
 * @mp:
 * @objid:
 * @which:
 * @prop:
 * @mbh:
 *
 * If successful, the caller holds a ref on the mblock (which must be put eventually).
 *
 * Return: %0 if successful, -errno otherwise...
 */
int mblock_find_get(struct mpool_descriptor *mp, u64 objid, int which,
		    struct mblock_props *prop, struct mblock_descriptor **mbh);

/**
 * mblock_put() - Put (release) a ref on an mblock
 * @mbh:
 *
 * Put a ref on a known mblock.
 *
 * Return: %0 if successful, -errno otherwise...
 */
void mblock_put(struct mblock_descriptor *mbh);

/**
 * mblock_commit() - Make allocated mblock persistent
 * @mp:
 * @mbh:
 *
 * if fails mblock still exists in an
 * uncommitted state so can retry commit or abort except as noted.
 *
 * Return: %0 if successful, -errno otherwise...
 * EBUSY if must abort
 */
int mblock_commit(struct mpool_descriptor *mp, struct mblock_descriptor *mbh);

/**
 * mblock_abort() - Discard uncommitted mblock
 * @mp:
 * @mbh:
 *
 * If successful mbh is invalid after call.
 *
 * Return: %0 if successful, -errno otherwise...
 *
 */
int mblock_abort(struct mpool_descriptor *mp, struct mblock_descriptor *mbh);

/**
 * mblock_delete() - Delete committed mblock
 * @mp:
 * @mbh:
 *
 * If successful mbh is invalid after call.
 *
 * Return: %0 if successful, -errno otherwise...
 */
int mblock_delete(struct mpool_descriptor *mp, struct mblock_descriptor *mbh);

/**
 * mblock_write() - Write iov to mblock
 * @mp:
 * @mbh:
 * @iov:
 * @iovcnt:
 * @len:
 *
 * Mblocks can be written until they are committed, or
 * until they are full.  If a caller needs to issue more than one write call
 * to the same mblock, all but the last write call must be optimal write size aligned.
 * The mpr_optimal_wrsz field in struct mblock_props gives the optimal write size.
 *
 * Return: %0 if success, -errno otherwise...
 */
int mblock_write(struct mpool_descriptor *mp, struct mblock_descriptor *mbh,
		 const struct kvec *iov, int iovcnt, size_t len);

/**
 * mblock_read() - Read data from mblock mbnum in committed mblock into iov
 * @mp:
 * @mbh:
 * @iov:
 * @iovcnt:
 * @boff:
 * @len:
 *
 * Read data from mblock mbnum in committed mblock into iov starting at
 * byte offset boff; boff and iov buffers must be a multiple of OS page
 * size for the mblock.
 *
 * If fails can call mblock_get_props() to confirm mblock was written.
 *
 * Return: 0 if successful, -errno otherwise...
 */
int mblock_read(struct mpool_descriptor *mp, struct mblock_descriptor *mbh,
		const struct kvec *iov, int iovcnt, loff_t boff, size_t len);

/**
 * mblock_get_props_ex() - Return extended mblock properties in prop
 * @mp:
 * @mbh:
 * @prop:
 *
 * Return: %0 if successful, -errno otherwise...
 */
int mblock_get_props_ex(struct mpool_descriptor *mp, struct mblock_descriptor *mbh,
			struct mblock_props_ex *prop);

bool mblock_objid(u64 objid);

#endif /* MPOOL_MBLOCK_H */
