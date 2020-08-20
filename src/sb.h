/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_SB_PRIV_H
#define MPOOL_SB_PRIV_H

struct mpool_dev_info;

/*
 * Drives have 2 superblocks.
 * + sb0 at byte offset 0
 * + sb1 at byte offset SB_AREA_SZ
 *
 * Read: sb0 is the authoritative copy, other copies are not used.
 * Updates: sb0 is updated first; if successful sb1 is updated
 */
/* Number of superblock per Physical Device.  */
#define SB_SB_COUNT        2

/*
 * Size in byte of the area occupied by a superblock. The superblock itself
 * may be smaller, but always starts at the beginning of its area.
 */
#define SB_AREA_SZ        (4096ULL)

/*
 * Size in byte of an area located just after the superblock areas.
 * Not used in 1.0. Later can be used for MDC0 metadata and/or voting sets.
 */
#define MDC0MD_AREA_SZ    (4096ULL)

/*
 * sb API functions
 */

/**
 * sb_magic_check() - check for sb magic value
 * @pd: struct mpool_dev_info *
 *
 * Determine if the mpool magic value exists in at least one place where
 * expected on drive pd.  Does NOT imply drive has a valid superblock.
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Return: 1 if found, 0 if not found, -(errno) if error reading
 */
int sb_magic_check(struct mpool_dev_info *pd);

/**
 * sb_write_new() - write superblock to new drive
 * @pd: struct mpool_dev_info *
 * @sb: struct omf_sb_descriptor *
 *
 * Write superblock sb to new (non-pool) drive
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Return: 0 if successful; merr_t otherwise
 */
merr_t sb_write_new(struct mpool_dev_info *pd, struct omf_sb_descriptor *sb);

/**
 * sb_write_update() - update superblock
 * @pd: struct mpool_dev_info *
 *	"pd" info is not used to fill up the super block, only "sb" content
 *	is used.
 * @sb: struct omf_sb_descriptor *
 *	"sb" content is written in the super block.
 *
 * Update superblock on pool drive
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Return: 0 if successful; merr_t otherwise
 */
merr_t sb_write_update(struct mpool_dev_info *pd, struct omf_sb_descriptor *sb);

/**
 * sb_erase() - erase superblock
 * @pd: struct mpool_dev_info *
 *
 * Erase superblock on drive pd.
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Return: 0 if successful; merr_t otherwise
 */
merr_t sb_erase(struct mpool_dev_info *pd);

/**
 * sb_read() - read superblock
 * @pd: struct mpool_dev_info *
 * @sb: struct omf_sb_descriptor *
 * @omf_ver: omf sb version
 * @force:
 * Read superblock from drive pd; make repairs as necessary.
 *
 * Note: only pd.status and pd.parm must be set; no other pd fields accessed.
 *
 * Return: 0 if successful; merr_t otherwise
 */
merr_t sb_read(struct mpool_dev_info *pd, struct omf_sb_descriptor *sb, u16 *omf_ver, bool force);

/**
 * sb_zones_for_sbs() - compute how many zones are needed to contain the
 *	               superblocks.
 * @pd_prop:
 */
u32 sb_zones_for_sbs(struct pd_prop *pd_prop);

/**
 * sbutil_mdc0_clear() - clear mdc0 of superblock
 * @sb: struct omf_sb_descriptor *)
 *
 * Clear (set to zeros) mdc0 portion of sb.
 *
 * Return: void
 */
void sbutil_mdc0_clear(struct omf_sb_descriptor *sb);

/**
 * sbutil_mdc0_isclear() - Test if mdc0 is clear
 * @sb: struct omf_sb_descriptor *
 *
 * Return: 1 if mdc0 portion of sb is clear.
 */
int sbutil_mdc0_isclear(struct omf_sb_descriptor *sb);

/**
 * sbutil_mdc0_copy() - copy mdc0 from one superblock to another
 * @tgtsb: struct omf_sb_descriptor *
 * @srcsb: struct omf_sb_descriptor *
 *
 * Copy mdc0 portion of srcsb to tgtsb.
 *
 * Return void
 */
void sbutil_mdc0_copy(struct omf_sb_descriptor *tgtsb, struct omf_sb_descriptor *srcsb);

/**
 * sbutil_mdc0_isvalid() - validate mdc0 of a superblock
 * @sb: struct omf_sb_descriptor *
 *
 * Validate mdc0 portion of sb and extract mdparm.
 * Return: 1 if valid and mdparm set; 0 otherwise.
 */
int sbutil_mdc0_isvalid(struct omf_sb_descriptor *sb);

/*
 * sb internal functions
 */
extern struct omf_sb_descriptor SBCLEAR;

merr_t sb_init(void);

void sb_exit(void);

#endif /* MPOOL_SB_PRIV_H */
