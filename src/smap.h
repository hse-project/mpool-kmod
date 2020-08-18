/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_SMAP_PRIV_H
#define MPOOL_SMAP_PRIV_H

/* Forward Decls */
struct mpool_usage;
struct mpool_devprops;
struct mpool_dev_info;
struct mc_smap_parms;

/*
 * Common defs
 */

/**
 * struct rmbkt - region map bucket
 */
struct rmbkt {
	struct mutex    pdi_rmlock;
	struct rb_root  pdi_rmroot;
} ____cacheline_aligned;

/**
 * struct smap_zone -
 * @smz_node:
 * @smz_key:
 * @smz_value:
 */
struct smap_zone {
	struct rb_node  smz_node;
	u64             smz_key;
	u64             smz_value;
};

/*
 * enum smap_space_type - space allocation policy flag
 *
 * @SMAP_SPC_UNDEF:
 * @SMAP_SPC_USABLE_ONLY:    allocate from usable space only
 * @SMAP_SPC_USABLE_2_SPARE: allocate from usable space first then spare
 *                          if needed
 * @SMAP_SPC_SPARE_ONLY:     allocate from spare space only
 * @SMAP_SPC_SPARE_2_USABLE: allocate from spare space first then usable
 *                          if needed
 */
enum smap_space_type {
	SMAP_SPC_UNDEF           = 0,
	SMAP_SPC_USABLE_ONLY     = 1,
	SMAP_SPC_USABLE_2_SPARE  = 2,
	SMAP_SPC_SPARE_ONLY      = 3,
	SMAP_SPC_SPARE_2_USABLE  = 4
};

static inline int saptype_valid(enum smap_space_type saptype)
{
	return (saptype && saptype <= 4);
}

/*
 * drive allocation info
 *
 * LOCKING:
 * + rgnsz, rgnladdr: constants; no locking required
 * + all other fields: protected by dalock
 */

/*
 * struct smap_dev_alloc -
 *
 * @sda_dalock:
 * @sda_rgnsz:    number of zones per rgn, excepting last
 * @sda_rgnladdr: address of first zone in last rgn
 * @sda_rgnalloc: rgn last alloced from
 * @sda_zoneeff:    total zones (zonetot) minus bad zones
 * @sda_utgt:      target max usable zones to allocate
 * @sda_uact:      actual usable zones allocated
 * @sda_stgt:      target max spare zones to allocate
 * @sda_sact       actual spare zones allocated
 *
 * NOTE:
 * + must maintain invariant that sact <= stgt
 * + however it is possible for uact > utgt due to changing % spare
 *   zones or zone failures.  this condition corrects when
 *   sufficient space is freed or if % spare zones is changed
 *   (again).
 *
 * Capacity pools and calcs:
 * + total zones = zonetot
 * + avail zones = zoneeff
 * + usable zones = utgt which is (zoneeff * (1 - spzone/100))
 * + free usable zones = max(0, utgt - uact); max handles uact > utgt
 * + used zones = uact; possible for used > usable (uact > utgt)
 * + spare zones = stgt which is (zoneeff - utgt)
 * + free spare zones = (stgt - sact); guaranteed that sact <= stgt
 */
struct smap_dev_alloc {
	spinlock_t sda_dalock;
	u32        sda_rgnsz;
	u32        sda_rgnladdr;
	u32        sda_rgnalloc;
	u32        sda_zoneeff;
	u32        sda_utgt;
	u32        sda_uact;
	u32        sda_stgt;
	u32        sda_sact;
};

struct smap_dev_znstats {
	u64    sdv_total;
	u64    sdv_avail;
	u64    sdv_usable;
	u64    sdv_fusable;
	u64    sdv_spare;
	u64    sdv_fspare;
	u64    sdv_used;
};

/**
 * smap_usage_work - delayed work struct for checking mpool free usable
 *                   space usage
 * @smapu_wstruct:
 * @smapu_mp:
 * @smapu_freepct: free space %
 */
struct smap_usage_work {
	struct delayed_work             smapu_wstruct;
	struct mpool_descriptor        *smapu_mp;
	int                             smapu_freepct;
};

/*
 * smap API functions
 */

/*
 * Return: all smap fns can return merr_t with the following errno values
 * on failure:
 * + EINVAL = invalid fn args
 * + ENOSPC = unable to allocate requested space
 * + ENOMEM = insufficient memory to complete operation
 */

/*
 * smap API usage notes:
 * + During mpool activation call smap_insert() for all existing objects
 *   before calling smap_alloc() or smap_free().
 */

/**
 * smap_mpool_init() - initialize the smaps for an initialized mpool_descriptor
 * @mp: struct mpool_descriptor *
 *
 * smap_mpool_init must be called once per mpool as it is being activated.
 *
 * Init space maps for all drives in mpool that are empty except for
 * superblocks; caller must ensure no other thread can access mp.
 *
 * TODO: Traversing smap rbtrees may need fix, since there may be unsafe
 * erases within loops.
 *
 * Return:
 * 0 if successful, merr_t with the following errno values on failure:
 * EINVAL if spare zone percentage is > 100%,
 * EINVAL if rgn count is 0, or
 * EINVAL if zonecnt on one of the drives is < rgn count
 * ENOMEM if there is no memory available
 */
merr_t smap_mpool_init(struct mpool_descriptor *mp);

/**
 * smap_mpool_free() - free smap structures in a mpool_descriptor
 * @mp: struct mpool_descriptor *
 *
 * Free space maps for all drives in mpool; caller must ensure no other
 * thread can access mp.
 *
 * Return: void
 */
void smap_mpool_free(struct mpool_descriptor *mp);

/**
 * smap_mpool_usage() - present stats of smap usage
 * @mp: struct mpool_descriptor *
 * @mclass: media class or MP_MED_ALL for all classes
 * @usage: struct mpool_usage *
 *
 * Fill in stats with space usage for media class; if MP_MED_ALL
 * report on all media classes; caller must hold mp.pdvlock.
 *
 * Locking: the caller should hold the pds_pdvlock at least in read to
 *	to be protected against media classes updates.
 *
 * Return: 0 if successful, merr_t otherwise...
 */
void smap_mpool_usage(struct mpool_descriptor *mp, u8 mclass, struct mpool_usage *usage);

/**
 * smap_drive_spares() - Set percentage of zones to set aside as spares
 * @mp: struct mpool_descriptor *
 * @mclassp: media class
 * @spzone: percentage of zones to use as spares
 *
 * Set percent spare zones to spzone for drives in media class mclass;
 * caller must hold mp.pdvlock.
 *
 * Locking: the caller should hold the pds_pdvlock at least in read to
 *	to be protected against media classes updates.
 *
 * Return: 0 if successful; merr_t otherwise
 */
merr_t smap_drive_spares(struct mpool_descriptor *mp, enum mp_media_classp mclassp, u8 spzone);

/**
 * smap_drive_usage() - Fill in a given drive's portion of dprop struct.
 * @mp:    struct mpool_descriptor *
 * @pdh:   drive number within the mpool_descriptor
 * @dprop: struct mpool_devprops *, structure to fill in
 *
 * Fill in usage portion of dprop for drive pdh; caller must hold mp.pdvlock
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t smap_drive_usage(struct mpool_descriptor *mp, u16 pdh, struct mpool_devprops *dprop);

/**
 * smap_drive_init() - Initialize a specific drive within a mpool_descriptor
 * @mp:    struct mpool_descriptor *
 * @mcsp:  smap parameters
 * @pdh:   u16, drive number within the mpool_descriptor
 *
 * Init space map for pool drive pdh that is empty except for superblocks
 * with a percent spare zones of spzone; caller must ensure pdh is not in use.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t smap_drive_init(struct mpool_descriptor *mp, struct mc_smap_parms *mcsp, u16 pdh);

/**
 * smap_drive_free() - Release resources for a specific drive
 * @mp:  struct mpool_descriptor *
 * @pdh: u16, drive number within the mpool_descriptor
 *
 * Free space map for pool drive pdh including partial (failed) inits;
 * caller must ensure pdh is not in use.
 *
 * Return: void
 */
void smap_drive_free(struct mpool_descriptor *mp, u16 pdh);

/**
 * smap_insert() - Inject an entry to an smap for existing object
 * @mp: struct mpool_descriptor *
 * @pdh: drive number within the mpool_descriptor
 * @zoneaddr: starting zone for entry
 * @zonecnt: number of zones in entry
 *
 * Add entry to space map for an existing object with a strip on drive pdh
 * starting at virtual erase block zoneaddr and continuing for zonecnt blocks.
 *
 * Used, in part for superblocks.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t smap_insert(struct mpool_descriptor *mp, u16 pdh, u64 zoneaddr, u32 zonecnt);

/**
 * smap_alloc() - Allocate a new contiguous zone range on a specific drive
 * @mp: struct mpool_descriptor
 * @pdh: u16, drive number within the mpool_descriptor
 * @zonecnt: u64, the number of zones requested
 * @sapolicy: enum smap_space_type, usable only, spare only, etc.
 * @zoneaddr: u64 *, the starting zone for the allocated range
 * @align: no. of zones (must be a power-of-2)
 *
 * Attempt to allocate zonecnt contiguous virtual erase blocks on drive pdh
 * in accordance with space allocation policy sapolicy.
 *
 * Return: 0 if succcessful; merr_t otherwise
 */
merr_t
smap_alloc(
	struct mpool_descriptor    *mp,
	u16                         pdh,
	u64                         zonecnt,
	enum smap_space_type        sapolicy,
	u64                        *zoneaddr,
	u64                         align);

/**
 * smap_free() - Free a previously allocated range of zones in the smap
 * @mp: struct mpool_descriptor *
 * @pdh: u16, number of the disk within the mpool_descriptor
 * @zoneaddr: u64, starting zone for the range to free
 * @zonecnt: u16, the number of zones in the range
 *
 * Free currently allocated space starting at virtual erase block zoneaddr
 * and continuing for zonecnt blocks.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t smap_free(struct mpool_descriptor *mp, u16 pdh, u64 zoneaddr, u16 zonecnt);

/*
 * smap internal functions
 */
merr_t smap_drive_alloc(struct mpool_descriptor *mp, struct mc_smap_parms *mcsp, u16 pdh);

/**
 * smap_mpool_usage() - Get the media class usage for a given mclass.
 * @mp:
 * @mclass: if MP_MED_ALL, return the sum of the stats for all media class,
 *	else the stats only for one media class.
 * @usage: output
 *
 * Locking: the caller should hold the pds_pdvlock at least in read to
 *	to be protected against media classes updates.
 */
void smap_mclass_usage(struct mpool_descriptor *mp, u8 mclass, struct mpool_usage *usage);

/**
 * smap_log_mpool_usage() - check drive mpool free usable space %, and log
 *                    a message if needed
 * @ws:
 */
void smap_log_mpool_usage(struct work_struct *ws);

/**
 * smap_wait_usage_done() - wait for periodical job for logging
 *                          pd free usable space % to complete
 * @mp:
 */
void smap_wait_usage_done(struct mpool_descriptor *mp);

#endif /* MPOOL_SMAP_PRIV_H */
