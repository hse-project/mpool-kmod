/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPCORE_H
#define MPOOL_MPCORE_H

#include <linux/rbtree.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>

#include "uuid.h"

#include "mp.h"
#include "pd.h"
#include "smap.h"
#include "mclass.h"
#include "pmd.h"
#include "params.h"

extern struct rb_root mpool_pools;

struct pmd_layout;

/**
 * DOC: LOCKING
 *
 * x-module locking hierarchy for mpool mp
 *
 * + mpool_s_lock
 * + pmd_s_lock
 * + mp.mda.mdi_slotv[x].(unc)obj[objid].rwlock (per object per mdc);
 *   normally obtained by calling pmd_obj_*lock(layout)
 * + mp.omlock
 * + mp.spcap_lock
 * + mp.mda.mdi_slotvlock
 * + mp.mda.mdi_slotv[x].uqlock (one per mdc)
 * + mp.mda.mdi_slotv[x].compactlock (one per mdc)
 * + mp.mda.mdi_slotv[x].uncolock (one per mdc)
 * + mp.mda.mdi_slotv[x].colock (one per mdc)
 * + mp.mda.mdi_slotv[x].bgoplock (one per mdc)
 * + mp.pds_pdvlock
 * + mp.pdv[d].zmlock[z] (one per drive smap allocation zone)
 * + mp.pdv[d].ds.sda_dalock (one per drive)
 *   <eol>
 *
 * NOTE: Every user object (mlog or mblock) is associated with exactly one
 * metadata container X (mdc X), X>0.  Operations on a user object take locks
 * related to that object and its mdc, mp.mda.mdi_slotv[X].* above, and also
 * on the pair of mlog objects used to implement mdc X which are associated
 * with mdc 0.
 * Hence all mp.mda.mdi_slotv[0].* locks are below any mp.mda.mdi_slotv[X].*
 * locks, X>0.
 */

/**
 * enum mpool_status -
 * @MPOOL_STAT_UNDEF:
 * @MPOOL_STAT_OPTIMAL:
 * @MPOOL_STAT_FAULTED:
 */
enum mpool_status {
	MPOOL_STAT_UNDEF    = 0,
	MPOOL_STAT_OPTIMAL  = 1,
	MPOOL_STAT_FAULTED  = 2,
	MPOOL_STAT_LAST = MPOOL_STAT_FAULTED,
};

_Static_assert((MPOOL_STAT_LAST < 256), "enum mpool_status must fit in u8");

/**
 * struct mpool_dev_info - Pool drive state, status, and params
 * @pdi_devid:    UUID for this drive
 * @pdi_parm:     drive parms
 * @pdi_status:   enum pd_status value: drive status
 * @pdi_ds:       drive space allocation info
 * @pdi_rmap:     per allocation zone space maps rbtree array, node:
 *                struct u64_to_u64_rb
 * @pdi_rmlock:   lock protects per zone space maps
 * @pdi_name:     device name (only the last path name component)
 *
 * Pool drive state, status, and params
 *
 * LOCKING:
 *    devid, mclass : constant; no locking required
 *    parm: constant EXCEPT in rare change of status from UNAVAIL; see below
 *    status: usage does not require locking, but MUST get/set via accessors
 *    state: protected by pdvlock in enclosing mpool_descriptor
 *    ds: protected by ds.dalock defined in smap module
 *    zmap[x]: protected by zmlock[x]
 *
 * parm fields are constant except in a rare change of status from UNAVAIL,
 * during which a subset of the fields are modified.  see the pd module for
 * details on how this is handled w/o requiring locking.
 */
struct mpool_dev_info {
	atomic_t                pdi_status; /* Barriers or acq/rel required */
	struct pd_dev_parm      pdi_parm;
	struct smap_dev_alloc   pdi_ds;
	struct rmbkt           *pdi_rmbktv;
	struct mpool_uuid       pdi_devid;
};

/* Shortcuts */
#define pdi_didstr    pdi_parm.dpr_prop.pdp_didstr
#define pdi_zonepg    pdi_parm.dpr_prop.pdp_zparam.dvb_zonepg
#define pdi_zonetot   pdi_parm.dpr_prop.pdp_zparam.dvb_zonetot
#define pdi_devtype   pdi_parm.dpr_prop.pdp_devtype
#define pdi_cmdopt    pdi_parm.dpr_prop.pdp_cmdopt
#define pdi_mclass    pdi_parm.dpr_prop.pdp_mclassp
#define pdi_devsz     pdi_parm.dpr_prop.pdp_devsz
#define pdi_sectorsz  pdi_parm.dpr_prop.pdp_sectorsz
#define pdi_optiosz   pdi_parm.dpr_prop.pdp_optiosz
#define pdi_fua       pdi_parm.dpr_prop.pdp_fua
#define pdi_prop      pdi_parm.dpr_prop
#define pdi_name      pdi_parm.dpr_name

/**
 * struct uuid_to_mpdesc_rb -
 * @utm_node:
 * @utm_uuid_le:
 * @utm_md:
 */
struct uuid_to_mpdesc_rb {
	struct rb_node              utm_node;
	struct mpool_uuid           utm_uuid_le;
	struct mpool_descriptor    *utm_md;
};

/**
 * struct mpdesc_mdparm - parameters used for the MDCs of the mpool.
 * @md_mclass:  media class used for the mpool metadata
 */
struct mpdesc_mdparm {
	u8     md_mclass;
};

/**
 * struct pre_compact_ctrl - used to start/stop/control precompaction
 * @pco_dwork:
 * @pco_mp:
 * @pco_nmtoc: next MDC to compact

 * Each time pmd_precompact_cb() runs it will consider the next MDC
 * for compaction.
 */
struct pre_compact_ctrl {
	struct delayed_work	 pco_dwork;
	struct mpool_descriptor *pco_mp;
	atomic_t		 pco_nmtoc;
};

/**
 * struct mpool_descriptor - Media pool descriptor
 * @pds_pdvlock:  drive membership/state lock
 * @pds_pdv:      per drive info array
 * @pds_omlock:   open mlog index lock
 * @pds_oml:      rbtree of open mlog layouts. indexed by objid
 *                node type: objid_to_layout_rb
 * @pds_poolid:   UUID of pool
 * @pds_mdparm:   mclass id of mclass used for mdc layouts
 * @pds_cfg:      mpool config
 * @pds_pdvcnt:   cnt of valid pdv entries
 * @pds_mc        table of media classes
 * @pds_uctxt     used by user-space mlogs to indicate the context
 * @pds_node:     for linking this object into an rbtree
 * @pds_params:   Per mpool parameters
 * @pds_workq:    Workqueue per mpool.
 * @pds_sbmdc0:   Used to store in RAM the MDC0 metadata. Loaded at activate
 *                time, changed when MDC0 is compacted.
 * @pds_mda:      metadata container array (this thing is huge!)
 *
 * LOCKING:
 *    poolid, ospagesz, mdparm: constant; no locking required
 *    mda: protected by internal locks as documented in pmd module
 *    oml: protected by omlock
 *    pdv: see note
 *    pds_mc: protected by pds_pdvlock
 *	Update of pds_mc[].mc_sparams.mc_spzone must also be enclosed
 *	with mpool_s_lock to serialize the spzone updates, because they include
 *	an append of an MDC0 record on top of updating mc_spzone.
 *    all other fields: protected by pds_pdvlock (as is pds_pdv[x].state)
 *    pds_sbmdc0: Used to store in RAM the MDC0 metadata. Loaded when mpool
 *	activated, no lock needed at that time (single) threaded.
 *	Then changed during MDC0 compaction. At that time it is protected by
 *	MDC0 compact lock.
 *
 * NOTE:
 *    pds_pdvcnt only ever increases so that pds_pdv[x], x < pdvcnt, can be
 *    accessed without locking, other than as required by the struct
 *    mpool_dev_info.
 *    mc_spzone is written and read only by mpool functions that are serialized
 *    via mpool_s_lock.
 */
struct mpool_descriptor {
	struct rw_semaphore         pds_pdvlock;

	____cacheline_aligned
	struct mpool_dev_info       pds_pdv[MPOOL_DRIVES_MAX];

	____cacheline_aligned
	struct mutex                pds_oml_lock;
	struct rb_root              pds_oml_root;

	/* Read-mostly fields... */
	____cacheline_aligned
	u16                         pds_pdvcnt;
	struct mpdesc_mdparm        pds_mdparm;
	struct workqueue_struct    *pds_workq;
	struct workqueue_struct    *pds_erase_wq;
	struct workqueue_struct    *pds_precompact_wq;

	struct media_class          pds_mc[MP_MED_NUMBER];
	struct mpcore_params        pds_params;
	struct omf_sb_descriptor    pds_sbmdc0;
	struct pre_compact_ctrl     pds_pco;
	struct smap_usage_work      pds_smap_usage_work;

	/* Rarey used fields... */
	struct mpool_config         pds_cfg;
	struct rb_node              pds_node;
	struct mpool_uuid           pds_poolid;
	char                        pds_name[MPOOL_NAMESZ_MAX];

	/* pds_mda is enormous (91K) */
	struct pmd_mda_info         pds_mda;
};

/**
 * mpool_desc_unavail_add() - Add unavailable drive to mpool descriptor.
 * @mp:
 * @omf_devparm:
 *
 * Add unavailable drive to mpool descriptor; caller must guarantee that
 * devparm.devid is not already there.
 * As part of adding the drive to the mpool descriptor, the drive is added
 * in its media class.
 *
 * Return: 0 if successful, merr_t (EINVAL or ENOMEM) otherwise
 */
merr_t mpool_desc_unavail_add(struct mpool_descriptor *mp, struct omf_devparm_descriptor *devparm);

/**
 * mpool_desc_pdmc_add() - Add a device in its media class.
 * @mp:
 * @pdh:
 * @omf_devparm:
 * @check_only: if true, the call doesn't change any state, it only check
 *	if the PD could be added in a media class.
 *
 * If the media class doesn't exist yet, it is created here.
 *
 * This function has two inputs related to the PD it is acting on:
 *  "phd"
 *  and "omf_devparm"
 *
 * If omf_devparm is NULL, it means that the media class in which the PD must
 * be placed is derived from mp->pds_pdv[pdh].pdi_parm.dpr_prop
 * In that case the PD properties (.dpr_prop) must be updated and
 * correct when entering this function.
 * devparm is NULL when the device is available, that means the discovery
 * was able to update .dpr_prop.
 *
 * If omf_devparm is not NULL, it means that the media class in which the PD
 * must be placed is derived from omf_devparm.
 * This is used when unavailable PDs are placed in their media class. In this
 * situation (because the PD is unavailable) the discovery couldn't discover
 * the PD properties and mp->pds_pdv[pdh].pdi_parm.dpr_prop has not been
 * updated because of that.
 * So we can't use .dpr_prop to place the PD in its class, instead we use what
 * is coming from the persitent metadata (PD state record in MDC0). Aka
 * omf_devparm.
 * mp->pds_pdv[pdh].pdi_parm.dpr_prop will be update if/when the PD is available
 * again.
 *
 * Restrictions in placing PDs in media classes
 * --------------------------------------------
 * This function enforces these restrictions.
 * These restrictions are:
 * a) in a mpool, for a given mclassp (enum mp_media_classp), there is
 *    at maximum one media class.
 * b) All drives of a media class must checksummed or none, no mix allowed.
 * c) The STAGING and CAPACITY classes must be both checksummed or both not
 *    checksummed.
 *
 * Locking:
 * -------
 *	Should be called with mp.pds_pdvlock held in write.
 *	Except if mpool is single threaded (during activate for example).
 */
merr_t
mpool_desc_pdmc_add(
	struct mpool_descriptor		*mp,
	u16				 pdh,
	struct omf_devparm_descriptor	*omf_devparm,
	bool				 check_only);

int uuid_to_mpdesc_insert(struct rb_root *root, struct mpool_descriptor *data);

merr_t
mpool_dev_sbwrite(
	struct mpool_descriptor    *mp,
	struct mpool_dev_info      *pd,
	struct omf_sb_descriptor   *sbmdc0);

merr_t
mpool_mdc0_sb2obj(
	struct mpool_descriptor    *mp,
	struct omf_sb_descriptor   *sb,
	struct pmd_layout         **l1,
	struct pmd_layout         **l2);

merr_t mpool_desc_init_newpool(struct mpool_descriptor *mp, u32 flags);

merr_t
mpool_dev_init_all(
	struct mpool_dev_info  *pdv,
	u64                     dcnt,
	char                  **dpaths,
	struct pd_prop	       *pd_prop);

void mpool_mdc_cap_init(struct mpool_descriptor *mp, struct mpool_dev_info *pd);

merr_t
mpool_desc_init_sb(
	struct mpool_descriptor    *mp,
	struct omf_sb_descriptor   *sbmdc0,
	u32                         flags,
	bool                       *mc_resize);

merr_t mpool_dev_sbwrite_newpool(struct mpool_descriptor *mp, struct omf_sb_descriptor *sbmdc0);

merr_t check_for_dups(char **listv, int cnt, int *dup, int *offset);

void fill_in_devprops(struct mpool_descriptor *mp, u64 pdh, struct mpool_devprops *dprop);

merr_t mpool_create_rmlogs(struct mpool_descriptor *mp, u64 mlog_cap);

struct mpool_descriptor *mpool_desc_alloc(void);

void mpool_desc_free(struct mpool_descriptor *mp);

merr_t mpool_dev_check_new(struct mpool_descriptor *mp, struct mpool_dev_info *pd);

static inline enum pd_status mpool_pd_status_get(struct mpool_dev_info *pd)
{
	enum pd_status  val;

	/* Acquire semantics used so that no reads will be re-ordered from
	 * before to after this read.
	 */
	val = atomic_read_acquire(&pd->pdi_status);

	return val;
}

static inline void mpool_pd_status_set(struct mpool_dev_info *pd, enum pd_status status)
{
	/* All prior writes must be visible prior to the status change */
	smp_wmb();
	atomic_set(&pd->pdi_status, status);
}

/**
 * mpool_get_mpname() - Get the mpool name
 * @mp:     mpool descriptor of the mpool
 * @mpname: buffer to copy the mpool name into
 * @mplen:  buffer length
 *
 * Return:
 * %0 if successful, EINVAL otherwise
 */
static inline merr_t mpool_get_mpname(struct mpool_descriptor *mp, char *mpname, size_t mplen)
{
	if (!mp || !mpname)
		return merr(EINVAL);

	strlcpy(mpname, mp->pds_name, mplen);

	return 0;
}


#endif /* MPOOL_MPCORE_H */
