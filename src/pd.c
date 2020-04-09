// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Pool drive module.
 *
 * Defines functions for probing, reading, and writing drives in an mpool.
 */

#define _LARGEFILE64_SOURCE

#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>

#include "mpcore_defs.h"


/*
 * pd API functions -- device-type independent dparm ops
 */

merr_t pd_dev_init(struct pd_dev_parm *dparm, struct pd_prop *pd_prop)
{
	merr_t err;

	dparm->dpr_prop = *pd_prop;

	if ((pd_prop->pdp_devtype != PD_DEV_TYPE_FILE) &&
		(pd_prop->pdp_devtype != PD_DEV_TYPE_BLOCK_STD) &&
		(pd_prop->pdp_devtype != PD_DEV_TYPE_BLOCK_NVDIMM)) {

		err = merr(EINVAL);
		mp_pr_err("unsupported PD type %d", err, pd_prop->pdp_devtype);
		return err;
	}

	return 0;
}

merr_t
pd_zone_pwritev(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	u64                     boff,
	int                     op_flags,
	struct cb_context      *cbctx)
{
	u64    woff;

	if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL)
		return merr(ev(EIO));

	woff = ((u64)pd->pdi_zonepg << PAGE_SHIFT) * zoneaddr + boff;

	return pd_bio_rw(pd, iov, iovcnt, woff, REQ_OP_WRITE, op_flags, cbctx);
}

merr_t
pd_zone_pwritev_sync(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	u64                     boff)
{
	merr_t		        err;
	struct block_device    *bdev;

	err = pd_zone_pwritev(pd, iov, iovcnt, zoneaddr, boff, REQ_FUA, NULL);
	if (ev(err))
		return err;

	/*
	 * This sync & invalidate bdev ensures that the data written from the
	 * kernel is immediately visible to the user-space.
	 */
	bdev = pd->pdi_parm.dpr_dev_private;
	if (bdev) {
		sync_blockdev(bdev);
		invalidate_bdev(bdev);
	}

	return 0;
}

merr_t
pd_zone_preadv(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	u64                     boff,
	struct cb_context      *cbctx)
{
	u64    roff;

	if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL)
		return merr(ev(EIO));

	roff = ((u64)pd->pdi_zonepg << PAGE_SHIFT) * zoneaddr + boff;

	return pd_bio_rw(pd, iov, iovcnt, roff, REQ_OP_READ, 0, cbctx);
}

merr_t
pd_zone_preadv_sync(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	u64                     boff)
{
	return pd_zone_preadv(pd, iov, iovcnt, zoneaddr, boff, NULL);
}

void
pd_dev_set_unavail(
	struct pd_dev_parm            *dparm,
	struct omf_devparm_descriptor *omf_devparm)
{
	struct pd_prop     *pd_prop = &(dparm->dpr_prop);

	/*
	 * Fill in dparm for unavailable drive; sets zone parm and other
	 * PD properties we keep in metadata; no ops vector because we need
	 * the device to be available to know it (the discovery gets it).
	 */
	strncpy(dparm->dpr_prop.pdp_didstr, PD_DEV_ID_PDUNAVAILABLE,
		PD_DEV_ID_LEN);
	pd_prop->pdp_devstate = PD_DEV_STATE_UNAVAIL;
	pd_prop->pdp_cmdopt = PD_CMD_NONE;

	pd_prop->pdp_zparam.dvb_zonepg  = omf_devparm->odp_zonepg;
	pd_prop->pdp_zparam.dvb_zonetot = omf_devparm->odp_zonetot;
	pd_prop->pdp_mclassp		= omf_devparm->odp_mclassp;
	pd_prop->pdp_phys_if		= DEVICE_PHYS_IF_UNKNOWN;
	pd_prop->pdp_sectorsz		= omf_devparm->odp_sectorsz;
	pd_prop->pdp_devsz		= omf_devparm->odp_devsz;
}

void pd_dev_set_avail(struct pd_dev_parm *tgtparm, struct pd_dev_parm *srcparm)
{
	/*
	 * Copy non-zone parms from srcparm to tgtparm, including the ops vector
	 * for the device type, so that tgtparm can be made available.
	 */
	strncpy(tgtparm->dpr_prop.pdp_didstr,
		srcparm->dpr_prop.pdp_didstr, PD_DEV_ID_LEN);
	tgtparm->dpr_prop.pdp_cmdopt = srcparm->dpr_prop.pdp_cmdopt;

	tgtparm->dpr_prop.pdp_devstate = PD_DEV_STATE_AVAIL;
}
