/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PD_PRIV_H
#define MPOOL_PD_PRIV_H

#include <mpool/mpool_ioctl.h>

struct mpool_dev_info;

/**
 * pd_erase_flags
 * PD_ERASE_FZERO:        force to write zeros to PD
 * PD_ERASE_READS_ERASED: readable after erase
 */
enum pd_erase_flags {
	PD_ERASE_FZERO          = 0x1,
	PD_ERASE_READS_ERASED   = 0x2,
};

/*
 * Common defs
 */

/**
 * struct pd_dev_parm -
 * @dpr_prop:		drive properties including zone parameters
 * @dpr_dev_private:    private info for implementation
 *
 */
struct pd_dev_parm {
	struct pd_prop	         dpr_prop;
	void		        *dpr_dev_private;
};

/* Shortcuts */
#define dpr_zonepg        dpr_prop.pdp_zparam.dvb_zonepg
#define dpr_zonetot       dpr_prop.pdp_zparam.dvb_zonetot
#define dpr_devsz         dpr_prop.pdp_devsz
#define dpr_didstr        dpr_prop.pdp_didstr
#define dpr_mediachar     dpr_prop.pdp_mediachar
#define dpr_cmdopt        dpr_prop.pdp_cmdopt
#define dpr_optiosz       dpr_prop.pdp_optiosz

/*
 * pd API functions -- device-type independent dparm ops
 */

/*
 * Error codes: All pd functions can return one or more of:
 *
 * -EINVAL    invalid fn args
 * -EBADSLT   attempt to read or write a bad erase block on a zone device
 * -EIO       all other errors
 */

/**
 * pd_dev_open() -
 * @path:
 * @dparm:
 *
 * Return:
 */
merr_t pd_dev_open(const char *path, struct pd_dev_parm *dparm, struct pd_prop *pd_prop);

/**
 * pd_dev_close() -
 * @pd:
 */
merr_t pd_dev_close(struct pd_dev_parm *dparm);

/**
 * pd_bio_erase() -
 * @pd:
 * @zaddr:
 * @zonecnt:
 * @flags: OR of pd_erase_flags bits
 *
 * Return:
 */
merr_t pd_zone_erase(struct mpool_dev_info *pd, u64 zaddr, u32 zonecnt, enum pd_erase_flags flag);

/*
 * pd API functions - device dependent operations
 */

/**
 * pd_zone_pwritev() -
 * @pd:
 * @iov:
 * @iovcnt:
 * @zaddr:
 * @boff: offset in bytes from the start of "zaddr".
 * @opflags:
 *
 * Return:
 */
merr_t
pd_zone_pwritev(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zaddr,
	loff_t                  boff,
	int                     opflags);

/**
 * pd_zone_pwritev_sync() -
 * @pd:
 * @iov:
 * @iovcnt:
 * @zaddr:
 * @boff: Offset in bytes from the start of zaddr.
 *
 * Return:
 */
merr_t
pd_zone_pwritev_sync(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zaddr,
	loff_t                  boff);

/**
 * pd_zone_preadv() -
 * @pd:
 * @iov:
 * @iovcnt:
 * @zaddr: target zone for this I/O
 * @boff:    byte offset into the target zone
 *
 * Return:
 */
merr_t
pd_zone_preadv(struct mpool_dev_info *pd, struct iovec *iov, int iovcnt, u64 zaddr, loff_t boff);

/**
 * pd_dev_set_unavail() -
 * @dparm:
 * @omf_devparm:
 *
 * Return:
 */
void pd_dev_set_unavail(struct pd_dev_parm *dparm, struct omf_devparm_descriptor *omf_devparm);

#endif /* MPOOL_PD_PRIV_H */
