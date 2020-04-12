/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PD_PRIV_H
#define MPOOL_PD_PRIV_H

#include <mpool/mpool_ioctl.h>
#include <mpcore/qos.h>

struct mpool_dev_info;
struct pd_dev_parm;

#define KSECSZ     512

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
 * From a PD structure, convert a page number into a byte number.
 */
#define PDBPAGE2BYTE(_pd, _bpgoff) ((_bpgoff) << PAGE_SHIFT)

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
 * pd_dev_init() - update PD parameters from the PD properties passed in.
 * @dparm: output
 * @pd_prop: input
 */
merr_t pd_dev_init(struct pd_dev_parm *dparm, struct pd_prop *pd_prop);

/**
 * pd_bio_dev_open() -
 * @path:
 * @dparm:
 *
 * Return:
 */
merr_t pd_bio_dev_open(const char *path, struct pd_dev_parm *dparm);

/**
 * pd_bio_erase() -
 * @pd:
 * @zoneaddr:
 * @zonecnt:
 * @flags: OR of pd_erase_flags bits
 *
 * Return:
 */
merr_t
pd_bio_erase(
	struct mpool_dev_info  *pd,
	u64                     zoneaddr,
	u32                     zonecnt,
	enum pd_erase_flags     flag);

/**
 * pd_bio_dev_close() -
 * @pd:
 */
merr_t pd_bio_dev_close(struct pd_dev_parm *dparm);

/**
 * pd_bio_rw() -
 * @pd:
 * @iov:
 * @iovcnt:
 * @off:
 * @rw:
 * @op_flags:
 */
merr_t
pd_bio_rw(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	loff_t                  off,
	int                     rw,
	int                     op_flags);

/*
 * pd API functions - device dependent operations
 */

/**
 * pd_zone_pwritev() -
 * @pd:
 * @iov:
 * @iovcnt:
 * @zoneaddr:
 * @boff: offset in bytes from the start of "zoneaddr".
 * @op_flags:
 *
 * Return:
 */
merr_t
pd_zone_pwritev(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	loff_t                  boff,
	int                     op_flags);

/**
 * pd_zone_pwritev_sync() -
 * @pd:
 * @iov:
 * @iovcnt:
 * @zoneaddr:
 * @boff: Offset in bytes from the start of zoneaddr.
 *
 * Return:
 */
merr_t
pd_zone_pwritev_sync(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	loff_t                  boff);

/**
 * pd_zone_preadv() -
 * @pd:
 * @iov:
 * @iovcnt:
 * @zoneaddr: target zone for this I/O
 * @boff:    byte offset into the target zone
 *
 * Return:
 */
merr_t
pd_zone_preadv(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	loff_t                  boff);

/**
 * pd_dev_set_unavail() -
 * @dparm:
 * @omf_devparm:
 *
 * Return:
 */
void
pd_dev_set_unavail(
	struct pd_dev_parm	      *dparm,
	struct omf_devparm_descriptor *omf_devparm);

/**
 * pd_dev_set_avail() -
 * @tgtparm:
 * @srcparm:
 *
 * Return:
 */
void
pd_dev_set_avail(struct pd_dev_parm *tgtparm, struct pd_dev_parm *srcparm);

#endif
