/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PD_H
#define MPOOL_PD_H

#include <linux/uio.h>

#include "uuid.h"
#include "mpool_ioctl.h"

/* Returns PD length in bytes. */
#define PD_LEN(_pd_prop) ((_pd_prop)->pdp_devsz)

/* Returns PD sector size (exponent, power of 2) */
#define PD_SECTORSZ(_pd_prop) ((_pd_prop)->pdp_sectorsz)

/* Return PD sector size mask */
#define PD_SECTORMASK(_pd_prop) ((uint64_t)(1 << PD_SECTORSZ(_pd_prop)) - 1)

struct omf_devparm_descriptor;

/**
 * struct pd_dev_parm -
 * @dpr_prop:		drive properties including zone parameters
 * @dpr_dev_private:    private info for implementation
 * @dpr_name:           device name
 */
struct pd_dev_parm {
	struct pd_prop	         dpr_prop;
	void		        *dpr_dev_private;
	char                     dpr_name[PD_NAMESZ_MAX];
};

/* Shortcuts */
#define dpr_zonepg        dpr_prop.pdp_zparam.dvb_zonepg
#define dpr_zonetot       dpr_prop.pdp_zparam.dvb_zonetot
#define dpr_devsz         dpr_prop.pdp_devsz
#define dpr_didstr        dpr_prop.pdp_didstr
#define dpr_mediachar     dpr_prop.pdp_mediachar
#define dpr_cmdopt        dpr_prop.pdp_cmdopt
#define dpr_optiosz       dpr_prop.pdp_optiosz

/**
 * enum pd_status - Transient drive status.
 * @PD_STAT_UNDEF:       undefined; should never occur
 * @PD_STAT_ONLINE:      drive is responding to I/O requests
 * @PD_STAT_SUSPECT:     drive is failing some I/O requests
 * @PD_STAT_OFFLINE:     drive declared non-responsive to I/O requests
 * @PD_STAT_UNAVAIL:     drive path not provided or open failed when
 *                        mpool was opened
 *
 * Transient drive status, these are stored as atomic_t variable
 * values
 */
enum pd_status {
	PD_STAT_UNDEF      = 0,
	PD_STAT_ONLINE     = 1,
	PD_STAT_SUSPECT    = 2,
	PD_STAT_OFFLINE    = 3,
	PD_STAT_UNAVAIL    = 4
};

_Static_assert((PD_STAT_UNAVAIL < 256), "enum pd_status must fit in uint8_t");

/**
 * enum pd_cmd_opt - drive command options
 * @PD_CMD_DISCARD:	     the device has TRIM/UNMAP command.
 * @PD_CMD_SECTOR_UPDATABLE: the device can be read/written with sector
 *	granularity.
 * @PD_CMD_DIF_ENABLED:      T10 DIF is used on this device.
 * @PD_CMD_SED_ENABLED:      Self encrypting enabled
 * @PD_CMD_DISCARD_ZERO:     the device supports discard_zero
 * @PD_CMD_RDONLY:           activate mpool with PDs in RDONLY mode,
 *                           write/discard commands are No-OPs.
 * Defined as a bit vector so can combine.
 * Fields holding such a vector should uint64_t.
 *
 * TODO: we need to find a way to detect if SED is enabled on a device
 */
enum pd_cmd_opt {
	PD_CMD_NONE             = 0,
	PD_CMD_DISCARD          = 0x1,
	PD_CMD_SECTOR_UPDATABLE = 0x2,
	PD_CMD_DIF_ENABLED      = 0x4,
	PD_CMD_SED_ENABLED      = 0x8,
	PD_CMD_DISCARD_ZERO     = 0x10,
	PD_CMD_RDONLY           = 0x20,
};

/**
 * Device types.
 * @PD_DEV_TYPE_BLOCK_STREAM: Block device implementing streams.
 * @PD_DEV_TYPE_BLOCK_STD:    Standard (non-streams) device (SSD, HDD).
 * @PD_DEV_TYPE_FILE:	      File in user space for UT.
 * @PD_DEV_TYPE_MEM:	      Memory semantic device. Such as NVDIMM
 *			      direct access (raw or dax mode).
 * @PD_DEV_TYPE_ZONE:	      zone-like device, such as open channel SSD
 *			      and SMR HDD (using ZBC/ZAC).
 * @PD_DEV_TYPE_BLOCK_NVDIMM: Standard (non-streams) NVDIMM in sector mode.
 */
enum pd_devtype {
	PD_DEV_TYPE_BLOCK_STREAM = 1,
	PD_DEV_TYPE_BLOCK_STD,
	PD_DEV_TYPE_FILE,
	PD_DEV_TYPE_MEM,
	PD_DEV_TYPE_ZONE,
	PD_DEV_TYPE_BLOCK_NVDIMM,
	PD_DEV_TYPE_LAST = PD_DEV_TYPE_BLOCK_NVDIMM,
};

_Static_assert((PD_DEV_TYPE_LAST < 256), "enum pd_devtype must fit in uint8_t");

/**
 * Device states.
 * @PD_DEV_STATE_AVAIL:       Device is available
 * @PD_DEV_STATE_UNAVAIL:     Device is unavailable
 */
enum pd_state {
	PD_DEV_STATE_UNDEFINED = 0,
	PD_DEV_STATE_AVAIL = 1,
	PD_DEV_STATE_UNAVAIL = 2,
	PD_DEV_STATE_LAST = PD_DEV_STATE_UNAVAIL,
};

_Static_assert((PD_DEV_STATE_LAST < 256), "enum pd_state must fit in uint8_t");

/*
 * pd API functions -- device-type independent dparm ops
 */

/*
 * Error codes: All pd functions can return one or more of:
 *
 * -EINVAL    invalid fn args
 * -EBADSLT   attempt to read or write a bad zone on a zone device
 * -EIO       all other errors
 */

/**
 * pd_dev_open() -
 * @path:
 * @dparm:
 *
 * Return:
 */
int pd_dev_open(const char *path, struct pd_dev_parm *dparm, struct pd_prop *pd_prop);

/**
 * pd_dev_close() -
 * @pd:
 */
int pd_dev_close(struct pd_dev_parm *dparm);

/**
 * pd_dev_flush() -
 * @pd:
 */
int pd_dev_flush(struct pd_dev_parm *dparm);

/**
 * pd_bio_erase() -
 * @pd:
 * @zaddr:
 * @zonecnt:
 * @reads_erased: whether the data can be read post DISCARD
 *
 * Return:
 */
int pd_zone_erase(struct pd_dev_parm *dparm, u64 zaddr, u32 zonecnt, bool reads_erased);

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
int pd_zone_pwritev(struct pd_dev_parm *dparm, const struct kvec *iov,
		    int iovcnt, u64 zaddr, loff_t boff, int opflags);

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
int pd_zone_pwritev_sync(struct pd_dev_parm *dparm, const struct kvec *iov,
			 int iovcnt, u64 zaddr, loff_t boff);

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
int pd_zone_preadv(struct pd_dev_parm *dparm, const struct kvec *iov,
		   int iovcnt, u64 zaddr, loff_t boff);

/**
 * pd_dev_set_unavail() -
 * @dparm:
 * @omf_devparm:
 *
 * Return:
 */
void pd_dev_set_unavail(struct pd_dev_parm *dparm, struct omf_devparm_descriptor *omf_devparm);

int pd_init(void) __cold;
void pd_exit(void) __cold;

#endif /* MPOOL_PD_H */
