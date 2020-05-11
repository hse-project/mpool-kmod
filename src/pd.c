// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Pool drive module with backing block devices.
 *
 * Defines functions for probing, reading, and writing drives in an mpool.
 * IO is done using kerel BIO facilities.
 */

#define _LARGEFILE64_SOURCE

#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/version.h>

#include "mpcore_defs.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
#define SECTOR_SHIFT   9
#endif

static const fmode_t    pd_bio_fmode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
static char            *pd_bio_holder = "mpool";

extern int mpc_chunker_size;

merr_t
pd_dev_open(
	const char         *path,
	struct pd_dev_parm *dparm,
	struct pd_prop     *pd_prop)
{
	struct block_device *bdev;

	bdev = blkdev_get_by_path(path, pd_bio_fmode, pd_bio_holder);
	if (IS_ERR(bdev))
		return merr(PTR_ERR(bdev));

	dparm->dpr_dev_private = bdev;
	dparm->dpr_prop = *pd_prop;

	if ((pd_prop->pdp_devtype != PD_DEV_TYPE_BLOCK_STD) &&
	    (pd_prop->pdp_devtype != PD_DEV_TYPE_BLOCK_NVDIMM)) {
		merr_t err = merr(EINVAL);

		mp_pr_err("unsupported PD type %d", err, pd_prop->pdp_devtype);
		return err;
	}

	return 0;
}

merr_t pd_dev_close(struct pd_dev_parm *dparm)
{
	struct block_device *bdev = dparm->dpr_dev_private;

	if (bdev) {
		dparm->dpr_dev_private = NULL;
		sync_blockdev(bdev);
		invalidate_bdev(bdev);
		blkdev_put(bdev, pd_bio_fmode);
	}

	return bdev ? 0 : ev(EINVAL);
}

/**
 * pd_bio_discard_() - issue discard command to erase a byte-aligned region
 * @pd:
 * @off:
 * @len:
 */
static merr_t pd_bio_discard(struct mpool_dev_info  *pd, u64 off, size_t len)
{
	struct block_device    *bdev;
	merr_t                  err = 0;
	int                     rc;

	bdev = pd->pdi_parm.dpr_dev_private;
	if (!bdev) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s not registered", err, pd->pdi_name);
		return err;
	}

	/* Validate I/O offset is sector-aligned */
	if (off & PD_SECTORMASK(&pd->pdi_prop)) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s, offset 0x%lx not multiple of sec size %u",
			  err, pd->pdi_name, (ulong)off,
			  (1 << PD_SECTORSZ(&pd->pdi_prop)));
		return err;
	}

	if (off > PD_LEN(&(pd->pdi_prop))) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s, offset 0x%lx past end 0x%lx",
			  err, pd->pdi_name,
			  (ulong)off, (ulong)PD_LEN(&pd->pdi_prop));
		return err;
	}

	rc = blkdev_issue_discard(bdev, off >> SECTOR_SHIFT,
				  len >> SECTOR_SHIFT, GFP_NOIO, 0);
	if (rc) {
		err = merr(rc);
		mp_pr_err("bdev %s, offset 0x%lx len 0x%lx, discard faiure",
			  err, pd->pdi_name,
			  (ulong)off, (ulong)len);
	}

	return err;
}

/**
 * pd_bio_wrt_zero() - write zeros to a zone-aligned region
 * @pd:
 * @zoneaddr:
 * @zonecnt:
 * @afp:
 */
static merr_t
pd_bio_wrt_zero(struct mpool_dev_info *pd, u64 zoneaddr, u32 zonecnt)
{
	struct block_device    *bdev;
	merr_t                  err;
	size_t                  zonelen;
	size_t                  sector;
	size_t                  nr_sects;

	bdev = pd->pdi_parm.dpr_dev_private;
	if (!bdev) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s not registered", err, pd->pdi_name);
		return err;
	}

	zonelen = (u64)pd->pdi_parm.dpr_zonepg << PAGE_SHIFT;
	sector = (zoneaddr * zonelen) >> SECTOR_SHIFT;
	nr_sects = (zonecnt * zonelen) >> SECTOR_SHIFT;

	/*
	 * Zero filling LBA range either using write-same if device supports,
	 * or writing zeros as a fallback
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	err = blkdev_issue_zeroout(bdev, sector, nr_sects, GFP_NOIO, 0);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	err = blkdev_issue_zeroout(bdev, sector, nr_sects, GFP_NOIO, true);
#else
	err = blkdev_issue_zeroout(bdev, sector, nr_sects, GFP_NOIO);
#endif

	return ev(err);
}

#define CAN_BE_DISCARDED(a, b) \
	!(((a) & PD_CMD_DIF_ENABLED) && \
	  ((a) & PD_CMD_SED_ENABLED) && \
	  ((b) & PD_ERASE_READS_ERASED))

/**
 * pd_zone_erase() - issue write-zeros or discard commands to erase PD
 * @pd
 * @zoneaddr:
 * @zonecnt:
 * @flag:
 * @afp:
 */
merr_t
pd_zone_erase(
	struct mpool_dev_info  *pd,
	u64                     zoneaddr,
	u32                     zonecnt,
	enum pd_erase_flags     flags)
{
	merr_t          err = 0;
	u64             cmdopt;

	/* validate args against zone param */
	if (zoneaddr >= pd->pdi_parm.dpr_zonetot)
		return merr(EINVAL);

	if (zonecnt == 0)
		zonecnt = pd->pdi_parm.dpr_zonetot - zoneaddr;

	if (zonecnt > (pd->pdi_parm.dpr_zonetot - zoneaddr))
		return merr(EINVAL);

	if (zonecnt == 0)
		return 0;

	/*
	 * Will decide if we need to write zeros or issue discard commands
	 * to the drive. If  PD_ERASE_FZERO flag is set, write zeros.
	 * when both DIF and SED are enabled, read from a discared block
	 * would fail, so we can't discard blocks if both DIF and SED are
	 * enabled AND we need to read blocks after erase.
	 */
	cmdopt = pd->pdi_cmdopt;
	if (flags & PD_ERASE_FZERO) {
		err = pd_bio_wrt_zero(pd, zoneaddr, zonecnt);
	} else if ((cmdopt & PD_CMD_DISCARD) &&
		   CAN_BE_DISCARDED(cmdopt, flags)) {
		size_t zlen;

		zlen = pd->pdi_parm.dpr_zonepg << PAGE_SHIFT;
		err = pd_bio_discard(pd, zoneaddr * zlen, zonecnt * zlen);
	}

	return ev(err);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
#define SUBMIT_BIO(op, bio)            submit_bio((bio))
#define SUBMIT_BIO_WAIT(op, bio)       submit_bio_wait((bio))
#else
#define SUBMIT_BIO(op, bio)            submit_bio((op), (bio))
#define SUBMIT_BIO_WAIT(op, bio)       submit_bio_wait((op), (bio))
#endif


static __always_inline void
pd_bio_init(
	struct bio             *bio,
	struct block_device    *bdev,
	int                     rw,
	loff_t                  off,
	int                     op_flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	bio_set_op_attrs(bio, rw, op_flags);
	bio->bi_iter.bi_sector = off >> SECTOR_SHIFT;
#else
	bio->bi_rw = op_flags;
	bio->bi_sector = off >> SECTOR_SHIFT;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	bio_set_dev(bio, bdev);
#else
	bio->bi_bdev = bdev;
#endif
}

static __always_inline struct bio *
pd_bio_chain(
	struct bio         *target,
	int                 op,
	unsigned int        nr_pages,
	gfp_t               gfp)
{
	struct bio *new;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	new = bio_alloc_bioset(gfp, nr_pages, &mpool_bioset);
#else
	new = bio_alloc_bioset(gfp, nr_pages, mpool_bioset);
#endif

	if (!target)
		return new;

	if (new) {
		bio_chain(target, new);
		SUBMIT_BIO(op, target);
	} else {
		SUBMIT_BIO_WAIT(op, target);
		bio_put(target);
	}

	return new;
}

/*
 * pd_bio_rw() expects a list of iovecs wherein each base ptr is sector
 * aligned and each length is multiple of sectors.
 *
 * If the IO is bigger than 1MiB (BIO_MAX_PAGES pages),
 * it is split in several IOs smaller that BIO_MAX_PAGES.
 *
 * @pd:
 * @iov:
 * @iovcnt:
 * @off: offset in bytes on disk
 * @rw:
 * @op_flags:
 *
 * NOTE:
 * If the size of an I/O is bigger than "Max data transfer size(MDTS),
 * block layer will split the I/O. MDTS is also known as "max_sector_kb"
 * in sysfs. Due to a bug in linux kernel, when DIF is enabled all the
 * split I/Os share the same buffer to hold DIF tags.  All the split writes
 * are issued to the device with the same set of DIF tags, which are generated
 * for the first split write. Except the first split write device will reject
 * all other split writes, due to mismatch between data and DIF tags.
 * In order to use DIF with stock linux kernel, do not IOs larger than MDTS.
 */
static merr_t
pd_bio_rw(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	loff_t                  off,
	int                     rw,
	int                     op_flags)
{
	struct block_device    *bdev;
	struct bio             *bio;
	struct page            *page;
	struct request_queue   *q;
	merr_t                  err = 0;
	u64                     iov_base, sector_mask;
	u32                     tot_pages, tot_len, len, iov_len, left;
	u32                     iolimit;
	int                     i, cc, op, rc;

	if (iovcnt < 1)
		return 0;

	bdev = pd->pdi_parm.dpr_dev_private;
	if (!bdev) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s not registered", err, pd->pdi_name);
		return err;
	}

	sector_mask = PD_SECTORMASK(&pd->pdi_prop);
	if (ev(off & sector_mask)) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s, %s offset 0x%lx not multiple of sector size %u",
			  err, pd->pdi_name,
			  (rw == REQ_OP_READ) ? "read" : "write",
			  (ulong)off, (1 << PD_SECTORSZ(&pd->pdi_prop)));
		return err;
	}

	if (ev(off > PD_LEN(&(pd->pdi_prop)))) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s, %s offset 0x%lx past device end 0x%lx",
			  err, pd->pdi_name,
			  (rw == REQ_OP_READ) ? "read" : "write",
			  (ulong)off, (ulong)PD_LEN(&pd->pdi_prop));
		return err;
	}

	tot_pages = 0;
	tot_len = 0;
	for (i = 0; i < iovcnt; i++) {
		if (((uintptr_t)iov[i].iov_base & ~PAGE_MASK) ||
		    (iov[i].iov_len & sector_mask)) {
			err = merr(ev(EINVAL));
			mp_pr_err("bdev %s, %s offset 0x%lx, misaligned iovec, iovec base 0x%lx, iovec len 0x%lx",
				  err, pd->pdi_name,
				  (rw == REQ_OP_READ) ? "read" : "write",
				  (ulong)off,
				  (ulong)iov[i].iov_base,
				  (ulong)iov[i].iov_len);
			return err;
		}

		iov_len = iov[i].iov_len;
		tot_len += iov_len;
		while (iov_len > 0) {
			len = min_t(size_t, PAGE_SIZE, iov_len);
			iov_len -= len;
			tot_pages++;
		}
	}

	if (off + tot_len > PD_LEN(&(pd->pdi_prop))) {
		err = merr(ev(EINVAL));
		mp_pr_err("bdev %s, %s I/O end past device end 0x%lx, 0x%lx:0x%x",
			  err, pd->pdi_name,
			  (rw == REQ_OP_READ) ? "read" : "write",
			  (ulong)PD_LEN(&(pd->pdi_prop)),
			  (ulong)off, tot_len);
		return err;
	}

	if (tot_len == 0)
		return 0;

	/* IO size for each bio is determined by the chunker size. */
	iolimit = mpc_chunker_size >> PAGE_SHIFT;
	iolimit = clamp_t(u32, iolimit, 32, BIO_MAX_PAGES);

	/*
	 * TODO: the fix for the linux bug will be included in kernel 4.12
	 * we can remove this DIF workaround, once we move to 4.12 or beyond.
	 */
	q = bdev_get_queue(bdev);
	if (q && (pd->pdi_cmdopt & PD_CMD_DIF_ENABLED))
		iolimit = min_t(u32, iolimit,
				(q->limits.max_sectors << 9) >> PAGE_SHIFT);

	left = 0;
	bio = NULL;
	op = (rw == REQ_OP_READ) ? READ : WRITE;

	for (i = 0; i < iovcnt; i++) {
		iov_base = (u64)iov[i].iov_base;
		iov_len = iov[i].iov_len;

		while (iov_len > 0) {
			if (left == 0) {
				left = min_t(size_t, tot_pages, iolimit);

				bio = pd_bio_chain(bio, op, left, GFP_NOIO);
				if (!bio)
					return merr(ENOMEM);

				pd_bio_init(bio, bdev, rw, off, op_flags);
			}

			len = min_t(size_t, PAGE_SIZE, iov_len);
			page = virt_to_page(iov_base);
			cc = -1;

			if (page)
				cc = bio_add_page(bio, page, len, 0);

			if (cc != len) {
				if (cc == 0 && bio->bi_vcnt > 0) {
					left = 0;
					continue;
				}

				bio_io_error(bio);
				bio_put(bio);
				return merr(EBUG);
			}

			iov_len -= len;
			iov_base += len;
			off += len;
			left--;
			tot_pages--;
		}
	}

	assert(bio);
	assert(tot_pages == 0);

	rc = SUBMIT_BIO_WAIT(op, bio);
	if (rc)
		err = merr(rc);
	bio_put(bio);

	return err;
}

merr_t
pd_zone_pwritev(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	loff_t                  boff,
	int                     op_flags)
{
	loff_t woff;

	if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL)
		return merr(ev(EIO));

	woff = ((u64)pd->pdi_zonepg << PAGE_SHIFT) * zoneaddr + boff;

	return pd_bio_rw(pd, iov, iovcnt, woff, REQ_OP_WRITE, op_flags);
}

merr_t
pd_zone_pwritev_sync(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     zoneaddr,
	loff_t                  boff)
{
	merr_t		        err;
	struct block_device    *bdev;

	err = pd_zone_pwritev(pd, iov, iovcnt, zoneaddr, boff, REQ_FUA);
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
	loff_t                  boff)
{
	loff_t roff;

	if (mpool_pd_status_get(pd) == PD_STAT_UNAVAIL)
		return merr(ev(EIO));

	roff = ((u64)pd->pdi_zonepg << PAGE_SHIFT) * zoneaddr + boff;

	return pd_bio_rw(pd, iov, iovcnt, roff, REQ_OP_READ, 0);
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
