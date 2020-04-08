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

#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/version.h>

#include "mpcore_defs.h"


#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
#define REQ_PREFLUSH REQ_FLUSH
#endif

#ifndef IOV_MAX
#define IOV_MAX         (1024)
#endif

static const fmode_t    pd_bio_fmode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;
static char            *pd_bio_holder = "mpool";

merr_t pd_bio_dev_open(const char *path, struct pd_dev_parm *dparm)
{
	struct block_device *bdev;

	bdev = blkdev_get_by_path(path, pd_bio_fmode, pd_bio_holder);
	if (IS_ERR(bdev))
		return merr(PTR_ERR(bdev));

	dparm->dpr_dev_private = bdev;

	return 0;
}

merr_t pd_bio_dev_close(struct pd_dev_parm *dparm)
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

	rc = blkdev_issue_discard(bdev, off >> 9, len >> 9, GFP_NOIO, 0);
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
	sector = zoneaddr * zonelen / KSECSZ;
	nr_sects = zonecnt * zonelen / KSECSZ;

	/*
	 * Zero filling LBA range either using write-same if device supports,
	 * or writing zeros as a fallback
	 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	err = blkdev_issue_zeroout(bdev, sector, nr_sects,
		GFP_KERNEL, 0);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 0, 0)
	err = blkdev_issue_zeroout(bdev, sector, nr_sects,
		GFP_KERNEL, true);
#else
	err = blkdev_issue_zeroout(bdev, sector, nr_sects, GFP_KERNEL);
#endif

	return ev(err);
}

#define CAN_BE_DISCARDED(a, b) \
	!(((a) & PD_CMD_DIF_ENABLED) && \
	  ((a) & PD_CMD_SED_ENABLED) && \
	  ((b) & PD_ERASE_READS_ERASED))

/**
 * pd_bio_erase_sync() - issue write-zeros or discard commands to erase PD
 * @pd
 * @zoneaddr:
 * @zonecnt:
 * @flag:
 * @afp:
 */
merr_t
pd_bio_erase_sync(
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

merr_t pd_bio_flush_sync(struct mpool_dev_info *pd)
{
	struct block_device    *bdev;
	struct bio             *bio;
	merr_t                  err = 0;
	int                     rc;

	bdev = pd->pdi_parm.dpr_dev_private;

	if (!bdev) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s not registered", err, pd->pdi_name);
		return err;
	}

	/* Alloc BIO with zero iovec, since this is an empty flush IO */
	bio = bio_alloc(GFP_KERNEL, 0);
	if (!bio)
		return merr(ENOMEM);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	bio_set_dev(bio, bdev);
#else
	bio->bi_bdev = bdev;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0) || defined(MPOOL_DISTRO_EL7)
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_PREFLUSH);
#else
	bio->bi_rw    = REQ_OP_PREFLUSH;
#endif

	/*
	 * Submit an empty flush BIO to block layer. Block layer will decide
	 * if an flush request needs to be issued. If device doesn't
	 * have volatile write cache, this empty flush BIO will be a no-op.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	rc = submit_bio_wait(bio);
#else
	rc = submit_bio_wait(WRITE_FLUSH, bio);
#endif
	bio_put(bio);

	if (rc)
		err = merr(rc);

	return err;
}

/**
 * Call back passed to the driver along with a bio.
 * Called by the driver.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
static void pd_bio_rw_cb(struct bio *bio, int err)
#else
static void pd_bio_rw_cb(struct bio *bio)
#endif
{
	struct cb_context  *cbctx;

	cbctx = bio->bi_private;
	if (!cbctx) {
		bio_put(bio);
		return;
	}

	/* Store the first error occurence in the callback object. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
	atomic_cmpxchg(&cbctx->cb_ioerr, 0,
		       blk_status_to_errno(bio->bi_status));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
	atomic_cmpxchg(&cbctx->cb_ioerr, 0, bio->bi_error);
#else
	atomic_cmpxchg(&cbctx->cb_ioerr, 0, err);
#endif

	if (atomic_dec_and_test(&cbctx->cb_iocnt))
		complete(&cbctx->cb_iodone);

	bio_put(bio);
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
 */
merr_t
pd_bio_rw(
	struct mpool_dev_info  *pd,
	struct iovec           *iov,
	int                     iovcnt,
	u64                     off,
	int                     rw,
	int                     op_flags,
	struct cb_context      *cbctx)
{
	struct block_device    *bdev;
	struct bio             *bio;
	merr_t                  err = 0;
	u32                     left;
	u32                     tot_pages;
	u32                     tot_len;
	u32                     len;
	u64                     iov_base;
	u32                     iov_len;
	int                     i;
	u64                     sector_mask;
	struct page            *page;
	int                     cc;
	u32                     iolimit = BIO_MAX_PAGES;
	struct request_queue   *q;
	int                     rc;

	if (iovcnt < 1)
		return 0;

	bdev = pd->pdi_parm.dpr_dev_private;
	if (!bdev) {
		err = merr(EINVAL);
		mp_pr_err("bdev %s not registered", err, pd->pdi_name);
		return err;
	}

	/* Validate I/O offset is sector-aligned */
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

	/*
	 * Validate each iovec
	 * 1) base is page-aligned
	 * 2) len is sector-aligned
	 */
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

		/* Count number of pages in this iovec */
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

	left = 0;
	bio = NULL;

	/*
	 * If the size of an I/O is bigger than "Max data transfer size(MDTS),
	 * block layer will split the I/O. MDTS is also known as
	 * "max_sector_kb" in sysfs. Due to a bug in linux kernel, when DIF
	 * is enabled all the split I/Os share the same buffer to hold DIF tags.
	 * All the split writes are issued to the device with the same set of
	 * DIF tags, which are generated for the first split write. Except the
	 * first split write device will reject all other split writes, due to
	 * mismatch between data and DIF tags, In order to allow customers to
	 * use DIF with stock linux kernel, we splits big I/Os to avoid sending
	 * I/Os, whose size are bigger than MDTS.
	 *
	 * TODO: the fix for the linux bug will be included in kernel 4.12
	 * we can remove this workaround, once we move to 4.12 or beyond
	 */
	q = bdev_get_queue(bdev);
	if (q && (pd->pdi_cmdopt & PD_CMD_DIF_ENABLED))
		iolimit = min_t(u32, iolimit,
				q->limits.max_sectors * KSECSZ / PAGE_SIZE);

	for (i = 0; i < iovcnt; i++) {
		iov_base = (u64) iov[i].iov_base;
		iov_len = iov[i].iov_len;
		/*
		 * Add pages in this iovec into bio. If bio contains more
		 * than 256 (BIO_MAX_PAGES) pages, issue the bio. then
		 * allocate a new one
		 */
		while (iov_len > 0) {
			if (left == 0) {
				/*
				 * No space left in the current bio, or we
				 * need to allocate the first bio
				 */
				if (bio) {
					if (cbctx) {
						atomic_inc(&cbctx->cb_iocnt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
						submit_bio(bio);
#else
						submit_bio((rw == REQ_OP_READ) ?
							   READ : WRITE, bio);
#endif
					} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
						rc = submit_bio_wait(bio);
#else
						rc = submit_bio_wait((
							rw == REQ_OP_READ) ?
							READ : WRITE, bio);
#endif
						bio_put(bio);
						if (rc)
							err = merr(rc);
					}
				}

				/* Allocate a new bio */
				left = min_t(size_t, tot_pages, iolimit);
				bio = bio_alloc(GFP_KERNEL, left);
				if (!bio) {
					err = merr(ENOMEM);
					goto out;
				}

				if (cbctx) {
					bio->bi_private = cbctx;
					bio->bi_end_io = pd_bio_rw_cb;
				}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
				bio_set_op_attrs(bio, rw, op_flags);
				bio->bi_iter.bi_sector = off / KSECSZ;
#else
				bio->bi_rw = op_flags;
				bio->bi_sector = off / KSECSZ;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
				bio_set_dev(bio, bdev);
#else
				bio->bi_bdev = bdev;
#endif
			}

			len = min_t(size_t, PAGE_SIZE, iov_len);
			page = virt_to_page(iov_base);
			cc = -1;

			if (page)
				cc = bio_add_page(bio, page, len, 0);

			if (cc != len) {
				if (cc == 0 && bio->bi_vcnt > 0) {
					/*
					 * Failed to add this page to the
					 * current bio, issue the current
					 * bio, then retry adding this page
					 * in the next bio.
					 */
					left = 0;
					continue;
				}

				bio_put(bio);
				bio = NULL;
				err = merr(ev(EINVAL));
				goto out;
			}

			/* Update the progress */
			iov_len -= len;
			iov_base += len;
			left--;
			tot_pages--;
			off += len;
		}
	}

	if (bio) {
		/* Issue the last bio */
		assert(tot_pages == 0);
		if (cbctx) {
			atomic_inc(&cbctx->cb_iocnt);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
			submit_bio(bio);
#else
			submit_bio((rw == REQ_OP_READ) ? READ : WRITE, bio);
#endif
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
			rc = submit_bio_wait(bio);
#else
			rc = submit_bio_wait((rw == REQ_OP_READ) ?
					     READ : WRITE, bio);
#endif
			bio_put(bio);
			if (rc)
				err = merr(rc);
		}
	}

	if (cbctx && atomic_dec_and_test(&cbctx->cb_iocnt))
		complete(&cbctx->cb_iodone);
out:
	return err;
}
