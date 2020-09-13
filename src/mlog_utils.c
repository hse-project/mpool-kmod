// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/mm.h>
#include <linux/log2.h>
#include <linux/blk_types.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <asm/page.h>

#include "assert.h"
#include "mpool_printk.h"

#include "pmd_obj.h"
#include "mpcore.h"
#include "mlog.h"
#include "mlog_utils.h"

#define mlpriv2layout(_ptr) \
	((struct pmd_layout *)((char *)(_ptr) - offsetof(struct pmd_layout, eld_priv)))

bool mlog_objid(u64 objid)
{
	return objid && pmd_objid_type(objid) == OMF_OBJ_MLOG;
}

/**
 * mlog2layout() - convert opaque mlog handle to pmd_layout
 *
 * This function converts the opaque handle (mlog_descriptor) used by
 * clients to the internal representation (pmd_layout).  The
 * conversion is a simple cast, followed by a sanity check to verify the
 * layout object is an mlog object.  If the validation fails, a NULL
 * pointer is returned.
 */
struct pmd_layout *mlog2layout(struct mlog_descriptor *mlh)
{
	struct pmd_layout *layout = (void *)mlh;

	return mlog_objid(layout->eld_objid) ? layout : NULL;
}

/**
 * layout2mlog() - convert pmd_layout to opaque mlog_descriptor
 *
 * This function converts the internally used pmd_layout to
 * the externally used opaque mlog_descriptor.
 */
struct mlog_descriptor *layout2mlog(struct pmd_layout *layout)
{
	return (struct mlog_descriptor *)layout;
}

static struct pmd_layout_mlpriv *oml_layout_find(struct mpool_descriptor *mp, u64 key)
{
	struct pmd_layout_mlpriv *this;
	struct pmd_layout *layout;
	struct rb_node *node;

	node = mp->pds_oml_root.rb_node;
	while (node) {
		this = rb_entry(node, typeof(*this), mlp_nodeoml);
		layout = mlpriv2layout(this);

		if (key < layout->eld_objid)
			node = node->rb_left;
		else if (key > layout->eld_objid)
			node = node->rb_right;
		else
			return this;
	}

	return NULL;
}

struct pmd_layout_mlpriv *oml_layout_insert(struct mpool_descriptor *mp,
					    struct pmd_layout_mlpriv *item)
{
	struct pmd_layout_mlpriv *this;
	struct pmd_layout *layout;
	struct rb_node **pos, *parent;
	struct rb_root *root;
	u64 key;

	root = &mp->pds_oml_root;
	pos = &root->rb_node;
	parent = NULL;

	key = mlpriv2layout(item)->eld_objid;

	while (*pos) {
		this = rb_entry(*pos, typeof(*this), mlp_nodeoml);
		layout = mlpriv2layout(this);

		parent = *pos;
		if (key < layout->eld_objid)
			pos = &(*pos)->rb_left;
		else if (key > layout->eld_objid)
			pos = &(*pos)->rb_right;
		else
			return this;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&item->mlp_nodeoml, parent, pos);
	rb_insert_color(&item->mlp_nodeoml, root);

	return NULL;
}

struct pmd_layout_mlpriv *oml_layout_remove(struct mpool_descriptor *mp, u64 key)
{
	struct pmd_layout_mlpriv *found;

	found = oml_layout_find(mp, key);
	if (found)
		rb_erase(&found->mlp_nodeoml, &mp->pds_oml_root);

	return found;
}

/**
 * mlog_free_abuf() - Free log pages in the append buffer, range:[start, end].
 *
 * @lstat: mlog_stat
 * @start: start log page index, inclusive
 * @end:   end log page index, inclusive
 */
void mlog_free_abuf(struct mlog_stat *lstat, int start, int end)
{
	int i;

	for (i = start; i <= end; i++) {
		if (lstat->lst_abuf[i]) {
			free_page((unsigned long)lstat->lst_abuf[i]);
			lstat->lst_abuf[i] = NULL;
		}
	}
}

/**
 * mlog_free_rbuf() - Free log pages in the read buffer, range:[start, end].
 *
 * @lstat: mlog_stat
 * @start: start log page index, inclusive
 * @end:   end log page index, inclusive
 */
void mlog_free_rbuf(struct mlog_stat *lstat, int start, int end)
{
	int i;

	for (i = start; i <= end; i++) {
		if (lstat->lst_rbuf[i]) {
			free_page((unsigned long)lstat->lst_rbuf[i]);
			lstat->lst_rbuf[i] = NULL;
		}
	}
}

/**
 * mlog_init_fsetparms() - Initialize frequently used mlog & flush set
 * parameters.
 *
 * @mp:     mpool descriptor
 * @layout: layout descriptor
 * @mfp:    fset parameters (output)
 */
static void mlog_init_fsetparms(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
				struct mlog_fsetparms *mfp)
{
	struct pmd_layout *layout;
	struct pd_prop *pdp;
	u8 secshift;
	u16 sectsz;

	layout = mlog2layout(mlh);
	assert(layout);

	pdp = &mp->pds_pdv[layout->eld_ld.ol_pdh].pdi_prop;
	secshift = PD_SECTORSZ(pdp);
	mfp->mfp_totsec = pmd_layout_cap_get(mp, layout) >> secshift;

	sectsz = 1 << secshift;
	assert((sectsz == PAGE_SIZE) || (sectsz == 512));

	mfp->mfp_sectsz  = sectsz;
	mfp->mfp_lpgsz   = PAGE_SIZE;
	mfp->mfp_secpga  = IS_ALIGNED(mfp->mfp_sectsz, mfp->mfp_lpgsz);
	mfp->mfp_nlpgmb  = MB >> PAGE_SHIFT;
	mfp->mfp_nsecmb  = MB >> secshift;
	mfp->mfp_nseclpg = mfp->mfp_lpgsz >> secshift;
}

/**
 * mlog_extract_fsetparms() - Helper to extract flush set parameters.
 *
 * @lstat:   mlog stat
 * @sectsz:  sector size
 * @totsec:  total number of sectors in the mlog
 * @nsecmb:  number of sectors in 1 MiB
 * @nseclpg: number of sectors in a log page
 */
void
mlog_extract_fsetparms(struct mlog_stat *lstat, u16 *sectsz, u32 *totsec, u16 *nsecmb, u16 *nseclpg)
{
	if (sectsz)
		*sectsz  = MLOG_SECSZ(lstat);
	if (totsec)
		*totsec  = MLOG_TOTSEC(lstat);
	if (nsecmb)
		*nsecmb  = MLOG_NSECMB(lstat);
	if (nseclpg)
		*nseclpg = MLOG_NSECLPG(lstat);
}

/**
 * mlog_stat_free()
 *
 * Deallocate log stat struct for mlog layout (if any).
 */
void mlog_stat_free(struct pmd_layout *layout)
{
	struct mlog_stat *lstat = &layout->eld_lstat;

	if (!lstat->lst_abuf)
		return;

	mlog_free_rbuf(lstat, 0, MLOG_NLPGMB(lstat) - 1);
	mlog_free_abuf(lstat, 0, MLOG_NLPGMB(lstat) - 1);

	kfree(lstat->lst_abuf);
	lstat->lst_abuf = NULL;
}

/**
 * mlog_read_iter_init() - Initialize read iterator
 *
 * @layout: mlog layout
 * @lstat:  mlog stat
 * @lri"    mlog read iterator
 */
void
mlog_read_iter_init(struct pmd_layout *layout, struct mlog_stat *lstat, struct mlog_read_iter *lri)
{
	lri->lri_layout = layout;
	lri->lri_gen    = layout->eld_gen;
	lri->lri_soff   = 0;
	lri->lri_roff   = 0;
	lri->lri_valid  = 1;
	lri->lri_rbidx  = 0;
	lri->lri_sidx   = 0;

	lstat->lst_rsoff  = -1;
	lstat->lst_rseoff = -1;
}

/**
 * mlog_stat_init_common() - Initialize mlog_stat fields.
 * @layout:
 * @lstat: mlog_stat
 */
void mlog_stat_init_common(struct pmd_layout *layout, struct mlog_stat *lstat)
{
	struct mlog_read_iter *lri;

	lstat->lst_pfsetid = 0;
	lstat->lst_cfsetid = 1;
	lstat->lst_abidx   = 0;
	lstat->lst_asoff   = -1;
	lstat->lst_cfssoff = OMF_LOGBLOCK_HDR_PACKLEN;
	lstat->lst_aoff    = OMF_LOGBLOCK_HDR_PACKLEN;
	lstat->lst_abdirty = false;
	lstat->lst_wsoff   = 0;
	lstat->lst_cstart  = 0;
	lstat->lst_cend    = 0;

	lri = &lstat->lst_citr;
	mlog_read_iter_init(layout, lstat, lri);
}

/**
 * mlog_rw_raw() - Called by mpctl kernel for mlog IO.
 * @mp:     mpool descriptor
 * @mlh:    mlog descriptor
 * @iov:    iovec
 * @iovcnt: iov cnt
 * @boff:   IO offset
 * @rw:     MPOOL_OP_READ or MPOOL_OP_WRITE
 *
 * The scatter-gather buffer must contain
 * framed mlog data (this is done in user space for user space mlogs).
 */
int mlog_rw_raw(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
		const struct kvec *iov, int iovcnt, u64 boff, u8 rw)
{
	struct pmd_layout *layout;
	int flags;
	int rc;

	layout = mlog2layout(mlh);
	if (!layout)
		return -EINVAL;

	flags = (rw == MPOOL_OP_WRITE) ? REQ_FUA : 0;

	pmd_obj_wrlock(layout);
	rc = pmd_layout_rw(mp, layout, iov, iovcnt, boff, flags, rw);
	pmd_obj_wrunlock(layout);

	return rc;
}

/**
 * mlog_rw() -
 * @mp:       mpool descriptor
 * @mlh:      mlog descriptor
 * @iov:      iovec
 * @iovcnt:   iov cnt
 * @boff:     IO offset
 * @rw:       MPOOL_OP_READ or MPOOL_OP_WRITE
 * @skip_ser: client guarantees serialization
 */
static int mlog_rw(struct mpool_descriptor *mp, struct mlog_descriptor *mlh,
		   struct kvec *iov, int iovcnt, u64 boff, u8 rw, bool skip_ser)
{
	struct pmd_layout *layout;

	layout = mlog2layout(mlh);
	if (!layout)
		return -EINVAL;

	if (!skip_ser) {
		int flags = (rw == MPOOL_OP_WRITE) ? REQ_FUA : 0;

		return pmd_layout_rw(mp, layout, iov, iovcnt, boff, flags, rw);
	}

	return mlog_rw_raw(mp, mlh, iov, iovcnt, boff, rw);
}

/**
 * mlog_stat_init() - Allocate and init log stat struct for mlog layout.
 *
 * Returns: 0 if successful, -errno otherwise
 */
int mlog_stat_init(struct mpool_descriptor *mp, struct mlog_descriptor *mlh, bool csem)
{
	struct pmd_layout *layout = mlog2layout(mlh);
	struct mlog_fsetparms mfp;
	struct mlog_stat *lstat;
	size_t bufsz;
	int rc;

	if (!layout)
		return -EINVAL;

	lstat = &layout->eld_lstat;

	mlog_stat_init_common(layout, lstat);
	mlog_init_fsetparms(mp, mlh, &mfp);

	bufsz = mfp.mfp_nlpgmb * sizeof(char *) * 2;

	lstat->lst_abuf = kzalloc(bufsz, GFP_KERNEL);
	if (!lstat->lst_abuf) {
		rc = -ENOMEM;
		mp_pr_err("mpool %s, allocating mlog 0x%lx status failed %zu",
			  rc, mp->pds_name, (ulong)layout->eld_objid, bufsz);
		return rc;
	}

	lstat->lst_rbuf = lstat->lst_abuf + mfp.mfp_nlpgmb;
	lstat->lst_mfp  = mfp;
	lstat->lst_csem = csem;

	return 0;
}

/**
 * mlog_setup_buf() - Build an iovec list to read into an mlog read buffer, or write from
 * an mlog append buffer.
 * @lstat:   mlog_stat
 * @riov:    iovec (output)
 * @iovcnt:  number of iovecs
 * @l_iolen: IO length for the last log page in the buffer
 * @op:      MPOOL_OP_READ or MPOOL_OP_WRITE
 *
 * In the read case, the read buffer pages will be allocated if not already populated.
 */
static int
mlog_setup_buf(struct mlog_stat *lstat, struct kvec **riov, u16 iovcnt, u32 l_iolen, u8 op)
{
	struct kvec *iov = *riov;
	u32 len = MLOG_LPGSZ(lstat);
	bool alloc_iov = false;
	u16 i;
	char *buf;

	assert(len == PAGE_SIZE);
	assert(l_iolen <= PAGE_SIZE);

	if (!iov) {
		assert((iovcnt * sizeof(*iov)) <= PAGE_SIZE);

		iov = kcalloc(iovcnt, sizeof(*iov), GFP_KERNEL);
		if (!iov)
			return -ENOMEM;

		alloc_iov = true;
		*riov = iov;
	}

	for (i = 0; i < iovcnt; i++, iov++) {

		buf = ((op == MPOOL_OP_READ) ? lstat->lst_rbuf[i] : lstat->lst_abuf[i]);

		/* iov_len for the last log page in read/write buffer. */
		if (i == iovcnt - 1 && l_iolen != 0)
			len = l_iolen;

		assert(IS_ALIGNED(len, MLOG_SECSZ(lstat)));

		if (op == MPOOL_OP_WRITE && buf) {
			iov->iov_base = buf;
			iov->iov_len  = len;
			continue;
		}

		/*
		 * Pages for the append buffer are allocated in
		 * mlog_append_*(), so we shouldn't be here for MPOOL_OP_WRITE.
		 */
		assert(op == MPOOL_OP_READ);

		/*
		 * If the read buffer contains stale log pages from a prior
		 * iterator, reuse them. No need to zero these pages for
		 * the same reason provided in the following comment.
		 */
		if (buf) {
			iov->iov_base = buf;
			iov->iov_len  = len;
			continue;
		}

		/*
		 * No need to zero the read buffer as we never read more than
		 * what's needed and do not consume beyond what's read.
		 */
		buf = (char *)__get_free_page(GFP_KERNEL);
		if (!buf) {
			mlog_free_rbuf(lstat, 0, i - 1);
			if (alloc_iov) {
				kfree(iov);
				*riov = NULL;
			}

			return -ENOMEM;
		}

		/*
		 * Must be a page-aligned buffer so that it can be used
		 * in bio_add_page().
		 */
		assert(PAGE_ALIGNED(buf));

		lstat->lst_rbuf[i] = iov->iov_base = buf;
		iov->iov_len = len;
	}

	return 0;
}

/**
 * mlog_populate_abuf() - Makes append offset page-aligned and performs the
 * read operation in the read-modify-write cycle.
 * @mp:       mpool descriptor
 * @layout:   layout descriptor
 * @soff:     sector/LB offset
 * @buf:      buffer to populate. Size of this buffer must be MLOG_LPGSZ(lstat).
 * @skip_ser: client guarantees serialization
 *
 * This is to ensure that IO-requests to the device are always 4K-aligned.
 * The read-modify-write cycle happens *only* if the first append post mlog
 * open lands on a non-page aligned sector offset. For any further appends,
 * read-modify-write cycle doesn't happen, as the 4k-aligned version of the
 * flush set algorithm ensures 4k-alignment of sector offsets at the start
 * of each log page.
 */
static int mlog_populate_abuf(struct mpool_descriptor *mp, struct pmd_layout *layout,
			      off_t *soff, char *buf, bool skip_ser)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	struct kvec iov;
	u16 sectsz, iovcnt, leading;
	off_t off;
	u32 leadb;
	int rc;

	sectsz = MLOG_SECSZ(lstat);

	/* Find the leading number of sectors to make it page-aligned. */
	leading = ((*soff * sectsz) & ~PAGE_MASK) >> ilog2(sectsz);
	if (leading == 0)
		return 0; /* Nothing to do */

	*soff = *soff - leading;
	leadb = leading * sectsz;

	iovcnt       = 1;
	iov.iov_base = buf;
	iov.iov_len  = MLOG_LPGSZ(lstat);

	off = *soff * sectsz;
	assert(IS_ALIGNED(off, MLOG_LPGSZ(lstat)));

	rc = mlog_rw(mp, layout2mlog(layout), &iov, iovcnt, off, MPOOL_OP_READ, skip_ser);
	if (rc) {
		mp_pr_err("mpool %s, mlog 0x%lx, read IO failed, iovcnt: %u, off: 0x%lx",
			  rc, mp->pds_name, (ulong)layout->eld_objid, iovcnt, off);

		return rc;
	}

	memset(&buf[leadb], 0, MLOG_LPGSZ(lstat) - leadb);

	return 0;
}

/**
 * mlog_populate_rbuf() - Fill the read buffer after aligning the read offset to page boundary.
 * @mp:       mpool descriptor
 * @layout:   layout descriptor
 * @nsec:     number of sectors to populate
 * @soff:     start sector/LB offset
 * @skip_ser: client guarantees serialization
 *
 * Having the read offsets page-aligned avoids unnecessary
 * complexity at the pd layer.
 *
 * In the worst case, for 512 byte sectors, we would end up reading 7
 * additional sectors, which is acceptable. There won't be any overhead for
 * 4 KiB sectors as they are naturally page-aligned.
 *
 * Caller must hold the write lock on the layout.
 */
int mlog_populate_rbuf(struct mpool_descriptor *mp, struct pmd_layout *layout,
		       u16 *nsec, off_t *soff, bool skip_ser)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	struct kvec *iov = NULL;
	u16 maxsec, sectsz, iovcnt, nseclpg, leading;
	off_t off;
	u32 l_iolen;
	int rc;

	mlog_extract_fsetparms(lstat, &sectsz, NULL, &maxsec, &nseclpg);

	/* Find the leading number of sectors to make it page-aligned. */
	leading = ((*soff * sectsz) & ~PAGE_MASK) >> ilog2(sectsz);
	*soff   = *soff - leading;
	*nsec  += leading;

	*nsec   = min_t(u32, maxsec, *nsec);
	iovcnt  = (*nsec + nseclpg - 1) / nseclpg;
	l_iolen = MLOG_LPGSZ(lstat);

	rc = mlog_setup_buf(lstat, &iov, iovcnt, l_iolen, MPOOL_OP_READ);
	if (rc) {
		mp_pr_err("mpool %s, mlog 0x%lx setup failed, iovcnt: %u, last iolen: %u",
			  rc, mp->pds_name, (ulong)layout->eld_objid, iovcnt, l_iolen);

		return rc;
	}

	off = *soff * sectsz;
	assert(IS_ALIGNED(off, MLOG_LPGSZ(lstat)));

	rc = mlog_rw(mp, layout2mlog(layout), iov, iovcnt, off, MPOOL_OP_READ, skip_ser);
	if (rc) {
		mp_pr_err("mpool %s, mlog 0x%lx populate rbuf, IO failed iovcnt: %u, off: 0x%lx",
			  rc, mp->pds_name, (ulong)layout->eld_objid, iovcnt, off);

		mlog_free_rbuf(lstat, 0, MLOG_NLPGMB(lstat) - 1);
		kfree(iov);

		return rc;
	}

	/*
	 * If there're any unused buffers beyond iovcnt, free it. This is
	 * likely to happen when there're multiple threads reading from
	 * the same mlog simultaneously, using their own iterator.
	 */
	mlog_free_rbuf(lstat, iovcnt, MLOG_NLPGMB(lstat) - 1);

	kfree(iov);

	return 0;
}

/**
 * mlog_alloc_abufpg() - Allocate a log page at append buffer index 'abidx'.
 * @mp:       mpool descriptor
 * @layout:   layout descriptor
 * @abidx:    allocate log page at index 'abidx'.
 * @skip_ser: client guarantees serialization
 *
 * If the sector size is 512B AND 4K-alignment is forced AND the append offset
 * at buffer index '0' is not 4K-aligned, then call mlog_populate_abuf().
 */
static int mlog_alloc_abufpg(struct mpool_descriptor *mp, struct pmd_layout *layout,
			     u16 abidx, bool skip_ser)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	char *abuf;

	assert(MLOG_LPGSZ(lstat) == PAGE_SIZE);

	abuf = (char *)get_zeroed_page(GFP_KERNEL);
	if (!abuf)
		return -ENOMEM;

	assert(PAGE_ALIGNED(abuf));

	lstat->lst_abuf[abidx] = abuf;

	if (abidx == 0) {
		off_t  asoff;
		off_t  wsoff;
		u16    aoff;
		u16    sectsz;
		int    rc;

		/* This path is taken *only* for the first append following an mlog_open(). */
		sectsz = MLOG_SECSZ(lstat);
		wsoff  = lstat->lst_wsoff;
		aoff   = lstat->lst_aoff;

		if (IS_SECPGA(lstat) || (IS_ALIGNED(wsoff * sectsz, MLOG_LPGSZ(lstat)))) {
			/* This is the common path */
			lstat->lst_asoff = wsoff;
			return 0;
		}

		/*
		 * This path is taken *only* if,
		 * - the log block size is 512B AND
		 * - lst_wsoff is non page-aligned, which is possible for the
		 *   first append post mlog_open.
		 */
		asoff = wsoff;
		rc = mlog_populate_abuf(mp, layout, &asoff, abuf, skip_ser);
		if (rc) {
			mlog_free_abuf(lstat, abidx, abidx);
			mp_pr_err("mpool %s, mlog 0x%lx, making write offset %ld 4K-aligned failed",
				  rc, mp->pds_name, (ulong)layout->eld_objid, wsoff);

			return rc;
		}

		assert(asoff <= wsoff);
		assert(IS_ALIGNED(asoff * sectsz, MLOG_LPGSZ(lstat)));
		lstat->lst_cfssoff = ((wsoff - asoff) * sectsz) + aoff;
		lstat->lst_asoff   = asoff;
	}

	return 0;
}

/**
 * mlog_flush_abuf() - Set up iovec and flush the append buffer to media.
 * @mp:       mpool descriptor
 * @layout:   layout descriptor
 * @skip_ser: client guarantees serialization
 */
static int mlog_flush_abuf(struct mpool_descriptor *mp, struct pmd_layout *layout, bool skip_ser)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	struct kvec *iov = NULL;
	u16    abidx, sectsz, nseclpg;
	off_t  off;
	u32    l_iolen;
	int    rc;

	mlog_extract_fsetparms(lstat, &sectsz, NULL, NULL, &nseclpg);

	abidx   = lstat->lst_abidx;
	l_iolen = MLOG_LPGSZ(lstat);

	rc = mlog_setup_buf(lstat, &iov, abidx + 1, l_iolen, MPOOL_OP_WRITE);
	if (rc) {
		mp_pr_err("mpool %s, mlog 0x%lx flush, buf setup failed, iovcnt: %u, iolen: %u",
			  rc, mp->pds_name, (ulong)layout->eld_objid, abidx + 1, l_iolen);

		return rc;
	}

	off = lstat->lst_asoff * sectsz;

	assert((IS_ALIGNED(off, MLOG_LPGSZ(lstat))) ||
		(IS_SECPGA(lstat) && IS_ALIGNED(off, MLOG_SECSZ(lstat))));

	rc = mlog_rw(mp, layout2mlog(layout), iov, abidx + 1, off, MPOOL_OP_WRITE, skip_ser);
	if (rc) {
		mp_pr_err("mpool %s, mlog 0x%lx flush append buf, IO failed iovcnt %u, off 0x%lx",
			  rc, mp->pds_name, (ulong)layout->eld_objid, abidx + 1, off);
		kfree(iov);

		return rc;
	}

	kfree(iov);

	return 0;
}

/**
 * mlog_flush_posthdlr_4ka() - Handles both successful and failed flush for 512B sectors with 4K-Alignment.
 * @layout: layout descriptor
 * @fsucc:  flush status
 */
static void mlog_flush_posthdlr_4ka(struct pmd_layout *layout, bool fsucc)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	u16    abidx, sectsz, asidx;
	off_t  asoff, wsoff;
	char  *abuf;
	u32    nsecwr;

	sectsz = MLOG_SECSZ(lstat);
	abidx  = lstat->lst_abidx;
	asoff  = lstat->lst_asoff;
	wsoff  = lstat->lst_wsoff;

	asidx  = wsoff - ((MLOG_NSECLPG(lstat) * abidx) + asoff);

	/* Set the current filling log page index to 0. */
	lstat->lst_abidx = 0;
	abuf = lstat->lst_abuf[0];

	if (!fsucc) {
		u32    cfssoff;

		/*
		 * Last CFS flush or header packing failed.
		 * Retain the pfsetid of the first log block.
		 */
		cfssoff = lstat->lst_cfssoff;
		memset(&abuf[cfssoff], 0, MLOG_LPGSZ(lstat) - cfssoff);
		asidx = (cfssoff >> ilog2(sectsz));
		lstat->lst_aoff  = cfssoff - (asidx * sectsz);
		lstat->lst_wsoff = asoff + asidx;

		goto exit2;
	}

	/* Last CFS flush succeded. */
	if (abidx != 0) {
		/* Reorganize buffers if the active log page not at index 0. */
		abuf = lstat->lst_abuf[abidx];
		lstat->lst_abuf[abidx] = NULL;
	}

	nsecwr = wsoff - (asoff + (lstat->lst_cfssoff >> ilog2(sectsz)));
	asoff  = wsoff - asidx;

	/* The last logblock of the just-written CFS is not full. */
	if (sectsz - lstat->lst_aoff >= OMF_LOGREC_DESC_PACKLEN) {
		if (nsecwr != 0)
			/* Set pfsetid to the cfsetid of just-written CFS. */
			lstat->lst_pfsetid  = lstat->lst_cfsetid;

		goto exit1;
	}

	/* The last logblock of the just-written CFS is full. */
	lstat->lst_aoff = OMF_LOGBLOCK_HDR_PACKLEN;
	++wsoff;
	if ((wsoff - asoff) == MLOG_NSECLPG(lstat)) {
		memset(&abuf[0], 0, MLOG_LPGSZ(lstat));
		asoff = wsoff;
	}
	/* Set pfsetid to the cfsetid of just-written CFS. */
	lstat->lst_pfsetid  = lstat->lst_cfsetid;

exit1:
	asidx              = wsoff - asoff;
	lstat->lst_cfssoff = (asidx * sectsz) + lstat->lst_aoff;
	lstat->lst_asoff   = asoff;
	lstat->lst_wsoff   = wsoff;

exit2:
	/* Increment cfsetid in all cases. */
	++lstat->lst_cfsetid;

	lstat->lst_abuf[0] = abuf;
}

/**
 * mlog_flush_posthdlr() - Handles both successful and failed flush for
 * 512B and 4K-sectors with native alignment, i.e., 512B and 4K resply.
 *
 * @layout: layout descriptor
 * @fsucc:  flush status
 */
static void mlog_flush_posthdlr(struct pmd_layout *layout, bool fsucc)
{
	struct mlog_stat *lstat = &layout->eld_lstat;

	char  *abuf;
	off_t  asoff;
	off_t  lpgoff;
	u16    abidx;
	u16    sectsz;
	u16    asidx;

	sectsz = MLOG_SECSZ(lstat);
	abidx  = lstat->lst_abidx;
	asoff  = lstat->lst_asoff;

	asidx  = lstat->lst_wsoff - ((MLOG_NSECLPG(lstat) * abidx) + asoff);
	lpgoff = asidx * sectsz;

	/* Set the current filling log page index to 0. */
	lstat->lst_abidx = 0;
	abuf = lstat->lst_abuf[0];

	if (!fsucc) {
		u32    cfssoff;

		/*
		 * Last CFS flush or header packing failed.
		 * Retain the pfsetid of the first log block.
		 */
		cfssoff = lstat->lst_cfssoff;
		memset(&abuf[cfssoff], 0, MLOG_LPGSZ(lstat) - cfssoff);
		lstat->lst_aoff  = cfssoff;
		lstat->lst_wsoff = asoff;

		goto exit2;
	}

	/* Last CFS flush succeded. */
	if (abidx != 0) {
		/* Reorganize buffers if the active log page not at index 0. */
		abuf = lstat->lst_abuf[abidx];
		lstat->lst_abuf[abidx] = NULL;
	}

	/* The last logblock of the just-written CFS is not full. */
	if (sectsz - lstat->lst_aoff >= OMF_LOGREC_DESC_PACKLEN) {
		/*
		 * If the last logblock in the just-written CFS is
		 * first in the append buffer at abidx.
		 */
		if (lpgoff == 0) {
			if (abidx != 0)
				lstat->lst_pfsetid = lstat->lst_cfsetid;

			goto exit1;
		}

		memcpy(&abuf[0], &abuf[lpgoff], sectsz);
		memset(&abuf[sectsz], 0, lpgoff - sectsz + lstat->lst_aoff);
	} else { /* The last logblock of the just-written CFS is full. */
		memset(&abuf[0], 0, lpgoff + sectsz);
		lstat->lst_aoff = OMF_LOGBLOCK_HDR_PACKLEN;
		++lstat->lst_wsoff;
	}
	/* Set pfsetid to the cfsetid of just-written CFS. */
	lstat->lst_pfsetid  = lstat->lst_cfsetid;

exit1:
	lstat->lst_cfssoff = lstat->lst_aoff;
	lstat->lst_asoff   = lstat->lst_wsoff;

exit2:
	/* Increment cfsetid in all cases. */
	++lstat->lst_cfsetid;

	lstat->lst_abuf[0] = abuf;
}

/**
 * mlog_logblocks_hdrpack() -  Pack log block header in all log blocks in the append buffer.
 * @layout: object layout
 *
 * Called prior to CFS flush
 */
static int mlog_logblocks_hdrpack(struct pmd_layout *layout)
{
	struct omf_logblock_header lbh;
	struct mlog_stat *lstat = &layout->eld_lstat;
	off_t lpgoff;
	u32 pfsetid, cfsetid;
	u16 sectsz, nseclpg;
	u16 idx, abidx;
	u16 sec, start;

	sectsz  = MLOG_SECSZ(lstat);
	nseclpg = MLOG_NSECLPG(lstat);
	abidx   = lstat->lst_abidx;
	pfsetid = lstat->lst_pfsetid;
	cfsetid = lstat->lst_cfsetid;

	lbh.olh_vers = OMF_LOGBLOCK_VERS;

	for (idx = 0; idx <= abidx; idx++) {
		start = 0;

		if (!IS_SECPGA(lstat) && idx == 0)
			start = (lstat->lst_cfssoff >> ilog2(sectsz));

		if (idx == abidx)
			nseclpg = lstat->lst_wsoff - (nseclpg * abidx + lstat->lst_asoff) + 1;

		for (sec = start; sec < nseclpg; sec++) {
			int rc;

			lbh.olh_pfsetid = pfsetid;
			lbh.olh_cfsetid = cfsetid;
			mpool_uuid_copy(&lbh.olh_magic, &layout->eld_uuid);
			lbh.olh_gen = layout->eld_gen;
			lpgoff = sec * sectsz;

			/* Pack the log block header. */
			rc = omf_logblock_header_pack_htole(&lbh, &lstat->lst_abuf[idx][lpgoff]);
			if (rc) {
				mp_pr_err("mlog packing lbh failed, log pg idx %u, vers %u failed",
					  rc, idx, lbh.olh_vers);

				return rc;
			}

			/* If there's more than one sector to flush, pfsetid is set to cfsetid. */
			pfsetid = cfsetid;
		}
	}

	return 0;
}

/**
 * mlog_logblocks_flush() - Flush CFS and handle both successful and failed flush.
 * @mp:       mpool descriptor
 * @layout:   layout descriptor
 * @skip_ser: client guarantees serialization
 */
int mlog_logblocks_flush(struct mpool_descriptor *mp, struct pmd_layout *layout, bool skip_ser)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	int    start, end, rc;
	bool   fsucc = true;
	u16    abidx;

	abidx = lstat->lst_abidx;

	/* Pack log block header in all the log blocks. */
	rc = mlog_logblocks_hdrpack(layout);
	if (rc) {
		mp_pr_err("mpool %s, mlog 0x%lx packing header failed",
			  rc, mp->pds_name, (ulong)layout->eld_objid);

	} else {
		rc = mlog_flush_abuf(mp, layout, skip_ser);
		if (rc)
			mp_pr_err("mpool %s, mlog 0x%lx log block flush failed",
				  rc, mp->pds_name, (ulong)layout->eld_objid);
	}

	if (rc) {
		/* If flush failed, free all log pages except the first one. */
		start = 1;
		end   = abidx;
		fsucc = false;
	} else {
		/* If flush succeeded, free all log pages except the last one.*/
		start = 0;
		end   = abidx - 1;

		/*
		 * Inform pre-compaction of the size of the active mlog and
		 * how much is used.
		 */
		pmd_precompact_alsz(mp, layout->eld_objid, lstat->lst_wsoff * MLOG_SECSZ(lstat),
				    lstat->lst_mfp.mfp_totsec * MLOG_SECSZ(lstat));
	}
	mlog_free_abuf(lstat, start, end);

	if (!IS_SECPGA(lstat))
		mlog_flush_posthdlr_4ka(layout, fsucc);
	else
		mlog_flush_posthdlr(layout, fsucc);

	return rc;
}

/**
 * mlog_append_dmax()
 *
 * Max data record that can be appended to log in bytes; -1 if no room
 * for a 0 byte data record due to record descriptor length.
 */
s64 mlog_append_dmax(struct pmd_layout *layout)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	u64 lbmax, lbrest;
	u32 sectsz, datalb;

	sectsz = MLOG_SECSZ(lstat);
	datalb = MLOG_TOTSEC(lstat);

	if (lstat->lst_wsoff >= datalb) {
		/* Mlog already full */
		return -1;
	}

	lbmax  = (sectsz - OMF_LOGBLOCK_HDR_PACKLEN - OMF_LOGREC_DESC_PACKLEN);
	lbrest = (datalb - lstat->lst_wsoff - 1) * lbmax;

	if ((sectsz - lstat->lst_aoff) < OMF_LOGREC_DESC_PACKLEN) {
		/* Current log block cannot hold even a record descriptor */
		if (lbrest)
			return lbrest;

		return -1;
	}

	/*
	 * Can start in current log block and spill over to others (if any)
	 */
	return sectsz - lstat->lst_aoff - OMF_LOGREC_DESC_PACKLEN + lbrest;
}

/**
 * mlog_update_append_idx() -
 *
 * Check whether the active log block is full and update the append offsets
 * accordingly.
 *
 * Returns: 0 on success; -errno otherwise
 */
int mlog_update_append_idx(struct mpool_descriptor *mp, struct pmd_layout *layout, bool skip_ser)
{
	struct mlog_stat *lstat = &layout->eld_lstat;
	u16 sectsz, nseclpg, abidx, asidx;
	int rc;

	sectsz  = MLOG_SECSZ(lstat);
	nseclpg = MLOG_NSECLPG(lstat);

	if (sectsz - lstat->lst_aoff < OMF_LOGREC_DESC_PACKLEN) {
		/* If the log block is full, move to the next log block in the buffer. */
		abidx = lstat->lst_abidx;
		asidx = lstat->lst_wsoff - ((nseclpg * abidx) + lstat->lst_asoff);
		if (asidx == nseclpg - 1)
			++lstat->lst_abidx;
		++lstat->lst_wsoff;
		lstat->lst_aoff = OMF_LOGBLOCK_HDR_PACKLEN;
	}

	abidx = lstat->lst_abidx;
	if (!lstat->lst_abuf[abidx]) {
		/* Allocate a log page at 'abidx' */
		rc = mlog_alloc_abufpg(mp, layout, abidx, skip_ser);
		if (rc)
			return rc;
	}

	return 0;
}

/**
 * mlog_logblocks_load_media() - Read log blocks from media, upto a maximum of 1 MiB.
 * @mp:    mpool descriptor
 * @lri:   read iterator
 * @inbuf: buffer to into (output)
 */
static int mlog_logblocks_load_media(struct mpool_descriptor *mp, struct mlog_read_iter *lri,
				     char **inbuf)
{
	struct pmd_layout *layout = lri->lri_layout;
	struct mlog_stat *lstat = &layout->eld_lstat;
	u16 maxsec, nsecs, sectsz;
	bool skip_ser = false;
	off_t rsoff;
	int remsec, rc;

	mlog_extract_fsetparms(lstat, &sectsz, NULL, &maxsec, NULL);

	/*
	 * The read and append buffer must never overlap. So, the read buffer
	 * can only hold sector offsets in the range [0, lstat->lst_asoff - 1].
	 */
	if (lstat->lst_asoff < 0)
		remsec = lstat->lst_wsoff;
	else
		remsec = lstat->lst_asoff;

	if (remsec == 0) {
		rc = -ENOTRECOVERABLE;
		mp_pr_err("mpool %s, objid 0x%lx, mlog read cannot be served from read buffer",
			  rc, mp->pds_name, (ulong)lri->lri_layout->eld_objid);
		return rc;
	}

	lri->lri_rbidx = 0;
	lri->lri_sidx  = 0;

	rsoff   = lri->lri_soff;
	remsec -= rsoff;
	assert(remsec > 0);
	nsecs   = min_t(u32, maxsec, remsec);

	if (layout->eld_flags & MLOG_OF_SKIP_SER)
		skip_ser = true;

	rc = mlog_populate_rbuf(mp, lri->lri_layout, &nsecs, &rsoff, skip_ser);
	if (rc) {
		mp_pr_err("mpool %s, objid 0x%lx, mlog read failed, nsecs: %u, rsoff: 0x%lx",
			  rc, mp->pds_name, (ulong)lri->lri_layout->eld_objid, nsecs, rsoff);

		lstat->lst_rsoff = lstat->lst_rseoff = -1;

		return rc;
	}

	/*
	 * 'nsecs' and 'rsoff' can be changed by mlog_populate_rbuf, if the
	 * read offset is not page-aligned. Adjust lri_sidx and lst_rsoff
	 * accordingly.
	 */
	lri->lri_sidx     = lri->lri_soff - rsoff;
	lstat->lst_rsoff  = rsoff;
	lstat->lst_rseoff = rsoff + nsecs - 1;

	*inbuf = lstat->lst_rbuf[lri->lri_rbidx];
	*inbuf += lri->lri_sidx * sectsz;

	return 0;
}

/**
 * mlog_logblock_load_internal() - Read log blocks from either the read buffer or media.
 * @mp:    mpool descriptor
 * @lri:   read iterator
 * @inbuf: buffer to load into (output)
 */
static int mlog_logblock_load_internal(struct mpool_descriptor *mp, struct mlog_read_iter *lri,
				       char **inbuf)
{
	struct mlog_stat *lstat;
	off_t rsoff, rseoff, soff;
	u16 nsecs, rbidx, rsidx;
	u16 nlpgs, nseclpg;
	int rc;

	lstat = &lri->lri_layout->eld_lstat;

	nseclpg = MLOG_NSECLPG(lstat);
	rbidx   = lri->lri_rbidx;
	rsidx   = lri->lri_sidx;
	soff    = lri->lri_soff;
	rsoff   = lstat->lst_rsoff;
	rseoff  = lstat->lst_rseoff;

	if (rsoff < 0)
		goto media_read;

	/*
	 * If the read offset doesn't fall within the read buffer range,
	 * then media read.
	 */
	if ((soff < rsoff) || (soff > rseoff))
		goto media_read;

	do {
		/* If this is not the start of log block. */
		if (lri->lri_roff != 0)
			break;

		/* Check if there's unconsumed data in rbuf. */
		nsecs = rseoff - rsoff + 1;
		nlpgs = (nsecs + nseclpg - 1) / nseclpg;

		/* No. of sectors in the last log page. */
		if (rbidx == nlpgs - 1) {
			nseclpg = nsecs % nseclpg;
			nseclpg = nseclpg > 0 ? nseclpg : MLOG_NSECLPG(lstat);
		}
		/* Remaining sectors in the active log page? */
		if (rsidx < nseclpg - 1) {
			++rsidx;
			break;
		}
		/* Remaining log pages in the read buffer? */
		if (rbidx >= nlpgs - 1)
			goto media_read;

		/* Free the active log page and move to next one. */
		mlog_free_rbuf(lstat, rbidx, rbidx);
		++rbidx;
		rsidx = 0;

		break;
	} while (0);

	/* Serve data from the read buffer. */
	*inbuf  = lstat->lst_rbuf[rbidx];
	*inbuf += rsidx * MLOG_SECSZ(lstat);

	lri->lri_rbidx = rbidx;
	lri->lri_sidx  = rsidx;

	return 0;

media_read:
	rc = mlog_logblocks_load_media(mp, lri, inbuf);
	if (rc) {
		mp_pr_err("mpool %s, objid 0x%lx, mlog new read failed",
			  rc, mp->pds_name, (ulong)lri->lri_layout->eld_objid);

		return rc;
	}

	return 0;
}

/**
 * mlog_loopback_load() - Load log block referenced by lri into lstat.
 *
 * Load log block referenced by lri into lstat, update lri if first read
 * from this log block, and return a pointer to the log block and a flag
 * indicating if lri references first record in log block.
 *
 * Note: lri can reference the log block currently accumulating in lstat
 *
 * Returns: 0 on success; -errno otherwise
 * One of the possible errno values:
 * -ENOMSG - if at end of log -- NB: requires an API change to signal without
 */
int mlog_logblock_load(struct mpool_descriptor *mp, struct mlog_read_iter *lri,
		       char **buf, bool *first)
{
	struct mlog_stat *lstat = NULL;
	int lbhlen = 0;
	int rc = 0;

	*buf = NULL;
	*first = false;
	lstat  = &lri->lri_layout->eld_lstat;

	if (!lri->lri_valid || lri->lri_soff > lstat->lst_wsoff) {
		/* lri is invalid; prior checks should prevent this */
		rc = -EINVAL;
		mp_pr_err("mpool %s, invalid offset %u %ld %ld",
			  rc, mp->pds_name, lri->lri_valid, lri->lri_soff, lstat->lst_wsoff);
	} else if ((lri->lri_soff == lstat->lst_wsoff) || (lstat->lst_asoff > -1 &&
			lri->lri_soff >= lstat->lst_asoff &&
			lri->lri_soff <= lstat->lst_wsoff)) {
		/*
		 * lri refers to the currently accumulating log block
		 * in lstat
		 */
		u16 abidx;
		u16 sectsz;
		u16 asidx;
		u16 nseclpg;

		if (!lri->lri_roff)
			/* First read with handle from this log block. */
			lri->lri_roff = OMF_LOGBLOCK_HDR_PACKLEN;

		if (lri->lri_soff == lstat->lst_wsoff && lri->lri_roff > lstat->lst_aoff) {
			/* lri is invalid; prior checks should prevent this */
			rc = -EINVAL;
			mp_pr_err("mpool %s, invalid next offset %u %u",
				  rc, mp->pds_name, lri->lri_roff, lstat->lst_aoff);
			goto out;
		} else if (lri->lri_soff == lstat->lst_wsoff && lri->lri_roff == lstat->lst_aoff) {
			/* Hit end of log */
			rc = -ENOMSG;
			goto out;
		} else if (lri->lri_roff == OMF_LOGBLOCK_HDR_PACKLEN)
			*first = true;

		sectsz  = MLOG_SECSZ(lstat);
		nseclpg = MLOG_NSECLPG(lstat);

		abidx = (lri->lri_soff - lstat->lst_asoff) / nseclpg;
		asidx = lri->lri_soff - ((nseclpg * abidx) + lstat->lst_asoff);

		*buf = &lstat->lst_abuf[abidx][asidx * sectsz];
	} else {
		/* lri refers to an existing log block; fetch it if not cached. */
		rc = mlog_logblock_load_internal(mp, lri, buf);
		if (!rc) {
			/*
			 * NOTE: log block header length must be based
			 * on version since not guaranteed to be the latest
			 */
			lbhlen = omf_logblock_header_len_le(*buf);

			if (lbhlen < 0) {
				rc = -ENODATA;
				mp_pr_err("mpool %s, getting header length failed %ld",
					  rc, mp->pds_name, (long)lbhlen);
			} else {
				if (!lri->lri_roff)
					/* First read with handle from this log block. */
					lri->lri_roff = lbhlen;

				if (lri->lri_roff == lbhlen)
					*first = true;
			}
		}
	}

out:
	if (rc) {
		*buf = NULL;
		*first = false;
	}

	return rc;
}

/**
 * mlogutil_closeall() - Close all open user (non-mdc) mlogs in mpool and release resources.
 *
 * This is an mpool deactivation utility and not part of the mlog user API.
 */
void mlogutil_closeall(struct mpool_descriptor *mp)
{
	struct pmd_layout_mlpriv *this, *tmp;
	struct pmd_layout *layout;

	oml_layout_lock(mp);

	rbtree_postorder_for_each_entry_safe(
		this, tmp, &mp->pds_oml_root, mlp_nodeoml) {

		layout = mlpriv2layout(this);

		if (pmd_objid_type(layout->eld_objid) != OMF_OBJ_MLOG) {
			mp_pr_warn("mpool %s, non-mlog object 0x%lx in open mlog layout tree",
				   mp->pds_name, (ulong)layout->eld_objid);
			continue;
		}

		if (!pmd_objid_isuser(layout->eld_objid))
			continue;

		/* Remove layout from open list and discard log data. */
		rb_erase(&this->mlp_nodeoml, &mp->pds_oml_root);
		mlog_stat_free(layout);
	}

	oml_layout_unlock(mp);
}

/**
 * mlog_getprops_cmn() - Retrieve basic mlog properties from layout.
 * @mp:
 * @layout:
 * @prop:
 */
void
mlog_getprops_cmn(struct mpool_descriptor *mp, struct pmd_layout *layout, struct mlog_props *prop)
{
	memcpy(prop->lpr_uuid.b, layout->eld_uuid.uuid, MPOOL_UUID_SIZE);
	prop->lpr_objid       = layout->eld_objid;
	prop->lpr_alloc_cap   = pmd_layout_cap_get(mp, layout);
	prop->lpr_gen         = layout->eld_gen;
	prop->lpr_iscommitted = layout->eld_state & PMD_LYT_COMMITTED;
	prop->lpr_mclassp    = mp->pds_pdv[layout->eld_ld.ol_pdh].pdi_mclass;
}
