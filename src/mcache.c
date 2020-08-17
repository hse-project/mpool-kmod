// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/log2.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <linux/memcontrol.h>
#include <linux/pagemap.h>
#include <linux/kobject.h>
#include <linux/mm_inline.h>
#include <linux/version.h>
#include <linux/kref.h>

#include <linux/backing-dev.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/migrate.h>
#include <linux/delay.h>
#include <linux/ctype.h>
#include <linux/uio.h>
#include <linux/prefetch.h>

#include "mpool_ioctl.h"

#include "mpool.h"
#include "mpool_printk.h"
#include "assert.h"
#include "evc.h"

#include "mpool_config.h"
#include "mpctl.h"
#include "mpctl_sys.h"
#include "mpctl_reap.h"
#include "init.h"

#if HAVE_MMAP_LOCK
#include <linux/mmap_lock.h>
#endif

#ifndef lru_to_page
#define lru_to_page(_head)  (list_entry((_head)->prev, struct page, lru))
#endif

#if HAVE_MEM_CGROUP_COUNT_VM_EVENT
#define count_memcg_event_mm(_x, _y)    mem_cgroup_count_vm_event((_x), (_y))
#elif !HAVE_COUNT_MEMCG_EVENT_MM
#define count_memcg_event_mm(_x, _y)
#endif

#if !HAVE_VM_FAULT_T
typedef int vm_fault_t;
#endif

/*
 * MPC_RA_IOV_MAX - Max pages per call to mblock read by a readahead
 * request.  Be careful about increasing this as it directly adds
 * (n * 24) bytes to the stack frame of mpc_readpages_cb().
 */
#define MPC_RA_IOV_MAX      (8)

#define NODEV               MKDEV(0, 0)    /* Non-existent device */

/*
 * Arguments required to initiate an asynchronous call to mblock_read()
 * and which must also be preserved across that call.
 *
 * Note: We could make things more efficient by changing a_pagev[]
 * to a struct kvec if mblock_read() would guarantee that it will
 * not alter the given iovec.
 */
struct readpage_args {
	void                       *a_xvm;
	struct mblock_descriptor   *a_mbdesc;
	u64                         a_mboffset;
	int                         a_pagec;
	struct page                *a_pagev[];
};

struct readpage_work {
	struct work_struct      w_work;
	struct readpage_args    w_args;
};

static void mpc_xvm_put(struct mpc_xvm *xvm);

static int mpc_readpage_impl(struct page *page, struct mpc_xvm *map);

/* The following structures are initialized at the end of this file. */
static const struct vm_operations_struct       mpc_vops_default;
const struct address_space_operations   mpc_aops_default;

static struct workqueue_struct *mpc_wq_trunc __read_mostly;
static struct workqueue_struct *mpc_wq_rav[4] __read_mostly;
struct mpc_reap *mpc_reap __read_mostly;

static size_t mpc_xvm_cachesz[2] __read_mostly;
static struct kmem_cache *mpc_xvm_cache[2] __read_mostly;

/*
 * Module params...
 */
static unsigned int mpc_xvm_max __read_mostly = 1048576 * 128;
module_param(mpc_xvm_max, uint, 0444);
MODULE_PARM_DESC(mpc_xvm_max, " max extended VMA regions");

unsigned int mpc_xvm_size_max __read_mostly = 30;
module_param(mpc_xvm_size_max, uint, 0444);
MODULE_PARM_DESC(mpc_xvm_size_max, " max extended VMA size log2");

static struct workqueue_struct *mpc_rgn2wq(uint rgn)
{
	return mpc_wq_rav[rgn % ARRAY_SIZE(mpc_wq_rav)];
}

static int mpc_rgnmap_isorphan(int rgn, void *item, void *data)
{
	struct mpc_xvm *xvm = item;
	void          **headp = data;

	if (xvm && kref_read(&xvm->xvm_ref) == 1 && !atomic_read(&xvm->xvm_opened)) {
		idr_replace(&xvm->xvm_rgnmap->rm_root, NULL, rgn);
		xvm->xvm_next = *headp;
		*headp = xvm;
	}

	return ITERCB_NEXT;
}

void mpc_rgnmap_flush(struct mpc_rgnmap *rm)
{
	struct mpc_xvm *head = NULL, *xvm;

	if (!rm)
		return;

	/* Wait for all mpc_xvm_free_cb() callbacks to complete... */
	flush_workqueue(mpc_wq_trunc);

	/*
	 * Build a list of all orphaned XVMs and release their birth
	 * references (i.e., XVMs that were created but never mmapped).
	 */
	mutex_lock(&rm->rm_lock);
	idr_for_each(&rm->rm_root, mpc_rgnmap_isorphan, &head);
	mutex_unlock(&rm->rm_lock);

	while ((xvm = head)) {
		head = xvm->xvm_next;
		mpc_xvm_put(xvm);
	}

	/* Wait for reaper to prune its lists... */
	while (atomic_read(&rm->rm_rgncnt) > 0)
		usleep_range(100000, 150000);
}

static struct mpc_xvm *mpc_xvm_lookup(struct mpc_rgnmap *rm, uint key)
{
	struct mpc_xvm *xvm;

	mutex_lock(&rm->rm_lock);
	xvm = idr_find(&rm->rm_root, key);
	if (xvm && !kref_get_unless_zero(&xvm->xvm_ref))
		xvm = NULL;
	mutex_unlock(&rm->rm_lock);

	return xvm;
}

void mpc_xvm_free(struct mpc_xvm *xvm)
{
	struct mpc_rgnmap *rm;

	assert((u32)(uintptr_t)xvm == xvm->xvm_magic);
	assert(atomic_read(&xvm->xvm_reapref) > 0);

again:
	mpc_reap_xvm_evict(xvm);

	if (atomic_dec_return(&xvm->xvm_reapref) > 0) {
		atomic_inc(xvm->xvm_freedp);
		return;
	}

	if (atomic64_read(&xvm->xvm_nrpages) > 0) {
		atomic_cmpxchg(&xvm->xvm_evicting, 1, 0);
		atomic_inc(&xvm->xvm_reapref);
		usleep_range(10000, 30000);
		goto again;
	}

	rm = xvm->xvm_rgnmap;

	mutex_lock(&rm->rm_lock);
	idr_remove(&rm->rm_root, xvm->xvm_rgn);
	mutex_unlock(&rm->rm_lock);

	xvm->xvm_magic = 0xbadcafe;
	xvm->xvm_rgn = -1;

	kmem_cache_free(xvm->xvm_cache, xvm);

	atomic_dec(&rm->rm_rgncnt);
}

static void mpc_xvm_free_cb(struct work_struct *work)
{
	struct mpc_xvm *xvm = container_of(work, typeof(*xvm), xvm_work);

	mpc_xvm_free(xvm);
}

static void mpc_xvm_get(struct mpc_xvm *xvm)
{
	kref_get(&xvm->xvm_ref);
}

static void mpc_xvm_release(struct kref *kref)
{
	struct mpc_xvm *xvm = container_of(kref, struct mpc_xvm, xvm_ref);
	struct mpc_rgnmap *rm = xvm->xvm_rgnmap;
	int  i;

	assert((u32)(uintptr_t)xvm == xvm->xvm_magic);

	mutex_lock(&rm->rm_lock);
	assert(kref_read(kref) == 0);
	idr_replace(&rm->rm_root, NULL, xvm->xvm_rgn);
	mutex_unlock(&rm->rm_lock);

	/*
	 * Wait for all in-progress readaheads to complete
	 * before we drop our mblock references.
	 */
	if (atomic_add_return(WQ_MAX_ACTIVE, &xvm->xvm_rabusy) > WQ_MAX_ACTIVE)
		flush_workqueue(mpc_rgn2wq(xvm->xvm_rgn));

	for (i = 0; i < xvm->xvm_mbinfoc; ++i)
		mblock_put(xvm->xvm_mpdesc, xvm->xvm_mbinfov[i].mbdesc);

	INIT_WORK(&xvm->xvm_work, mpc_xvm_free_cb);
	queue_work(mpc_wq_trunc, &xvm->xvm_work);
}

static void mpc_xvm_put(struct mpc_xvm *xvm)
{
	kref_put(&xvm->xvm_ref, mpc_xvm_release);
}

/*
 * VM operations
 */

static void mpc_vm_open(struct vm_area_struct *vma)
{
	mpc_xvm_get(vma->vm_private_data);
}

static void mpc_vm_close(struct vm_area_struct *vma)
{
	mpc_xvm_put(vma->vm_private_data);
}

static int mpc_alloc_and_readpage(struct vm_area_struct *vma, pgoff_t offset, gfp_t gfp)
{
	struct file            *file;
	struct page            *page;
	struct address_space   *mapping;
	int                     rc;

	page = __page_cache_alloc(gfp | __GFP_NOWARN);
	if (ev(!page))
		return -ENOMEM;

	file    = vma->vm_file;
	mapping = file->f_mapping;

	rc = add_to_page_cache_lru(page, mapping, offset, gfp & GFP_KERNEL);
	if (rc == 0)
		rc = mpc_readpage_impl(page, vma->vm_private_data);
	else if (rc == -EEXIST)
		rc = 0;

	put_page(page);

	return rc;
}

static bool mpc_lock_page_or_retry(struct page *page, struct mm_struct *mm, uint flags)
{
	might_sleep();

	if (trylock_page(page))
		return true;

	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (flags & FAULT_FLAG_RETRY_NOWAIT)
			return false;

#if HAVE_MMAP_LOCK
		mmap_read_unlock(mm);
#else
		up_read(&mm->mmap_sem);
#endif
		/* _killable version is not exported by the kernel. */
		wait_on_page_locked(page);
		return false;
	}

	if (flags & FAULT_FLAG_KILLABLE) {
		int rc;

		rc = lock_page_killable(page);
		if (rc) {
#if HAVE_MMAP_LOCK
			mmap_read_unlock(mm);
#else
			up_read(&mm->mmap_sem);
#endif
			return false;
		}
	} else {
		lock_page(page);
	}

	return true;
}

static int mpc_handle_page_error(struct page *page, struct vm_area_struct *vma)
{
	int     rc;

	ClearPageError(page);

	rc = mpc_readpage_impl(page, vma->vm_private_data);
	if (rc == 0) {
		wait_on_page_locked(page);
		if (ev(!PageUptodate(page)))
			rc = -EIO;
	}

	put_page(page);

	return rc;
}

static vm_fault_t mpc_vm_fault_impl(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct address_space   *mapping;
	struct inode           *inode;
	vm_fault_t              vmfrc;
	pgoff_t                 offset;
	loff_t                  size;
	struct page            *page;

	mapping = vma->vm_file->f_mapping;
	inode   = mapping->host;
	offset  = vmf->pgoff;
	vmfrc   = 0;

	size = round_up(i_size_read(inode), PAGE_SIZE);
	if (ev(offset >= (size >> PAGE_SHIFT)))
		return VM_FAULT_SIGBUS;

retry_find:
	page = find_get_page(mapping, offset);
	if (!page) {
		int rc = mpc_alloc_and_readpage(vma, offset, mapping_gfp_mask(mapping));

		if (ev(rc < 0))
			return (rc == -ENOMEM) ? VM_FAULT_OOM : VM_FAULT_SIGBUS;

		vmfrc = VM_FAULT_MAJOR;
		goto retry_find;
	}

	/* At this point, page is not locked but has a ref. */
	if (vmfrc == VM_FAULT_MAJOR) {
		count_vm_event(PGMAJFAULT);
		count_memcg_event_mm(vma->vm_mm, PGMAJFAULT);
	}

	if (!mpc_lock_page_or_retry(page, vma->vm_mm, vmf->flags)) {
		put_page(page);
		return vmfrc | VM_FAULT_RETRY;
	}

	/* At this point, page is locked with a ref. */
	if (unlikely(page->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto retry_find;
	}

	VM_BUG_ON_PAGE(page->index != offset, page);

	if (unlikely(!PageUptodate(page))) {
		int rc = mpc_handle_page_error(page, vma);

		/* At this point, page is not locked and has no ref. */
		if (ev(rc))
			return VM_FAULT_SIGBUS;
		goto retry_find;
	}

	/* Page is locked with a ref. */
	vmf->page = page;

	mpc_reap_xvm_touch(vma->vm_private_data, page->index);

	return vmfrc | VM_FAULT_LOCKED;
}

#if HAVE_VMFAULT_VMF
static vm_fault_t mpc_vm_fault(struct vm_fault *vmf)
{
	return mpc_vm_fault_impl(vmf->vma, vmf);
}

#else

static vm_fault_t mpc_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)

{
	return mpc_vm_fault_impl(vma, vmf);
}
#endif

/*
 * MPCTL address-space operations.
 */

static int mpc_readpage_impl(struct page *page, struct mpc_xvm *xvm)
{
	struct mpc_mbinfo  *mbinfo;
	struct kvec         iov[1];
	off_t               offset;
	uint                mbnum;
	merr_t              err;

	offset  = page->index << PAGE_SHIFT;
	offset %= (1ul << mpc_xvm_size_max);

	mbnum = offset / xvm->xvm_bktsz;
	if (ev(mbnum >= xvm->xvm_mbinfoc)) {
		unlock_page(page);
		return -EINVAL;
	}

	mbinfo = xvm->xvm_mbinfov + mbnum;
	offset %= xvm->xvm_bktsz;

	if (ev(offset >= mbinfo->mblen)) {
		unlock_page(page);
		return -EINVAL;
	}

	iov[0].iov_base = page_address(page);
	iov[0].iov_len = PAGE_SIZE;

	err = mblock_read(xvm->xvm_mpdesc, mbinfo->mbdesc, iov, 1, offset, PAGE_SIZE);
	if (ev(err)) {
		unlock_page(page);
		return -merr_errno(err);
	}

	if (xvm->xvm_hcpagesp)
		atomic64_inc(xvm->xvm_hcpagesp);
	atomic64_inc(&xvm->xvm_nrpages);

	SetPagePrivate(page);
	set_page_private(page, (ulong)xvm);
	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}

#define MPC_RPARGSBUFSZ \
	(sizeof(struct readpage_args) + MPC_RA_IOV_MAX * sizeof(void *))

/**
 * mpc_readpages_cb() - mpc_readpages() callback
 * @work:   w_work.work from struct readpage_work
 *
 * The incoming arguments are in the first page (a_pagev[0]) which
 * we are about to overwrite, so we copy them to the stack.
 */
static void mpc_readpages_cb(struct work_struct *work)
{
	char                    argsbuf[MPC_RPARGSBUFSZ];
	struct readpage_args   *args = (void *)argsbuf;
	struct kvec             iovbuf[MPC_RA_IOV_MAX];
	struct kvec            *iov = iovbuf;
	struct mpc_xvm         *xvm;
	struct readpage_work   *w;

	size_t  argssz;
	int     pagec, i;
	merr_t  err;

	w = container_of(work, struct readpage_work, w_work);

	pagec = w->w_args.a_pagec;
	argssz = sizeof(*args) + sizeof(args->a_pagev[0]) * pagec;

	assert(pagec <= ARRAY_SIZE(iovbuf));
	assert(argssz <= sizeof(argsbuf));

	memcpy(args, &w->w_args, argssz);
	w = NULL; /* Do not touch! */

	xvm = args->a_xvm;

	/*
	 * Synchronize with mpc_xvm_put() to prevent dropping our
	 * mblock references while there are reads in progress.
	 */
	if (ev(atomic_inc_return(&xvm->xvm_rabusy) > WQ_MAX_ACTIVE)) {
		err = merr(ENXIO);
		goto errout;
	}

	for (i = 0; i < pagec; ++i) {
		iov[i].iov_base = page_address(args->a_pagev[i]);
		iov[i].iov_len = PAGE_SIZE;
	}

	err = mblock_read(xvm->xvm_mpdesc, args->a_mbdesc, iov,
			  pagec, args->a_mboffset, pagec << PAGE_SHIFT);
	if (ev(err))
		goto errout;

	if (xvm->xvm_hcpagesp)
		atomic64_add(pagec, xvm->xvm_hcpagesp);
	atomic64_add(pagec, &xvm->xvm_nrpages);
	atomic_dec(&xvm->xvm_rabusy);

	for (i = 0; i < pagec; ++i) {
		struct page *page = args->a_pagev[i];

		SetPagePrivate(page);
		set_page_private(page, (ulong)xvm);
		SetPageUptodate(page);

		unlock_page(page);
		put_page(page);
	}

	return;

errout:
	atomic_dec(&xvm->xvm_rabusy);

	for (i = 0; i < pagec; ++i) {
		unlock_page(args->a_pagev[i]);
		put_page(args->a_pagev[i]);
	}
}

static int
mpc_readpages(
	struct file            *file,
	struct address_space   *mapping,
	struct list_head       *pages,
	uint                    nr_pages)
{
	struct workqueue_struct    *wq;
	struct readpage_work       *w;
	struct work_struct         *work;
	struct mpc_mbinfo          *mbinfo;
	struct mpc_unit            *unit;
	struct mpc_xvm             *xvm;
	struct page                *page;

	off_t   offset, mbend;
	uint    mbnum, iovmax, i;
	uint    ra_pages_max;
	ulong   index;
	gfp_t   gfp;
	u32     key;
	int     rc;

	unit = file->private_data;

	ra_pages_max = unit->un_ra_pages_max;
	if (ra_pages_max < 1)
		return 0;

	page   = lru_to_page(pages);
	offset = page->index << PAGE_SHIFT;
	index  = page->index;
	work   = NULL;
	w      = NULL;

	key = offset >> mpc_xvm_size_max;

	/*
	 * The idr value here (xvm) is pinned for the lifetime of the address map.
	 * Therefore, we can exit the rcu read-side critsec without worry that xvm will be
	 * destroyed before put_page() has been called on each and every page in the given
	 * list of pages.
	 */
	rcu_read_lock();
	xvm = idr_find(&unit->un_rgnmap.rm_root, key);
	rcu_read_unlock();

	if (ev(!xvm))
		return 0;

	offset %= (1ul << mpc_xvm_size_max);

	mbnum = offset / xvm->xvm_bktsz;
	if (ev(mbnum >= xvm->xvm_mbinfoc))
		return 0;

	mbinfo = xvm->xvm_mbinfov + mbnum;

	mbend = mbnum * xvm->xvm_bktsz + mbinfo->mblen;
	iovmax = MPC_RA_IOV_MAX;

	gfp = mapping_gfp_mask(mapping) & GFP_KERNEL;
	wq = mpc_rgn2wq(xvm->xvm_rgn);

	if (mpc_reap_xvm_duress(xvm))
		nr_pages = min_t(uint, nr_pages, 8);

	nr_pages = min_t(uint, nr_pages, ra_pages_max);

	for (i = 0; i < nr_pages; ++i) {
		page    = lru_to_page(pages);
		offset  = page->index << PAGE_SHIFT;
		offset %= (1ul << mpc_xvm_size_max);

		/* Don't read past the end of the mblock. */
		if (offset >= mbend)
			break;

		/* mblock reads must be logically contiguous. */
		if (page->index != index && work) {
			queue_work(wq, work);
			work = NULL;
		}

		index = page->index + 1; /* next expected page index */

		prefetchw(&page->flags);
		list_del(&page->lru);

		rc = add_to_page_cache_lru(page, mapping, page->index, gfp);
		if (rc) {
			if (work) {
				queue_work(wq, work);
				work = NULL;
			}
			put_page(page);
			continue;
		}

		if (!work) {
			w = page_address(page);
			INIT_WORK(&w->w_work, mpc_readpages_cb);
			w->w_args.a_xvm = xvm;
			w->w_args.a_mbdesc = mbinfo->mbdesc;
			w->w_args.a_mboffset = offset % xvm->xvm_bktsz;
			w->w_args.a_pagec = 0;
			work = &w->w_work;

			iovmax = MPC_RA_IOV_MAX;
			iovmax -= page->index % MPC_RA_IOV_MAX;
		}

		w->w_args.a_pagev[w->w_args.a_pagec++] = page;

		/*
		 * Restrict batch size to the number of struct kvecs
		 * that will fit into a page (minus our header).
		 */
		if (w->w_args.a_pagec >= iovmax) {
			queue_work(wq, work);
			work = NULL;
		}
	}

	if (work)
		queue_work(wq, work);

	return 0;
}

/**
 * mpc_releasepage() - Linux VM calls the release page when pages are released.
 * @page:
 * @gfp:
 *
 * The function is added as part of tracking incoming and outgoing pages.
 * When the number of pages owned exceeds the limit (if defined) reap function
 * will get invoked to trim down the usage.
 */
static int mpc_releasepage(struct page *page, gfp_t gfp)
{
	struct mpc_xvm *xvm;

	if (ev(!PagePrivate(page)))
		return 0;

	xvm = (void *)page_private(page);
	if (ev(!xvm))
		return 0;

	ClearPagePrivate(page);
	set_page_private(page, 0);

	assert((u32)(uintptr_t)xvm == xvm->xvm_magic);

	if (xvm->xvm_hcpagesp)
		atomic64_dec(xvm->xvm_hcpagesp);
	atomic64_dec(&xvm->xvm_nrpages);

	return 1;
}

#if HAVE_INVALIDATEPAGE_LENGTH
static void mpc_invalidatepage(struct page *page, uint offset, uint length)
{
	mpc_releasepage(page, 0);
}

#else

static void mpc_invalidatepage(struct page *page, ulong offset)
{
	mpc_releasepage(page, 0);
}
#endif

/**
 * mpc_migratepage() -  Callback for handling page migration.
 *
 * @mapping:
 * @newpage:
 * @page:
 * @mode:
 *
 * The drivers having private pages are supplying this callback.
 * Not sure the page migration releases or invalidates the page being migrated,
 * or else the tracking of incoming and outgoing pages will be in trouble. The
 * callback is added to deal with uncertainties around migration. The migration
 * will be declined so long as the page is private and it belongs to mpctl.
 */
static int
mpc_migratepage(
	struct address_space   *mapping,
	struct page            *newpage,
	struct page            *page,
	enum migrate_mode       mode)
{
	if (page_has_private(page) &&
	    !try_to_release_page(page, GFP_KERNEL))
		return -EAGAIN;

	assert(PageLocked(page));

	return migrate_page(mapping, newpage, page, mode);
}

int mpc_mmap(struct file *fp, struct vm_area_struct *vma)
{
	struct mpc_unit    *unit = fp->private_data;
	struct mpc_xvm     *xvm;

	off_t   off;
	ulong   len;
	u32     key;

	off = vma->vm_pgoff << PAGE_SHIFT;
	len = vma->vm_end - vma->vm_start - 1;

	/* Verify that the request does not cross an xvm region boundary. */
	if ((off >> mpc_xvm_size_max) != ((off + len) >> mpc_xvm_size_max))
		return -EINVAL;

	/* Acquire a reference on the region map for this region. */
	key = off >> mpc_xvm_size_max;

	xvm = mpc_xvm_lookup(&unit->un_rgnmap, key);
	if (!xvm)
		return -EINVAL;

	/*
	 * Drop the birth ref on first open so that the final call
	 * to mpc_vm_close() will cause the vma to be destroyed.
	 */
	if (atomic_inc_return(&xvm->xvm_opened) == 1)
		mpc_xvm_put(xvm);

	vma->vm_ops = &mpc_vops_default;

	vma->vm_flags &= ~(VM_RAND_READ | VM_SEQ_READ);
	vma->vm_flags &= ~(VM_MAYWRITE | VM_MAYEXEC);

	vma->vm_flags = (VM_DONTEXPAND | VM_DONTDUMP | VM_NORESERVE);
	vma->vm_flags |= VM_MAYREAD | VM_READ | VM_RAND_READ;

	vma->vm_private_data = xvm;

	fp->f_ra.ra_pages = unit->un_ra_pages_max;

	mpc_reap_xvm_add(unit->un_ds_reap, xvm);

	return 0;
}

/**
 * mpioc_xvm_create() - create an extended VMA map (AKA mcache map)
 * @unit:
 * @arg:
 */
merr_t mpioc_xvm_create(struct mpc_unit *unit, struct mpool_descriptor *mp, struct mpioc_vma *ioc)
{
	struct mpc_rgnmap          *rm;
	struct mpc_mbinfo          *mbinfov;
	struct kmem_cache          *cache;
	struct mpc_xvm             *xvm;

	u64     *mbidv;
	size_t  largest, sz;
	uint    mbidc, mult;
	merr_t  err;
	int     rc, i;

	if (ev(!unit || !unit->un_mapping || !ioc))
		return merr(EINVAL);

	if (ioc->im_mbidc < 1)
		return merr(EINVAL);

	if (ioc->im_advice > MPC_VMA_PINNED)
		return merr(EINVAL);

	mult = 1;
	if (ioc->im_advice == MPC_VMA_WARM)
		mult = 10;
	else if (ioc->im_advice == MPC_VMA_HOT)
		mult = 100;

	mbidc = ioc->im_mbidc;

	sz = sizeof(*xvm) + sizeof(*mbinfov) * mbidc;
	if (sz > mpc_xvm_cachesz[1])
		return merr(EINVAL);
	else if (sz > mpc_xvm_cachesz[0])
		cache = mpc_xvm_cache[1];
	else
		cache = mpc_xvm_cache[0];

	sz = mbidc * sizeof(mbidv[0]);

	mbidv = kmalloc(sz, GFP_KERNEL);
	if (!mbidv)
		return merr(ENOMEM);

	rc = copy_from_user(mbidv, ioc->im_mbidv, sz);
	if (rc) {
		kfree(mbidv);
		return merr(EFAULT);
	}

	xvm = kmem_cache_zalloc(cache, GFP_KERNEL);
	if (!xvm) {
		kfree(mbidv);
		return merr(ENOMEM);
	}

	xvm->xvm_magic = (u32)(uintptr_t)xvm;
	xvm->xvm_mbinfoc = mbidc;
	xvm->xvm_mpdesc = mp;

	xvm->xvm_mapping = unit->un_mapping;
	xvm->xvm_rgnmap = &unit->un_rgnmap;
	xvm->xvm_advice = ioc->im_advice;
	kref_init(&xvm->xvm_ref);
	xvm->xvm_cache = cache;
	atomic_set(&xvm->xvm_opened, 0);

	INIT_LIST_HEAD(&xvm->xvm_list);
	atomic_set(&xvm->xvm_evicting, 0);
	atomic_set(&xvm->xvm_reapref, 1);
	atomic64_set(&xvm->xvm_nrpages, 0);
	atomic_set(&xvm->xvm_rabusy, 0);

	largest = 0;
	err = 0;

	mbinfov = xvm->xvm_mbinfov;

	for (i = 0; i < mbidc; ++i) {
		struct mpc_mbinfo *mbinfo = mbinfov + i;
		struct mblock_props props;

		err = mblock_find_get(mp, mbidv[i], 1, &props, &mbinfo->mbdesc);
		if (err) {
			mbidc = i;
			goto errout;
		}

		mbinfo->mblen = ALIGN(props.mpr_write_len, PAGE_SIZE);
		mbinfo->mbmult = mult;
		atomic64_set(&mbinfo->mbatime, 0);

		largest = max_t(size_t, largest, mbinfo->mblen);
	}

	xvm->xvm_bktsz = roundup_pow_of_two(largest);

	if (xvm->xvm_bktsz * mbidc > (1ul << mpc_xvm_size_max)) {
		err = merr(E2BIG);
		goto errout;
	}

	rm = &unit->un_rgnmap;

	mutex_lock(&rm->rm_lock);
	xvm->xvm_rgn = idr_alloc(&rm->rm_root, NULL, 1, -1, GFP_KERNEL);
	if (xvm->xvm_rgn < 1) {
		mutex_unlock(&rm->rm_lock);

		err = merr(xvm->xvm_rgn ?: EINVAL);
		goto errout;
	}

	ioc->im_offset = (ulong)xvm->xvm_rgn << mpc_xvm_size_max;
	ioc->im_bktsz = xvm->xvm_bktsz;
	ioc->im_len = xvm->xvm_bktsz * mbidc;
	ioc->im_len = ALIGN(ioc->im_len, (1ul << mpc_xvm_size_max));

	atomic_inc(&rm->rm_rgncnt);

	idr_replace(&rm->rm_root, xvm, xvm->xvm_rgn);
	mutex_unlock(&rm->rm_lock);

errout:
	if (err) {
		for (i = 0; i < mbidc; ++i)
			mblock_put(mp, mbinfov[i].mbdesc);
		kmem_cache_free(cache, xvm);
	}

	kfree(mbidv);

	return err;
}

/**
 * mpioc_xvm_destroy() - destroy an extended VMA
 * @unit:
 * @arg:
 */
merr_t mpioc_xvm_destroy(struct mpc_unit *unit, struct mpioc_vma *ioc)
{
	struct mpc_rgnmap  *rm;
	struct mpc_xvm     *xvm;
	u64                 rgn;

	if (ev(!unit || !ioc))
		return merr(EINVAL);

	rgn = ioc->im_offset >> mpc_xvm_size_max;
	rm = &unit->un_rgnmap;

	mutex_lock(&rm->rm_lock);
	xvm = idr_find(&rm->rm_root, rgn);
	if (xvm && kref_read(&xvm->xvm_ref) == 1 && !atomic_read(&xvm->xvm_opened))
		idr_remove(&rm->rm_root, rgn);
	else
		xvm = NULL;
	mutex_unlock(&rm->rm_lock);

	if (xvm)
		mpc_xvm_put(xvm);

	return 0;
}

merr_t mpioc_xvm_purge(struct mpc_unit *unit, struct mpioc_vma *ioc)
{
	struct mpc_xvm *xvm;
	u64             rgn;

	if (ev(!unit || !ioc))
		return merr(EINVAL);

	rgn = ioc->im_offset >> mpc_xvm_size_max;

	xvm = mpc_xvm_lookup(&unit->un_rgnmap, rgn);
	if (!xvm)
		return merr(ENOENT);

	mpc_reap_xvm_evict(xvm);

	mpc_xvm_put(xvm);

	return 0;
}

merr_t mpioc_xvm_vrss(struct mpc_unit *unit, struct mpioc_vma *ioc)
{
	struct mpc_xvm *xvm;
	u64             rgn;

	if (ev(!unit || !ioc))
		return merr(EINVAL);

	rgn = ioc->im_offset >> mpc_xvm_size_max;

	xvm = mpc_xvm_lookup(&unit->un_rgnmap, rgn);
	if (!xvm)
		return merr(ENOENT);

	ioc->im_vssp = mpc_xvm_pglen(xvm);
	ioc->im_rssp = atomic64_read(&xvm->xvm_nrpages);

	mpc_xvm_put(xvm);

	return 0;
}

merr_t mcache_init(void)
{
	size_t      sz;
	merr_t      err;
	int         i;

	mpc_xvm_max = clamp_t(uint, mpc_xvm_max, 1024, 1u << 30);
	mpc_xvm_size_max = clamp_t(ulong, mpc_xvm_size_max, 27, 32);

	sz = sizeof(struct mpc_mbinfo) * 8;
	mpc_xvm_cachesz[0] = sizeof(struct mpc_xvm) + sz;

	mpc_xvm_cache[0] = kmem_cache_create("mpool_xvm_0", mpc_xvm_cachesz[0], 0,
					     SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);
	if (!mpc_xvm_cache[0]) {
		err = merr(ENOMEM);
		mp_pr_err("mpc xvm cache 0 create failed", err);
		return err;
	}

	sz = sizeof(struct mpc_mbinfo) * 32;
	mpc_xvm_cachesz[1] = sizeof(struct mpc_xvm) + sz;

	mpc_xvm_cache[1] = kmem_cache_create("mpool_xvm_1", mpc_xvm_cachesz[1], 0,
					     SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);
	if (!mpc_xvm_cache[1]) {
		err = merr(ENOMEM);
		mp_pr_err("mpc xvm cache 1 create failed", err);
		return err;
	}

	mpc_wq_trunc = alloc_workqueue("mpc_wq_trunc", WQ_UNBOUND, 16);
	if (!mpc_wq_trunc) {
		err = merr(ENOMEM);
		mp_pr_err("trunc workqueue alloc failed", err);
		return err;
	}

	err = mpc_reap_create(&mpc_reap);
	if (ev(err)) {
		mp_pr_err("reap create failed", err);
		return err;
	}

	for (i = 0; i < ARRAY_SIZE(mpc_wq_rav); ++i) {
		int     maxactive = 16;
		char    name[16];

		snprintf(name, sizeof(name), "mpc_wq_ra%d", i);

		mpc_wq_rav[i] = alloc_workqueue(name, 0, maxactive);
		if (!mpc_wq_rav[i]) {
			err = merr(ENOMEM);
			mp_pr_err("mpctl ra workqueue alloc failed", err);
			return err;
		}
	}

	return 0;
}

void mcache_exit(void)
{
	int    i;

	for (i = 0; i < ARRAY_SIZE(mpc_wq_rav); ++i) {
		destroy_workqueue(mpc_wq_rav[i]);
		mpc_wq_rav[i] = NULL;
	}

	mpc_reap_destroy(mpc_reap);
	destroy_workqueue(mpc_wq_trunc);
	kmem_cache_destroy(mpc_xvm_cache[1]);
	kmem_cache_destroy(mpc_xvm_cache[0]);
}

static const struct vm_operations_struct mpc_vops_default = {
	.open           = mpc_vm_open,
	.close          = mpc_vm_close,
	.fault          = mpc_vm_fault,
};

const struct address_space_operations mpc_aops_default = {
	.readpages      = mpc_readpages,
	.releasepage    = mpc_releasepage,
	.invalidatepage = mpc_invalidatepage,
	.migratepage    = mpc_migratepage,
};
