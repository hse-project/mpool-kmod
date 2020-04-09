// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * The reaper subsystem tracks residency of pages from specified VMAs and
 * weighs the memory used against system free memory.  Should the relative
 * residency vs free memory fall below a predetermined low watermark the
 * reaper begins evicting pages from the specified VMAs, stopping when free
 * memory rises above a high watermark that is slightly higher than the low
 * watermark.
 *
 * The reaper maintains several lists of VMAs and cycles through them in a
 * round-robin fashion to select pages to evict.  Each VMA is comprised of
 * one or more contiguous virtual subranges of pages, where each subrange
 * is delineated by an mblock (typically no larger than 32M).  Each mblock
 * has an associated access time which is updated on each page fault to any
 * page in the mblock.  The reaper leverages the atime to decide whether or
 * not to evict all the pages in the subrange based upon the current TTL,
 * where the current TTL grows shorter as the urgency to evict pages grows
 * stronger.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/sched.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/clock.h>
#endif

#include <mpcore/mpcore_printk.h>
#include <mpcore/assert.h>
#include <mpcore/alloc.h>
#include <mpcore/evc.h>

#include "mpctl_params.h"
#include "mpctl_internal.h"
#include "mpctl_reap_internal.h"

/**
 * mpc_readp_meminfo() - Get current system-wide memory usage
 * @freep:    ptr to return bytes of free memory
 * @availp:   ptr to return bytes of available memory
 * @shift:    shift results by %shift bits
 *
 * %mpc_reap_meminfo() returns current free and available memory
 * sizes obtained from /proc/meminfo in userland and si_meminfo()
 * in the kernel.  The resulting sizes are in bytes, but the
 * caller can supply a non-zero %shift argment to obtain results
 * in different units (e.g., for MiB shift=20, for GiB shift=30).
 *
 * %freep and/or %availp may be NULL.
 */
static void mpc_reap_meminfo(ulong *freep, ulong *availp, uint shift)
{
	struct sysinfo si;

	si_meminfo(&si);

	if (freep)
		*freep = (si.freeram * si.mem_unit) >> shift;

	if (availp)
		*availp = (si_mem_available() * si.mem_unit) >> shift;
}

static void mpc_reap_evict_vma(struct mpc_vma *meta)
{
	struct address_space   *mapping = meta->mcm_mapping;
	struct mpc_reap        *reap = meta->mcm_reap;

	pgoff_t off, bktsz, len;
	u64     ttl, xtime, now;
	int     i;

	bktsz = meta->mcm_bktsz >> PAGE_SHIFT;
	off = mpc_vma_pgoff(meta);

	ttl = atomic_read(&reap->reap_ttl) * 1000ul;
	now = local_clock();

	for (i = 0; i < meta->mcm_mbinfoc; ++i, off += bktsz) {
		struct mpc_mbinfo *mbinfo = meta->mcm_mbinfov + i;

		xtime = now - (ttl * mbinfo->mbmult);
		len = mbinfo->mblen >> PAGE_SHIFT;

		if (atomic64_read(&mbinfo->mbatime) > xtime)
			continue;

		atomic64_set(&mbinfo->mbatime, U64_MAX);

		invalidate_inode_pages2_range(mapping, off, off + len);

		if (atomic64_read(&meta->mcm_nrpages) < 32)
			break;

		if (need_resched())
			cond_resched();

		ttl = atomic_read(&reap->reap_ttl) * 1000ul;
		now = local_clock();
	}
}

/**
 * mpc_reap_evict() - Evict "cold"  pages from the given list of VMAs
 * @process:    A list of one of more map meta structures of VMAs to be reaped
 */
static void mpc_reap_evict(struct list_head *process)
{
	struct mpc_vma *meta, *next;

	list_for_each_entry_safe(meta, next, process, mcm_list) {
		if (atomic_read(&meta->mcm_reap->reap_lwm))
			mpc_reap_evict_vma(meta);

		atomic_cmpxchg(&meta->mcm_evicting, 1, 0);
	}
}

/**
 * mpc_reap_scan() - Scan for pages to purge
 * @elem:
 * @idx:    reap list index
 */
static void mpc_reap_scan(struct mpc_reap_elem *elem)
{
	struct list_head   *list, process;
	struct mpc_vma     *meta, *next;
	u64                 nrpages, n;

	INIT_LIST_HEAD(&process);

	mutex_lock(&elem->reap_lock);
	list = &elem->reap_list;
	n = 0;

	list_for_each_entry_safe(meta, next, list, mcm_list) {
		nrpages = atomic64_read(&meta->mcm_nrpages);

		if (nrpages < 32)
			continue;

		if (atomic_read(&meta->mcm_reapref) == 1)
			continue;

		if (atomic_cmpxchg(&meta->mcm_evicting, 0, 1))
			continue;

		list_del(&meta->mcm_list);
		list_add(&meta->mcm_list, &process);

		if (++n > 4)
			break;
	}
	mutex_unlock(&elem->reap_lock);

	mpc_reap_evict(&process);

	mutex_lock(&elem->reap_lock);
	list_splice_tail(&process, list);
	mutex_unlock(&elem->reap_lock);

	usleep_range(300, 700);
}

static void mpc_reap_run(struct work_struct *work)
{
	struct mpc_reap_elem   *elem;
	struct mpc_reap        *reap;

	elem = container_of(work, struct mpc_reap_elem, reap_work);
	reap = elem->reap_reap;

	while (atomic_read(&reap->reap_lwm))
		mpc_reap_scan(elem);

	atomic_cmpxchg(&elem->reap_running, 1, 0);
}

/**
 * mpc_reap_tune() - Dynamic tuning of reap knobs.
 * @reap:
 */
static void mpc_reap_tune(struct mpc_reap *reap)
{
	ulong   total_pages, hpages, wpages, cpages, mfree;
	uint    freepct, hwm, lwm, ttl, debug, i;

	hpages = wpages = cpages = 0;

	/* Take a live snapshot of the current memory usage.  Disable
	 * preemption so that the result is reasonably accurate.
	 */
	preempt_disable();
	mpc_reap_meminfo(&mfree, NULL, PAGE_SHIFT);

	for (i = 0; i < REAP_ELEM_MAX; ++i) {
		struct mpc_reap_elem *elem = &reap->reap_elem[i];

		hpages += atomic64_read(&elem->reap_hpages);
		wpages += atomic64_read(&elem->reap_wpages);
		cpages += atomic64_read(&elem->reap_cpages);
	}
	preempt_enable();

	total_pages = mfree + hpages + wpages + cpages;

	/* Determine the current percentage of free memory relative to the
	 * number of hot+warm+cold pages tracked by the reaper.  freepct,
	 * lwm, and hwm are scaled to 10000 for finer resolution.
	 */
	freepct = ((hpages + wpages + cpages) * 10000) / total_pages;
	freepct = 10000 - freepct;

	lwm = (100 - mpc_reap_mempct_get()) * 100;
	hwm = (lwm * 10300) / 10000;
	hwm = min_t(u32, hwm, 9700);
	ttl = mpc_reap_ttl_get();

	if (freepct >= hwm) {
		if (atomic_read(&reap->reap_ttl) != ttl)
			atomic_set(&reap->reap_ttl, ttl);
		if (atomic_read(&reap->reap_lwm))
			atomic_set(&reap->reap_lwm, 0);
	} else if (freepct < lwm || atomic_read(&reap->reap_lwm) > 0) {
		ulong x = 10000 - (freepct * 10000) / hwm;

		if (atomic_read(&reap->reap_lwm) != x) {
			atomic_set(&reap->reap_lwm, x);

			x = (ttl * (500ul * 500)) / (x * x);
			if (x > ttl)
				x = ttl;

			atomic_set(&reap->reap_ttl, x);
		}
	}

	debug = mpc_reap_debug_get();
	if (!debug || (debug == 1 && freepct > hwm))
		return;

	if (atomic_inc_return(&reap->reap_emit) % REAP_ELEM_MAX > 0)
		return;

	mp_pr_info(
		"%s: %lu %lu, hot %lu, warm %lu, cold %lu, freepct %u, lwm %u, hwm %u, %2u, ttl %u",
		__func__,
		mfree >> (20 - PAGE_SHIFT),
		total_pages >> (20 - PAGE_SHIFT),
		hpages >> (20 - PAGE_SHIFT),
		wpages >> (20 - PAGE_SHIFT),
		cpages >> (20 - PAGE_SHIFT),
		freepct, lwm, hwm,
		atomic_read(&reap->reap_lwm),
		atomic_read(&reap->reap_ttl) / 1000);
}

static void mpc_reap_prune(struct work_struct *work)
{
	struct mpc_vma         *meta, *next;
	struct mpc_reap_elem   *elem;
	struct mpc_reap        *reap;
	struct list_head        freeme;

	uint   nfreed, eidx;
	ulong  delay;

	reap = container_of(work, struct mpc_reap, reap_dwork.work);

	/* First, assesss the current memory situation.  If free
	 * memory is below the low watermark then try to start a
	 * reaper to evict some pages.
	 */
	mpc_reap_tune(reap);

	if (atomic_read(&reap->reap_lwm)) {
		eidx = atomic_read(&reap->reap_eidx) % REAP_ELEM_MAX;
		elem = reap->reap_elem + eidx;

		if (!atomic_cmpxchg(&elem->reap_running, 0, 1))
			queue_work(reap->reap_wq, &elem->reap_work);
	}

	/* Next, advance to the next elem and prune VMAs that have
	 * been freed.
	 */
	eidx = atomic_inc_return(&reap->reap_eidx) % REAP_ELEM_MAX;

	elem = reap->reap_elem + eidx;
	INIT_LIST_HEAD(&freeme);

	nfreed = atomic_read(&elem->reap_nfreed);

	if (nfreed && mutex_trylock(&elem->reap_lock)) {
		struct list_head   *list = &elem->reap_list;
		uint                npruned = 0;

		list_for_each_entry_safe(meta, next, list, mcm_list) {
			if (atomic_read(&meta->mcm_reapref) > 1)
				continue;

			list_del(&meta->mcm_list);
			list_add_tail(&meta->mcm_list, &freeme);

			if (++npruned >= nfreed)
				break;
		}
		mutex_unlock(&elem->reap_lock);

		list_for_each_entry_safe(meta, next, &freeme, mcm_list)
			mpc_vma_free(meta);

		atomic_sub(npruned, &elem->reap_nfreed);
	}

	delay = mpc_reap_mempct_get() < 100 ? 1000 / REAP_ELEM_MAX : 1000;
	delay = msecs_to_jiffies(delay);

	queue_delayed_work(reap->reap_wq, &reap->reap_dwork, delay);
}

/**
 * mpc_reap_create() - Allocate and initialize reap data strctures
 * @reapout: Initialized reap structure.
 *
 * Returns ENOMEM if the allocation fails.
 */
merr_t mpc_reap_create(struct mpc_reap **reapp)
{
	struct mpc_reap_elem   *elem;
	struct mpc_reap        *reap;

	uint  flags, i;

	flags = WQ_UNBOUND | WQ_HIGHPRI | WQ_CPU_INTENSIVE;
	*reapp = NULL;

	reap = alloc_aligned(sizeof(*reap), 128, GFP_KERNEL);
	if (ev(!reap))
		return merr(ENOMEM);

	memset(reap, 0, sizeof(*reap));

	reap->reap_wq = alloc_workqueue("mpc_reap", flags, REAP_ELEM_MAX + 1);
	if (ev(!reap->reap_wq)) {
		free_aligned(reap);
		return merr(ENOMEM);
	}

	atomic_set(&reap->reap_lwm, 0);
	atomic_set(&reap->reap_ttl, 0);
	atomic_set(&reap->reap_eidx, 0);
	atomic_set(&reap->reap_emit, 0);

	for (i = 0; i < REAP_ELEM_MAX; ++i) {
		elem = &reap->reap_elem[i];

		mutex_init(&elem->reap_lock);
		INIT_LIST_HEAD(&elem->reap_list);

		INIT_WORK(&elem->reap_work, mpc_reap_run);
		atomic_set(&elem->reap_running, 0);
		elem->reap_reap = reap;

		atomic64_set(&elem->reap_hpages, 0);
		atomic64_set(&elem->reap_wpages, 0);
		atomic64_set(&elem->reap_cpages, 0);
		atomic_set(&elem->reap_nfreed, 0);
	}

	INIT_DELAYED_WORK(&reap->reap_dwork, mpc_reap_prune);
	queue_delayed_work(reap->reap_wq, &reap->reap_dwork, 1);

	*reapp = reap;

	return 0;
}

void mpc_reap_destroy(struct mpc_reap *reap)
{
	struct mpc_reap_elem   *elem;
	int                     i;

	if (ev(!reap))
		return;

	cancel_delayed_work_sync(&reap->reap_dwork);

	/* There shouldn't be any reapers running at this point,
	 * but perform a flush/wait for good measure...
	 */
	atomic_set(&reap->reap_lwm, 0);
	flush_workqueue(reap->reap_wq);

	for (i = 0; i < REAP_ELEM_MAX; ++i) {
		elem = &reap->reap_elem[i];

		assert(atomic64_read(&elem->reap_hpages) == 0);
		assert(atomic64_read(&elem->reap_wpages) == 0);
		assert(atomic64_read(&elem->reap_cpages) == 0);
		assert(atomic_read(&elem->reap_nfreed) == 0);
		assert(list_empty(&elem->reap_list));

		mutex_destroy(&elem->reap_lock);
	}

	destroy_workqueue(reap->reap_wq);
	free_aligned(reap);
}

void mpc_reap_vma_add(struct mpc_reap *reap, struct mpc_vma *meta)
{
	struct mpc_reap_elem   *elem;
	uint                    idx;
	uint                    mult;

	if (!reap || !meta)
		return;

	if (meta->mcm_advice == MPC_VMA_PINNED)
		return;

	mult = 1;
	if (meta->mcm_advice == MPC_VMA_WARM)
		mult = 10;
	else if (meta->mcm_advice == MPC_VMA_HOT)
		mult = 30;

	/* Acquire a reference on meta for the reaper...
	 */
	atomic_inc(&meta->mcm_reapref);
	meta->mcm_reap = reap;

	idx = (get_cycles() >> 1) % REAP_ELEM_MAX;

	elem = &reap->reap_elem[idx];

	mutex_lock(&elem->reap_lock);
	meta->mcm_freedp = &elem->reap_nfreed;

	if (meta->mcm_advice == MPC_VMA_HOT)
		meta->mcm_hcpagesp = &elem->reap_hpages;
	else if (meta->mcm_advice == MPC_VMA_WARM)
		meta->mcm_hcpagesp = &elem->reap_wpages;
	else
		meta->mcm_hcpagesp = &elem->reap_cpages;

	list_add_tail(&meta->mcm_list, &elem->reap_list);
	mutex_unlock(&elem->reap_lock);
}

void mpc_reap_vma_evict(struct mpc_vma *meta)
{
	pgoff_t start, end, bktsz;

	if (atomic_cmpxchg(&meta->mcm_evicting, 0, 1))
		return;

	start = mpc_vma_pgoff(meta);
	end = mpc_vma_pglen(meta) + start;
	bktsz = meta->mcm_bktsz >> PAGE_SHIFT;

	if (bktsz < 1024)
		bktsz = end - start;

	/* Evict in chunks to improve mmap_sem interleaving...
	 */
	for (; start < end; start += bktsz)
		invalidate_inode_pages2_range(
			meta->mcm_mapping, start, start + bktsz);

	atomic_cmpxchg(&meta->mcm_evicting, 1, 0);
}

void mpc_reap_vma_touch(struct mpc_vma *meta, int index)
{
	struct mpc_reap    *reap;
	atomic64_t         *atimep;
	pgoff_t             offset;
	ulong               delay;
	uint                mbnum;
	uint                lwm;
	u64                 now;

	reap = meta->mcm_reap;
	if (!reap)
		return;

	offset = (index << PAGE_SHIFT) % (1ul << mpc_vma_size_max);
	mbnum = offset / meta->mcm_bktsz;

	atimep = &meta->mcm_mbinfov[mbnum].mbatime;
	now = local_clock();

	/* Don't update atime too frequently.  If we set atime to
	 * U64_MAX in mpc_reap_evict_vma() then the addition here
	 * will roll over and atime will be updated.
	 */
	if (atomic64_read(atimep) + (10 * USEC_PER_SEC) < now)
		atomic64_set(atimep, now);

	/* Sleep a bit if the reaper is having trouble meeting
	 * the free memory target.
	 */
	lwm = atomic_read(&reap->reap_lwm);
	if (lwm < 3333)
		return;

	delay = 500000 / (10001 - lwm) - (500000 / 10001);
	delay = min_t(ulong, delay, 3000);

	usleep_range(delay, delay * 2);
}

bool mpc_reap_vma_duress(struct mpc_vma *meta)
{
	struct mpc_reap    *reap;
	uint                lwm;

	if (meta->mcm_advice == MPC_VMA_HOT)
		return false;

	reap = meta->mcm_reap;
	if (!reap)
		return false;

	lwm = atomic_read(&reap->reap_lwm);
	if (lwm < 1500)
		return false;

	if (lwm > 3000)
		return true;

	return (meta->mcm_advice == MPC_VMA_COLD);
}

void mpc_reap_init(void)
{
	ulong   mavail;
	uint    pct = 60;

	mpc_reap_meminfo(NULL, &mavail, 30);

	if (mavail > 256)
		pct = 10;
	else if (mavail > 128)
		pct = 13;
	else if (mavail > 64)
		pct = 25;
	else if (mavail > 32)
		pct = 40;

	mpc_reap_mempct_set(100 - pct);
}
