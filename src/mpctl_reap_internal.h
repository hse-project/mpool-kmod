/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPCTL_REAP_INTERNAL_H
#define MPCTL_REAP_INTERNAL_H

#define REAP_ELEM_MAX       3

/**
 * struct mpc_reap_elem -
 * @reap_lock:      lock to protect reap_list
 * @reap_list:      list of inodes
 * @reap_active:    reaping in progress
 * @reap_hpages:    total hot pages which are mapped
 * @reap_cpages:    total coldpages which are mapped
 */
struct mpc_reap_elem {
	struct mutex            reap_lock;
	struct list_head        reap_list;

	____cacheline_aligned
	atomic_t                reap_running;
	struct work_struct      reap_work;
	struct mpc_reap        *reap_reap;

	____cacheline_aligned
	atomic64_t              reap_hpages;
	atomic_t                reap_nfreed;

	____cacheline_aligned
	atomic64_t              reap_wpages;

	____cacheline_aligned
	atomic64_t              reap_cpages;
};

/**
 * struct mpc_reap -
 * @reap_lwm:    Low water mark
 * @reap_ttl:    Time-to-live
 * @reap_wq:
 * @reap_eidx:   Pruner element index
 * @reap_emit:   Pruner debug message control
 * @reap_elem:    Array of reaper lists (reaper pool)
 */
struct mpc_reap {
	atomic_t                    reap_lwm;
	atomic_t                    reap_ttl;
	struct workqueue_struct    *reap_wq;

	____cacheline_aligned
	atomic_t                    reap_eidx;
	atomic_t                    reap_emit;
	struct delayed_work         reap_dwork;

	struct mpc_reap_elem        reap_elem[REAP_ELEM_MAX];
};

#endif /* MPCTL_REAP_INTERNAL_H */
