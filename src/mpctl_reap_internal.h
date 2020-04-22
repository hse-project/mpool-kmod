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
 * @reap_lwm:     Low water mark
 * @reap_ttl_cur: Current time-to-live
 * @reap_wq:
 *
 * @reap_hdr:     sysctl table header
 * @reap_tab:     sysctl table components
 * @reap_mempct:
 * @reap_ttl:
 * @reap_debug:
 *
 * @reap_eidx:    Pruner element index
 * @reap_emit:    Pruner debug message control
 * @reap_dwork:
 * @reap_elem:    Array of reaper lists (reaper pool)
 */
struct mpc_reap {
	atomic_t                    reap_lwm;
	atomic_t                    reap_ttl_cur;
	struct workqueue_struct    *reap_wq;

	____cacheline_aligned
	struct ctl_table_header    *reap_hdr;
	struct ctl_table           *reap_tab;
	int                         reap_mempct;
	int                         reap_ttl;
	int                         reap_debug;

	____cacheline_aligned
	atomic_t                    reap_eidx;
	atomic_t                    reap_emit;
	struct delayed_work         reap_dwork;

	struct mpc_reap_elem        reap_elem[REAP_ELEM_MAX];
};

#endif /* MPCTL_REAP_INTERNAL_H */
