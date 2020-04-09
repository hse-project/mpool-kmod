/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * DOC: Module info.
 *
 * Defines qos functions used by mpool core or mpool control
 */

/* TODO: This file will be gone soon. */

#ifndef MPOOL_MPCORE_QOS_H
#define MPOOL_MPCORE_QOS_H

#include <linux/atomic.h>
#include <linux/wait.h>

#include <mpcore/merr.h>

/**
 * asynchronous IO
 * @mio_iocnt : pending io Count
 * @mio_lock:   Wait queue
 */
struct mio_asyncctx {
	atomic_t                 mio_iocnt;
	merr_t                   mio_err;
	wait_queue_head_t        mio_lock;
} ____cacheline_aligned;

#endif
