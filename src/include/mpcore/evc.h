/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_EVC_H
#define MPOOL_EVC_H

#include <linux/atomic.h>
#include <linux/cache.h>

struct evc {
	atomic64_t      evc_odometer;
	atomic64_t      evc_odometer_timestamp;
	atomic64_t      evc_trip_odometer_timestamp;
	int             evc_trip_odometer;
	u32             evc_flags;
} ____cacheline_aligned;

#define ev(_expr)						\
	({							\
		static struct evc _evc = {			\
			.evc_odometer = ATOMIC_INIT(0),		\
			.evc_trip_odometer = 0,			\
			.evc_flags = 0,				\
		};						\
		typeof(_expr) _tmp = _expr;			\
								\
		unlikely(_tmp) ? (evc_count(&_evc), _tmp) : _tmp;	\
	})

void evc_init(void);
void evc_count(struct evc *evc);

#endif
