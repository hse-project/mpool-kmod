/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_EVC_H
#define MPOOL_EVC_H

#include <linux/atomic.h>
#include <linux/cache.h>

struct evc {
	atomic64_t  evc_odometer;
	struct evc *evc_next;
	const char *evc_file;
	const char *evc_func;
	int         evc_line;
} ____cacheline_aligned;

#define _evc_section       __section(mpool_evc)

#define ev(_expr)						\
	({							\
		static struct evc _evc _evc_section = {		\
			.evc_odometer = ATOMIC_INIT(0),		\
			.evc_next = NULL,			\
			.evc_file = __FILE__,			\
			.evc_func = __func__,			\
			.evc_line = __LINE__,			\
		};						\
		typeof(_expr) _tmp = (_expr);			\
								\
		unlikely(_tmp) ? (evc_count(&_evc), _tmp) : _tmp;	\
	})

void evc_count(struct evc *evc);
void evc_init(void);
void evc_fini(void);

#endif /* MPOOL_EVC_H */
