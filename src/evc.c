// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/version.h>

#include <mpcore/evc.h>

static void evc_get_timestamp(atomic64_t *timestamp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	ktime_t t;
#define XXTIME t.tv64
#else
	u64 t;
#define XXTIME t
#endif
	t = ktime_get_real();
	atomic64_set(timestamp, XXTIME);
}

void evc_init(void)
{
	static struct evc evc __maybe_unused = {
		.evc_odometer = ATOMIC_INIT(0),
	};
}

void evc_count(struct evc *evc)
{
	if (unlikely(atomic64_inc_return(&evc->evc_odometer) == 1)) {
		/* TODO: to be implemented/enhanced */
	}

	evc_get_timestamp(&evc->evc_odometer_timestamp);
}
