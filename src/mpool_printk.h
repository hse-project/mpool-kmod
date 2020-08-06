/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PRINTK_H
#define MPOOL_PRINTK_H

#include <linux/printk.h>

#include "merr.h"

/* TODO: Use dev_crit(), dev_err(), ... */

#define mp_pr_crit(_fmt, _err, ...)				\
do {								\
	char errbuf[128];					\
								\
	pr_crit("%s: " _fmt ": %s",		                \
	       __func__, ## __VA_ARGS__,			\
	       merr_strinfo((_err), errbuf, sizeof(errbuf)));	\
} while (0)

#define mp_pr_err(_fmt, _err, ...)				\
do {								\
	char errbuf[128];					\
								\
	pr_err("%s: " _fmt ": %s",		                \
	       __func__, ## __VA_ARGS__,			\
	       merr_strinfo((_err), errbuf, sizeof(errbuf)));	\
} while (0)

#define mp_pr_warn(_fmt, ...)					\
	pr_warn("%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_notice(_fmt, ...)					\
	pr_notice("%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_info(_fmt, ...)					\
	pr_info("%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_debug(_fmt, _err, ...)				\
do {								\
	char errbuf[128];					\
								\
	pr_debug("%s: " _fmt ": %s",			        \
	       __func__, ## __VA_ARGS__,			\
	       merr_strinfo((_err), errbuf, sizeof(errbuf)));	\
} while (0)


/* Rate limited version of mp_pr_err(). */
#define mp_pr_rl(_fmt, _err, ...)				\
do {								\
	static unsigned long state;				\
	uint dly = msecs_to_jiffies(333);			\
	char errbuf[128];					\
								\
	if (printk_timed_ratelimit(&state, dly)) {		\
		merr_strinfo((_err), errbuf, sizeof(errbuf));	\
		pr_err("%s: " _fmt ": %s",		        \
		       __func__, ## __VA_ARGS__, errbuf);	\
	}							\
} while (0)

#endif /* MPOOL_PRINTK_H */
