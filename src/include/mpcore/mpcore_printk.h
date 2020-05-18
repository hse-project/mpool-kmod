/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PRINTK_H
#define MPOOL_PRINTK_H

#include <linux/printk.h>

#include <mpcore/merr.h>

/* TODO: Use dev_crit(), dev_err(), ... */

#define mp_pr_crit(_fmt, _err, ...)				\
do {								\
	char errbuf[128];					\
								\
	printk(KERN_CRIT "%s: " _fmt ": %s",		        \
	       __func__, ## __VA_ARGS__,			\
	       merr_strinfo((_err), errbuf, sizeof(errbuf)));	\
} while (0)

#define mp_pr_err(_fmt, _err, ...)				\
do {								\
	char errbuf[128];					\
								\
	printk(KERN_ERR "%s: " _fmt ": %s",		        \
	       __func__, ## __VA_ARGS__,			\
	       merr_strinfo((_err), errbuf, sizeof(errbuf)));	\
} while (0)

#define mp_pr_warn(_fmt, ...)					\
	printk(KERN_WARNING "%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_notice(_fmt, ...)					\
	printk(KERN_NOTICE "%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_info(_fmt, ...)					\
	printk(KERN_INFO "%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_debug(_fmt, _err, ...)				\
do {								\
	char errbuf[128];					\
								\
	printk(KERN_DEBUG "%s: " _fmt ": %s",			\
	       __func__, ## __VA_ARGS__,			\
	       merr_strinfo((_err), errbuf, sizeof(errbuf)));	\
} while (0)


/* Rate limited version of mp_pr_err().
 */
#define mp_pr_rl(_fmt, _err, ...)				\
do {								\
	static unsigned long state;				\
	uint dly = msecs_to_jiffies(333);			\
	char errbuf[128];					\
								\
	if (printk_timed_ratelimit(&state, dly)) {		\
		merr_strinfo((_err), errbuf, sizeof(errbuf));	\
		printk(KERN_ERR "%s: " _fmt ": %s",		\
		       __func__, ## __VA_ARGS__, errbuf);	\
	}							\
} while (0)

#endif
