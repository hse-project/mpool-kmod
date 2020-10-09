/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PRINTK_H
#define MPOOL_PRINTK_H

#include <linux/printk.h>

static unsigned long mp_pr_rl_state __maybe_unused;

/* TODO: Use dev_crit(), dev_err(), ... */

#define mp_pr_crit(_fmt, _err, ...)				\
	pr_crit("%s: " _fmt ": errno %d", __func__, ## __VA_ARGS__, (_err))

#define mp_pr_err(_fmt, _err, ...)				\
	pr_err("%s: " _fmt ": errno %d", __func__, ## __VA_ARGS__, (_err))

#define mp_pr_warn(_fmt, ...)					\
	pr_warn("%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_notice(_fmt, ...)					\
	pr_notice("%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_info(_fmt, ...)					\
	pr_info("%s: " _fmt, __func__, ## __VA_ARGS__)

#define mp_pr_debug(_fmt, _err, ...)				\
	pr_debug("%s: " _fmt ": errno %d", __func__, ## __VA_ARGS__,  (_err))


/* Rate limited version of mp_pr_err(). */
#define mp_pr_rl(_fmt, _err, ...)				\
do {								\
	if (printk_timed_ratelimit(&mp_pr_rl_state, 333)) {	\
		pr_err("%s: " _fmt ": errno %d",		\
		       __func__, ## __VA_ARGS__, (_err));	\
	}							\
} while (0)

#endif /* MPOOL_PRINTK_H */
