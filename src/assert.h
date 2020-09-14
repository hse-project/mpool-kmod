/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_ASSERT_H
#define MPOOL_ASSERT_H

#include <linux/bug.h>

#ifdef CONFIG_MPOOL_ASSERT
__cold __noreturn
static inline void assertfail(const char *expr, const char *file, int line)
{
	pr_err("mpool assertion failed: %s in %s:%d\n", expr, file, line);
	BUG();
}

#define ASSERT(_expr)   (likely(_expr) ? (void)0 : assertfail(#_expr, __FILE__, __LINE__))

#else
#define ASSERT(_expr)   (void)(_expr)
#endif

#endif /* MPOOL_ASSERT_H */
