/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_ASSERT_H
#define MPOOL_ASSERT_H

#include <linux/bug.h>

#ifdef NDEBUG
#define assert(cond)
#else
#define assert(cond)    BUG_ON(!(cond))
#endif

#endif
