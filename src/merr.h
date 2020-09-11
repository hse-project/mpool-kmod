/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MERR_H
#define MPOOL_MERR_H

#define EBUG                (666)

typedef int                 merr_t;

#define merr(_errnum)       (_errnum)

static inline int merr_errno(merr_t merr)
{
	return merr;
}

#endif /* MPOOL_MERR_H */
