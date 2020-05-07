// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * DOC: Module info.
 *
 * Common until functions.
 */

#include <linux/sort.h>

#include <mpcore/atomic.h>

#include "mpcore_defs.h"

enum pd_status mpool_pd_status_get(struct mpool_dev_info *pd)
{
	enum pd_status  val;

	/* Acquire semantics used so that no reads will be re-ordered from
	 * before to after this read.
	 */
	val = atomic_read_acq(&pd->pdi_status);

	return val;
}

void mpool_pd_status_set(struct mpool_dev_info *pd, enum pd_status status)
{
	/* All prior writes must be visible prior to the status change */
	smp_wmb();
	atomic_set(&pd->pdi_status, status);
}

static int comp_func(const void *c1, const void *c2)
{
	return strcmp(*(char **)c1, *(char **)c2);
}

merr_t check_for_dups(char **listv, int cnt, int *dup, int *offset)
{
	const char **sortedv;
	const char  *prev;
	int          i;
	merr_t       err;

	*dup = 0;
	*offset = -1;

	if (0 == cnt || 1 == cnt)
		return 0;

	sortedv = kcalloc(cnt + 1, sizeof(char *), GFP_KERNEL);
	if (!sortedv) {
		err = merr(ENOMEM);
		mp_pr_err("kcalloc failed for %d paths, first path %s",
			  err, cnt, *listv);
		return err;
	}

	/* make a shallow copy */
	for (i = 0; i < cnt; i++)
		sortedv[i] = listv[i];

	sortedv[i] = NULL;

	sort(sortedv, cnt, sizeof(char *), comp_func, NULL);

	prev = sortedv[0];
	for (i = 1; i < cnt; i++) {
		if (strcmp(sortedv[i], prev) == 0) {
			mp_pr_info("path %s is duplicated", prev);
			*dup = 1;
			break;
		}

		prev = sortedv[i];
	}

	/* find offset, prev points to first dup */
	if (*dup) {
		for (i = 0; i < cnt; i++) {
			if (prev == listv[i]) {
				*offset = i;
				break;
			}
		}
	}

	kfree(sortedv);
	return 0;
}
