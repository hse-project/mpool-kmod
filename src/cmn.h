/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * DOC: Module info.
 *
 * Common mpool definitions and utilities module.
 *
 */
#ifndef MPOOL_CMN_PRIV_H
#define MPOOL_CMN_PRIV_H

/**
 * mpool_pd_status_get() -
 * @pd:
 *
 * Return: status of pool disk.
 */
enum pd_status mpool_pd_status_get(struct mpool_dev_info *pd);

/**
 * mpool_pd_status_set() -
 * @pd:
 * @status:
 *
 */
void mpool_pd_status_set(struct mpool_dev_info *pd, enum pd_status status);

/**
 * check_for_dups() - Detect duplicates in a string list
 * @list: list of c strings to be checked
 * @cnt:  number of strings in the list
 * @dup:  out, set if there are duplicates
 * @offset: out, updated with the offset of the first duplicate.
 *
 * Detects if there are duplicate strings in a string list, also finds the
 * offset of the first duplicate.
 *
 * Return: %0 if successfull, merr_t if failed.
 */
merr_t check_for_dups(char **list, int cnt, int *dup, int *offset);

#endif
