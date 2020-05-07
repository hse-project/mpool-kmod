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

/*
 * well-known values
 */

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


/* Common RB Tree access functions and structs */

/**
 * struct u64_to_u64_rb -
 * @utu_node:
 * @utu_key:
 * @utu_value:
 */
struct u64_to_u64_rb {
	struct rb_node  utu_node;
	u64             utu_key;
	u64             utu_value;
};

/**
 * u64_to_u64_search() -
 * @root:
 * @key_u64:
 *
 * Return: pointer to struct u64_to_u64_rb if found else NULL.
 */
struct u64_to_u64_rb *u64_to_u64_search(struct rb_root *root, u64 key_u64);

/**
 * u64_to_u64_insert() -
 * @root:
 * @data:
 *
 * Return: true on success else false.
 */
int u64_to_u64_insert(struct rb_root *root, struct u64_to_u64_rb *data);

/**
 * objid_to_layout_search_oml() -
 * @root:
 * @key_objid:
 *
 * Return: pointer to objid_to_layout_search_oml if found else NULL.
 */
struct ecio_layout_descriptor *
objid_to_layout_search_oml(struct rb_root *root, u64 key_objid);

/**
 * objid_to_layout_insert_oml() -
 * @root:
 * @data:
 *
 * Return: true on success else false.
 */
int
objid_to_layout_insert_oml(
	struct rb_root                 *root,
	struct ecio_layout_descriptor  *data);

/**
 * calc_io_len() -
 * @iov:
 * @iovcnt:
 *
 * Return: total bytes in iovec list.
 */
static inline u64 calc_io_len(struct iovec *iov, int iovcnt)
{
	int    i = 0;
	u64    rval = 0;

	for (i = 0; i < iovcnt; i++)
		rval += iov[i].iov_len;

	return rval;
};

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
