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

struct uuid_to_idx_rb *
uuid_to_idx_search(struct rb_root *root, struct mpool_uuid *key_uuid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct uuid_to_idx_rb *data =
			rb_entry(node, struct uuid_to_idx_rb, uti_node);
		int result;

		result = mpool_uuid_compare(key_uuid, &data->uti_uuid);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

int uuid_to_idx_insert(struct rb_root *root, struct uuid_to_idx_rb *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct uuid_to_idx_rb *this =
			rb_entry(*new, struct uuid_to_idx_rb, uti_node);
		int result = mpool_uuid_compare(&data->uti_uuid, &this->uti_uuid);

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->uti_node, parent, new);
	rb_insert_color(&data->uti_node, root);

	return true;
}

struct u64_to_u64_rb *u64_to_u64_search(struct rb_root *root, u64 key_u64)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct u64_to_u64_rb   *data =
			rb_entry(node, struct u64_to_u64_rb, utu_node);

		if (key_u64 < data->utu_key)
			node = node->rb_left;
		else if (key_u64 > data->utu_key)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

int u64_to_u64_insert(struct rb_root *root, struct u64_to_u64_rb *data)
{
	struct rb_node    **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct u64_to_u64_rb *this =
			rb_entry(*new, struct u64_to_u64_rb, utu_node);
		parent = *new;
		if (data->utu_key < this->utu_key)
			new = &((*new)->rb_left);
		else if (data->utu_key > this->utu_key)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->utu_node, parent, new);
	rb_insert_color(&data->utu_node, root);

	return true;
}

struct ecio_layout_descriptor *
objid_to_layout_search_oml(struct rb_root *root, u64 key_objid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct ecio_layout_mlo *mlo =
			rb_entry(node, struct ecio_layout_mlo,
				 mlo_nodeoml);
		struct ecio_layout_descriptor *data = mlo->mlo_layout;

		if (key_objid < data->eld_objid)
			node = node->rb_left;
		else if (key_objid > data->eld_objid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

int
objid_to_layout_insert_oml(
	struct rb_root                 *root,
	struct ecio_layout_descriptor  *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct ecio_layout_mlo *mlo =
			rb_entry(*new, struct ecio_layout_mlo,
				 mlo_nodeoml);
		struct ecio_layout_descriptor *this = mlo->mlo_layout;

		parent = *new;
		if (data->eld_objid < this->eld_objid)
			new = &((*new)->rb_left);
		else if (data->eld_objid > this->eld_objid)
			new = &((*new)->rb_right);
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->eld_nodeoml, parent, new);
	rb_insert_color(&data->eld_nodeoml, root);

	return true;
}

struct ecio_layout_descriptor *
objid_to_layout_search_mdc(struct rb_root *root, u64 key_objid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct ecio_layout_descriptor *data =
			rb_entry(node, struct ecio_layout_descriptor,
				 eld_nodemdc);
		if (key_objid < data->eld_objid)
			node = node->rb_left;
		else if (key_objid > data->eld_objid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

struct ecio_layout_descriptor *
objid_to_layout_insert_mdc(
	struct rb_root                 *root,
	struct ecio_layout_descriptor  *data)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to insert given layout, or return the colliding
	 * layout if there's already a layout in the tree with the given ID.
	 */
	while (*new) {
		struct ecio_layout_descriptor *this =
			rb_entry(*new, struct ecio_layout_descriptor,
				     eld_nodemdc);
		parent = *new;
		if (data->eld_objid < this->eld_objid)
			new = &((*new)->rb_left);
		else if (data->eld_objid > this->eld_objid)
			new = &((*new)->rb_right);
		else
			return this;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&data->eld_nodemdc, parent, new);
	rb_insert_color(&data->eld_nodemdc, root);

	return NULL;
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

void mp_obj_rwl_prefetch(struct mp_obj_descriptor *obj, bool w)
{
	if (obj) {
		if (w)
			__builtin_prefetch(
			((struct ecio_layout_descriptor *)obj)->eld_rwlock, 1);
		else
			__builtin_prefetch(
			((struct ecio_layout_descriptor *)obj)->eld_rwlock, 0);
	}
}
