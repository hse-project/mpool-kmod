/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_ALLOC_H
#define MPOOL_ALLOC_H

#include <linux/gfp.h>

/**
 * alloc_aligned() - allocated aligned memory
 * @size:   desired number of bytes
 * @align:  desired alignment
 * @flags:  flags passed to kmalloc()
 *
 * %align must be a power-of-two less than or equal to PAGE_SIZE.
 */
void *alloc_aligned(size_t size, size_t align, gfp_t flags);

void free_aligned(const void *ptr);


struct numa_elmset;

/**
 * numa_elmset_create() - Create a set of elements/buffers from
 *	each system numa node.
 *
 * @nb_el_node: number of elements to allocate per memory node.
 * @el_sz: size of one element in bytes. The element size must be <= PAGE_SIZE
 * @init_func: called on each element.
 *
 * The amount of usable memory allocated per node in bytes is
 * el_sz*nb_el_node.
 * Each element doesn't share cache lines with other elements.
 * The allocation is done by pages. The pages allocated on each node are not
 * physically contiguous, it is not required.
 *
 */
void *
numa_elmset_create(u32 nb_el_node, size_t el_sz, void (*init_func)(void *));

/**
 * numa_elmset_destroy() - Destroy a set of elements.
 * @nm:
 *
 * Called to free what was allocated by numa_elmset_alloc().
 */
void numa_elmset_destroy(struct numa_elmset *nm);

/**
 * numa_elmset_addr() - return the address of the element located on node "node"
 *	at index "idx".
 * @nm:
 * @node:
 * @idx: index of the element on the node. 0 first elem, 1 second etc...
 */
void *numa_elmset_addr(struct numa_elmset *nm, int node, u32 idx);

#endif
