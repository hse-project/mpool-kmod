// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/numa.h>
#include <linux/vmalloc.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include <mpcore/assert.h>
#include <mpcore/alloc.h>

#ifndef ARCH_KMALLOC_MINALIGN
#define ARCH_KMALLOC_MINALIGN   __alignof__(unsigned long long)
#endif

void *alloc_aligned(size_t size, size_t align, gfp_t flags)
{
	void   *mem;
	size_t  sz;

	assert(!(align & (align - 1))); /* must be a power-of-2 */

	if (align < ARCH_KMALLOC_MINALIGN)
		align = ARCH_KMALLOC_MINALIGN;

	sz = size < align ? align : size;
	sz = ALIGN(sz, align);

	mem = kmalloc(sz + align, flags);
	if (mem) {
		void **ptr = (void *)(((uintptr_t)mem + align) & ~(align - 1));

		*(ptr - 1) = mem;
		mem = ptr;
	}

	return mem;
}

void free_aligned(const void *ptr)
{
	if (ptr) {
		ptr = *((const void **)ptr - 1);
		kfree(ptr);
	}
}

/**
 * struct numa_elmset - "nm" stands for numa
 * @nm_elm_per_node: max elements per numa node
 * @nm_nodec:        number of elements in nm_nodev[]
 * @nm_elm_sz:       element size (cache line aligned)
 * @nm_order:        node pages alloc order
 * @nm_nodev:        vector of per-numa node base memory addresses
 */
struct numa_elmset {
	u32     nm_elm_per_node;
	u32     nm_nodec;
	u32     nm_elm_sz;
	u32     nm_order;
	void   *nm_nodev[];
};

void *
numa_elmset_create(u32 elm_per_node, size_t elm_sz, void (*init_func)(void *))
{
	struct numa_elmset *nm = NULL;
	struct page       **pagev;

	uint    pg_per_node, order;
	int     node, node_max, i;

	elm_sz = ALIGN(elm_sz, SMP_CACHE_BYTES);
	pg_per_node = (elm_per_node * elm_sz + PAGE_SIZE - 1) / PAGE_SIZE;

	if (pg_per_node < 1 || pg_per_node > 32 ||
	    elm_sz > PAGE_SIZE || elm_per_node > PAGE_SIZE * 32)
		return NULL;

	pagev = vmalloc(MAX_NUMNODES * sizeof(*pagev));
	if (!pagev)
		return NULL;

	memset(pagev, 0, MAX_NUMNODES * sizeof(*pagev));

	order = get_order(pg_per_node * PAGE_SIZE);
	node_max = 0;

	for_each_online_node(node) {
		pagev[node] = alloc_pages_node(node, GFP_KERNEL, order);

		if (node >= node_max)
			node_max = node + 1;
	}

	for (node = 0; node < node_max; ++node) {
		if (!pagev[node]) {
			pagev[node] = alloc_pages(GFP_KERNEL, order);
			if (!pagev[node])
				goto errout;
		}
	}

	nm = kmalloc(sizeof(*nm) + node_max * sizeof(void *), GFP_KERNEL);
	if (!nm)
		goto errout;

	nm->nm_elm_per_node = elm_per_node;
	nm->nm_nodec = node_max;
	nm->nm_elm_sz = elm_sz;
	nm->nm_order = order;

	for (node = 0; node < node_max; ++node) {
		nm->nm_nodev[node] = page_address(pagev[node]);

		for (i = 0; i < elm_per_node && init_func; ++i)
			init_func(nm->nm_nodev[node] + elm_sz * i);
	}

errout:
	for (node = 0; node < node_max && !nm; ++node)
		__free_pages(pagev[node], order);

	vfree(pagev);

	return nm;
}

void numa_elmset_destroy(struct numa_elmset *nm)
{
	int node;

	for (node = 0; node < nm->nm_nodec && nm; ++node)
		free_pages((u64)nm->nm_nodev[node], nm->nm_order);

	kfree(nm);
}

void *numa_elmset_addr(struct numa_elmset *nm, int node, u32 idx)
{
	assert(nm);

	idx %= nm->nm_elm_per_node;
	node %= nm->nm_nodec;

	return nm->nm_nodev[node] + idx * nm->nm_elm_sz;
}
