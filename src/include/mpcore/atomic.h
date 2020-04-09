/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_ATOMIC_H
#define MPOOL_ATOMIC_H

#include <linux/atomic.h>

/*
 * atomic_ptr_cmpxchg()
 *
 * if (*ptr == oldv):
 *     *ptr = newv
 *     return newv
 * else
 *     return *ptr (previous contents, which were not expected)
 */
static inline void *atomic_ptr_cmpxchg(void **p, void *expectedv, void *newv)
{
	void *retv = expectedv;

	if (!__atomic_compare_exchange_n(p, &retv, newv, 0,
					 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
		return (void *)retv;

	return (void *)newv;
}


/* The increment must complete before any subsequent load or store
 * (in program order across all cpus in the system) is performed.
 */
static inline int atomic_inc_acq(atomic_t *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_ACQUIRE);
}

/* All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the decrement is performed.
 */
static inline int atomic_dec_rel(atomic_t *v)
{
	return __atomic_sub_fetch(&v->counter, 1, __ATOMIC_RELEASE);
}

/* All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the store is performed.
 */
static inline void atomic_set_rel(atomic_t *v, int n)
{
	__atomic_store_n(&v->counter, n, __ATOMIC_RELEASE);
}

/* The read must complete (in program order) before any subsequent
 * load or store is performed.
 */
static inline int atomic_read_acq(const atomic_t *v)
{
	return __atomic_load_n(&v->counter, __ATOMIC_ACQUIRE);
}

/* The increment must complete before any subsequent load or store
 * (in program order across all cpus in the system) is performed.
 */
static inline int atomic64_inc_acq(atomic64_t *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_ACQUIRE);
}

/* All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the decrement is performed.
 */
static inline int atomic64_inc_rel(atomic64_t *v)
{
	return __atomic_add_fetch(&v->counter, 1, __ATOMIC_RELEASE);
}

static inline int atomic_or_fetch_rel(atomic_t *v, int val)
{
	return __atomic_or_fetch(&v->counter, val, __ATOMIC_RELEASE);
}

static inline int atomic_and_fetch_rel(atomic_t *v, int val)
{
	return __atomic_and_fetch(&v->counter, val, __ATOMIC_RELEASE);
}

static inline void *atomic_ptr_exchange(void **p, void *val)
{
	return (void *)__atomic_exchange_n(p, val, __ATOMIC_RELAXED);
}

/* Atomically reads the value of @v.
 *
 * The read must complete (in program order) before any subsequent
 * load or store is performed.
 */
static inline long atomic64_read_acq(const atomic64_t *v)
{
	return __atomic_load_n(&v->counter, __ATOMIC_ACQUIRE);
}

/* Atomically return the current value of *v and then perform *v = *v + i.
 *
 * The fetch/add must complete before any subsequent load or store
 * (in program order across all cpus in the system) is performed.
 */
static inline long atomic64_fetch_add_acq(long i, atomic64_t *v)
{
	return __atomic_fetch_add(&v->counter, i, __ATOMIC_ACQUIRE);
}

/* Atomically return the current value of *v and then perform *v = *v + i.
 *
 * All prior loads and stores (in program order across all cpus in
 * the system) must have completed before the fetch/add is performed.
 */
static inline long atomic64_fetch_add_rel(long i, atomic64_t *v)
{
	return __atomic_fetch_add(&v->counter, i, __ATOMIC_RELEASE);
}

#endif
