/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPCTL_REAP_H
#define MPCTL_REAP_H

struct mpc_reap;
struct mpc_vma;

/**
 * mpc_reap_create() - Allocate and initialize reap data strctures
 * @reapp: Ptr to initialized reap structure.
 *
 * Return: ENOMEM if the allocaiton fails.
 */
merr_t
mpc_reap_create(
	struct mpc_reap  **reapp);

/**
 * mpc_reap_destroy() - Destroy the given reaper
 * @reap:
 */
void
mpc_reap_destroy(
	struct mpc_reap    *reap);

/**
 * mpc_reap_vma_add() - Add a vma to the reap list
 * @meta:  ds vma
 */
void
mpc_reap_vma_add(
	struct mpc_reap  *reap,
	struct mpc_vma   *meta);

/**
 * mpc_reap_vma_evict() - Evict all pages of given VMA
 * @meta:
 */
void
mpc_reap_vma_evict(
	struct mpc_vma     *meta);

/**
 * mpc_reap_vma_touch() - Update vma mblock atime
 * @meta:   ds vma
 * @index:  valid page index within the VMA
 *
 * Update the access time stamp of the mblock given by the valid
 * page %index within the VMA.  Might sleep for some number of
 * microseconds if the reaper is under duress (i.e., the more
 * urgent the duress the longer the sleep).
 *
 * This function is called only by mpc_vm_fault_impl(), once
 * for each successful page fault.
 */
void
mpc_reap_vma_touch(
	struct mpc_vma *meta,
	int             index);

/**
 * mpc_reap_vma_duress() - Check to see if reaper is under duress
 * @meta:   ds vma
 *
 * Return: %false if the VMA is marked MPC_VMA_HOT.
 * Return: %false if reaper is not enabled nor under duress.
 * Return: %true depending upon the urgency of duress and the
 * VMA advice (MPC_VMA_WARM or MPC_VMA_COLD).
 *
 * This function is called only by mpc_readpages() to decide whether
 * or not to reduce the size of a speculative readahead request.
 */
bool
mpc_reap_vma_duress(
	struct mpc_vma *meta);

#endif /* MPCTL_REAP_H */
