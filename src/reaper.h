/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_REAPER_H
#define MPOOL_REAPER_H

#define MPC_REAP_PARAMS_CNT    3

struct mpc_reap;
struct mpc_xvm;

/**
 * mpc_reap_create() - Allocate and initialize reap data strctures
 * @reapp: Ptr to initialized reap structure.
 *
 * Return: -ENOMEM if the allocaiton fails.
 */
int mpc_reap_create(struct mpc_reap **reapp);

/**
 * mpc_reap_destroy() - Destroy the given reaper
 * @reap:
 */
void mpc_reap_destroy(struct mpc_reap *reap);

/**
 * mpc_reap_xvm_add() - Add an extended VMA to the reap list
 * @xvm: extended VMA
 */
void mpc_reap_xvm_add(struct mpc_reap *reap, struct mpc_xvm *xvm);

/**
 * mpc_reap_xvm_evict() - Evict all pages of given extended VMA
 * @xvm: extended VMA
 */
void mpc_reap_xvm_evict(struct mpc_xvm *xvm);

/**
 * mpc_reap_xvm_touch() - Update extended VMA mblock atime
 * @xvm:    extended VMA
 * @index:  valid page index within the extended VMA
 *
 * Update the access time stamp of the mblock given by the valid
 * page %index within the VMA.  Might sleep for some number of
 * microseconds if the reaper is under duress (i.e., the more
 * urgent the duress the longer the sleep).
 *
 * This function is called only by mpc_vm_fault_impl(), once
 * for each successful page fault.
 */
void mpc_reap_xvm_touch(struct mpc_xvm *xvm, int index);

/**
 * mpc_reap_xvm_duress() - Check to see if reaper is under duress
 * @xvm:   extended VMA
 *
 * Return: %false if the VMA is marked MPC_XVM_HOT.
 * Return: %false if reaper is not enabled nor under duress.
 * Return: %true depending upon the urgency of duress and the
 * VMA advice (MPC_XVM_WARM or MPC_XVM_COLD).
 *
 * This function is called only by mpc_readpages() to decide whether
 * or not to reduce the size of a speculative readahead request.
 */
bool mpc_reap_xvm_duress(struct mpc_xvm *xvm);

void mpc_reap_params_add(struct device_attribute *dattr);

#endif /* MPOOL_REAPER_H */
