/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MPCORE_INIT_H
#define MPOOL_MPCORE_INIT_H

/**
 * mpool_mod_init() - mpool module initialization function
 *
 * Return: 0 if successful, -(errno) otherwise
 */
int mpool_mod_init(void);

/**
 * mpool_mod_exit() - mpool module exit function
 *
 */
void mpool_mod_exit(void);

#endif
