// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/module.h>

#include "mpool_defs.h"
#include "mcache.h"
#include "mpctl.h"

static void mpool_exit_impl(void)
{
	mpctl_exit();
	mcache_exit();
	mpcore_exit();
	evc_fini();
}

/**
 * mpool_init() - Load and initialize mpool
 */
static __init int mpool_init(void)
{
	const char             *errmsg = NULL;
	merr_t                  err;

	evc_init();

	err = mpcore_init();
	if (err) {
		errmsg = "mpcore init failed";
		goto errout;
	}

	err = mcache_init();
	if (err) {
		errmsg = "mcache init failed";
		goto errout;
	}

	err = mpctl_init();
	if (err) {
		errmsg = "mpctl init failed";
		goto errout;
	}

errout:
	if (err) {
		mp_pr_err("%s", err, errmsg);
		mpool_exit_impl();
	}

	return -merr_errno(err);
}

static __exit void mpool_exit(void)
{
	mpool_exit_impl();
}

module_init(mpool_init);
module_exit(mpool_exit);

MODULE_DESCRIPTION("Object Storage Media Pool (mpool)");
MODULE_AUTHOR("Micron Technology, Inc.");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(MPOOL_VERSION);
