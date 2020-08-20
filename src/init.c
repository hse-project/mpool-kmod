// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/module.h>

#include "merr.h"
#include "evc.h"
#include "mpool_printk.h"

#include "omf_if.h"
#include "pd.h"
#include "smap.h"
#include "pmd_obj.h"
#include "sb.h"
#include "mcache.h"
#include "mpctl.h"

/*
 * Module params...
 */
unsigned int mpc_xvm_max __read_mostly = 1048576 * 128;
module_param(mpc_xvm_max, uint, 0444);
MODULE_PARM_DESC(mpc_xvm_max, " max extended VMA regions");

unsigned int mpc_xvm_size_max __read_mostly = 30;
module_param(mpc_xvm_size_max, uint, 0444);
MODULE_PARM_DESC(mpc_xvm_size_max, " max extended VMA size log2");

unsigned int mpc_maxunits __read_mostly = 1024;
module_param(mpc_maxunits, uint, 0444);
MODULE_PARM_DESC(mpc_maxunits, " max mpools");

unsigned int mpc_rwsz_max __read_mostly = 32;
module_param(mpc_rwsz_max, uint, 0444);
MODULE_PARM_DESC(mpc_rwsz_max, " max mblock/mlog r/w size (mB)");

unsigned int mpc_rwconc_max __read_mostly = 8;
module_param(mpc_rwconc_max, uint, 0444);
MODULE_PARM_DESC(mpc_rwconc_max, " max mblock/mlog large r/w concurrency");

unsigned int mpc_rsvd_bios_max __read_mostly = 16;
module_param(mpc_rsvd_bios_max, uint, 0444);
MODULE_PARM_DESC(mpc_rsvd_bios_max, "max reserved bios in mpool bioset");

int mpc_chunker_size __read_mostly = 128;
module_param(mpc_chunker_size, uint, 0644);
MODULE_PARM_DESC(mpc_chunker_size, "Chunking size (in KiB) for device I/O");

static void mpool_exit_impl(void)
{
	mpctl_exit();
	mcache_exit();
	pmd_exit();
	smap_exit();
	sb_exit();
	omf_exit();
	pd_exit();
	evc_exit();
}

/**
 * mpool_init() - Load and initialize mpool
 */
static __init int mpool_init(void)
{
	const char *errmsg = NULL;
	merr_t      err;

	evc_init();

	err = pd_init();
	if (err) {
		errmsg = "pd init failed";
		goto errout;
	}

	err = omf_init();
	if (err) {
		errmsg = "omf init failed";
		goto errout;
	}

	err = sb_init();
	if (err) {
		errmsg = "sb init failed";
		goto errout;
	}

	err = smap_init();
	if (err) {
		errmsg = "smap init failed";
		goto errout;
	}

	err = pmd_init();
	if (err) {
		errmsg = "pmd init failed";
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
