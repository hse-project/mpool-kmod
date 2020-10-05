// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/module.h>

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
unsigned int xvm_max __read_mostly = 1048576 * 128;
module_param(xvm_max, uint, 0444);
MODULE_PARM_DESC(xvm_max, " max extended VMA regions");

unsigned int xvm_size_max __read_mostly = 30;
module_param(xvm_size_max, uint, 0444);
MODULE_PARM_DESC(xvm_size_max, " max extended VMA size log2");

unsigned int maxunits __read_mostly = 1024;
module_param(maxunits, uint, 0444);
MODULE_PARM_DESC(maxunits, " max mpools");

unsigned int rwsz_max_mb __read_mostly = 32;
module_param(rwsz_max_mb, uint, 0444);
MODULE_PARM_DESC(rwsz_max_mb, " max mblock/mlog r/w size (mB)");

unsigned int rwconc_max __read_mostly = 8;
module_param(rwconc_max, uint, 0444);
MODULE_PARM_DESC(rwconc_max, " max mblock/mlog large r/w concurrency");

unsigned int rsvd_bios_max __read_mostly = 16;
module_param(rsvd_bios_max, uint, 0444);
MODULE_PARM_DESC(rsvd_bios_max, "max reserved bios in mpool bioset");

int chunk_size_kb __read_mostly = 128;
module_param(chunk_size_kb, uint, 0644);
MODULE_PARM_DESC(chunk_size_kb, "Chunk size (in KiB) for device I/O");

static void mpool_exit_impl(void)
{
	mpctl_exit();
	mcache_exit();
	pmd_exit();
	smap_exit();
	sb_exit();
	omf_exit();
	pd_exit();
}

static __init int mpool_init(void)
{
	const char *errmsg = NULL;
	int rc;

	rc = pd_init();
	if (rc) {
		errmsg = "pd init failed";
		goto errout;
	}

	rc = omf_init();
	if (rc) {
		errmsg = "omf init failed";
		goto errout;
	}

	rc = sb_init();
	if (rc) {
		errmsg = "sb init failed";
		goto errout;
	}

	rc = smap_init();
	if (rc) {
		errmsg = "smap init failed";
		goto errout;
	}

	rc = pmd_init();
	if (rc) {
		errmsg = "pmd init failed";
		goto errout;
	}

	rc = mcache_init();
	if (rc) {
		errmsg = "mcache init failed";
		goto errout;
	}

	rc = mpctl_init();
	if (rc) {
		errmsg = "mpctl init failed";
		goto errout;
	}

errout:
	if (rc) {
		mp_pr_err("%s", rc, errmsg);
		mpool_exit_impl();
	}

	return rc;
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
