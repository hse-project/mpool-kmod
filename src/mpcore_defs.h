/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/* DOC: Module info.
 *
 * Common headers definitions for mpool.
 *
 */
#ifndef MPOOL_MPCORE_DEFS_PRIV_H
#define MPOOL_MPCORE_DEFS_PRIV_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/kref.h>

#include <mpool/mpool_ioctl.h>

#include <mpcore/mpcore_printk.h>
#include <mpcore/mpcore_defs.h>
#include <mpcore/evc.h>
#include <mpcore/assert.h>

#include "init.h"
#include "omf.h"
#include "omf_if.h"
#include "ecio.h"
#include "pd.h"
#include "pd_bio.h"
#include "smap.h"
#include "pmd.h"
#include "mlog.h"
#include "mclass.h"
#include "mp.h"
#include "sb.h"
#include "upgrade.h"

#endif
