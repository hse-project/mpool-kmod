// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/fs.h>

static int test_fadvise(struct file *filp, loff_t off, loff_t len, int advice)
{
	return 0;
}

int test(void)
{
    const struct file_operations test_fops __maybe_unused = {
	    .fadvise = test_fadvise,
    };

    return 0;
}
