// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/blkdev.h>

int test(void)
{
    return blkdev_issue_flush(NULL, 0, NULL);
}
