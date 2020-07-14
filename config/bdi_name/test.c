// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/backing-dev.h>

int test(void)
{
    return noop_backing_dev_info.name ? 0 : -EINVAL;
}
