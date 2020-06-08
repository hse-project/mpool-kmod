// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/fs.h>

int
test(void)
{
    struct address_space m = { .backing_dev_info = NULL, };

    return m.backing_dev_info ? 0 : -EINVAL;
}
