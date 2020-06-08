// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/uio.h>

int
test(void)
{
    return iov_iter_get_pages(NULL, NULL, 0, 0, NULL);
}
