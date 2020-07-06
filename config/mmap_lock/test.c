// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/mmap_lock.h>

int test(void)
{
     mmap_read_unlock(NULL);
     return 0;
}
