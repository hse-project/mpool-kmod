// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/memcontrol.h>

int
test(void)
{
    count_memcg_event_mm(NULL, 0);

    return 0;
}
