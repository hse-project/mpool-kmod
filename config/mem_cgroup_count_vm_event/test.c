// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/memcontrol.h>

int
test(void)
{
    mem_cgroup_count_vm_event((struct mm_struct *)NULL, 0);

    return 0;
}
