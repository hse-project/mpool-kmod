// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"

vm_fault_t x = 0;

int
test(void)
{
    return sizeof(x);
}
