// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/mm.h>

#include "../vm_fault_t/config.h"

#if !HAVE_VM_FAULT_T
typedef int vm_fault_t;
#endif

static vm_fault_t my_fault(struct vm_fault *vmf)
{
    return 0;
}

static const struct vm_operations_struct vops = {
    .fault = my_fault,
};

int
test(void)
{
    return vops.fault(NULL);
}
