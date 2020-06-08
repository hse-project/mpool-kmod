// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/fs.h>
#include <linux/mm.h>

static void my_invalidatepage(struct page *page, uint offset, uint length)
{
}

static struct address_space_operations aops = {
    .invalidatepage = my_invalidatepage,
};

int
test(void)
{
    aops.invalidatepage((struct page *)NULL, (uint)0, (uint)0);

    return 0;
}
