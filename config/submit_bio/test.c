// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/bio.h>

int
test(void)
{
    submit_bio(NULL);

    return 0;
}
