// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/bio.h>

int
test(void)
{
    struct block_device *bdev = (void *)1;
    struct bio *bio = (void *)1;

    bio_set_dev(bio, bdev);

    return 0;
}
