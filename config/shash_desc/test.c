// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <crypto/hash.h>

int
test(void)
{
	SHASH_DESC_ON_STACK(desc, NULL);

    desc->flags = 0;

    return desc->flags;
}
