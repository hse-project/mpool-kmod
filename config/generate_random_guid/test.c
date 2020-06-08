// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../test.h"
#include <linux/uuid.h>

int
test(unsigned char uuid[16])
{
	generate_random_guid(uuid);

    return 0;
}
