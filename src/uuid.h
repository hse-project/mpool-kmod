/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_UUID_H
#define MPOOL_UUID_H

#define MPOOL_UUID_SIZE        16
#define MPOOL_UUID_STRING_LEN  36

#include <linux/kernel.h>
#include <linux/uuid.h>

#include "mpool_config.h"

struct mpool_uuid {
	unsigned char uuid[MPOOL_UUID_SIZE];
};

/* mpool_uuid uses the LE version in the kernel */
static inline void mpool_generate_uuid(struct mpool_uuid *uuid)
{
#if HAVE_GENERATE_RANDOM_GUID
	generate_random_guid(uuid->uuid);
#else
	uuid_le l_u;

	uuid_le_gen(&l_u);
	memcpy(uuid->uuid, l_u.b, MPOOL_UUID_SIZE);
#endif
}

static inline void mpool_uuid_copy(struct mpool_uuid *u_dst, const struct mpool_uuid *u_src)
{
	memcpy(u_dst->uuid, u_src->uuid, MPOOL_UUID_SIZE);
}

static inline int mpool_uuid_compare(const struct mpool_uuid *uuid1, const struct mpool_uuid *uuid2)
{
	return memcmp(uuid1, uuid2, MPOOL_UUID_SIZE);
}

static inline void mpool_uuid_clear(struct mpool_uuid *uuid)
{
	memset(uuid->uuid, 0, MPOOL_UUID_SIZE);
}

static inline int mpool_uuid_is_null(const struct mpool_uuid *uuid)
{
	const struct mpool_uuid zero = { };

	return !memcmp(&zero, uuid, sizeof(zero));
}

static inline void mpool_unparse_uuid(const struct mpool_uuid *uuid, char *dst)
{
	const unsigned char *u = uuid->uuid;

	snprintf(dst, MPOOL_UUID_STRING_LEN + 1,
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 u[0], u[1], u[2], u[3],
		 u[4], u[5], u[6], u[7],
		 u[8], u[9], u[10], u[11],
		 u[12], u[13], u[14], u[15]);
}

#endif /* MPOOL_UUID_H */
