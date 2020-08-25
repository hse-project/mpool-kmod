// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>

#include "merr.h"

DEFINE_MERR(merr_bug1, "mpool_merr_bug1k");
DEFINE_MERR(merr_bug2, "mpool_merr_bug2k");
DEFINE_MERR(merr_bug3, "mpool_merr_bug3k");
DEFINE_MERR(merr_base, "mpool_merr_bug0k");

static const char *merr_file(merr_t err)
{
	s32 off;

	if (err == 0 || err == -1 || (err & MERR_RSVD_MASK))
		return NULL;

	off = (s64)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;

	/*
	 * Rough guess, the offset shouldn't be larger than the number
	 * of .c files in the module.
	 * TODO: Better to check the bounds of the "mpool_merr" segment, but how?
	 */
	if (off < -32 || off > 32)
		return merr_bug2;

	return merr_base + (off * MERR_ALIGN);
}

merr_t merr_to_user(merr_t err, char __user *ubuf)
{
	const char *file;

	s64 len = MERR_BASE_SZ / 2;
	s64 off;
	int rc;

	if (err == 0 || !ubuf)
		return (err & ~MERR_FILE_MASK);

	if (!IS_ALIGNED((ulong)ubuf, MERR_ALIGN)) {
		WARN_ONCE(1, "ubuf misaligned: err %lx, ubuf %p", (ulong)err, ubuf);
		return (err & ~MERR_FILE_MASK);
	}

	file = merr_file(err);
	if (!file)
		file = merr_bug3;

	off = (s64)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;
	off *= MERR_ALIGN;

	if (off < -len || off > len) {
		WARN_ONCE(1, "%s: ubuf bounds: err %lx, ubuf %p, off %ld len %ld, file %s",
			  __func__, (ulong)err, ubuf, (long)off, (long)len, file);
		return (err & ~MERR_FILE_MASK);
	}

	rc = copy_to_user(ubuf + off + len, file, strlen(file) + 1);
	if (rc) {
		WARN_ONCE(1, "%s: ubuf copyout: err %lx, ubuf %p, off %ld, len %ld, file %s",
			  __func__, (ulong)err, ubuf, (long)off, (long)len, file);
		return (err & ~MERR_FILE_MASK);
	}

	err &= ~MERR_FILE_MASK;
	err |= ((u64)((off + len) / MERR_ALIGN) << MERR_FILE_SHIFT);

	return err;
}

merr_t merr_pack(int errnum, const char *file, int line)
{
	merr_t  err = 0;
	s64     off;

	if (errnum == 0)
		return 0;

	if (errnum < 0)
		errnum = -errnum;

	if (!file || !IS_ALIGNED((ulong)file, MERR_ALIGN))
		file = merr_bug1;

	off = (file - merr_base) / MERR_ALIGN;

	/* Check to see if off will fit into MERR_FILE_MASK bits.
	 */
	if (((s64)((u64)off << MERR_FILE_SHIFT) >> MERR_FILE_SHIFT) == off)
		err = (u64)off << MERR_FILE_SHIFT;

	err |= ((u64)line << MERR_LINE_SHIFT) & MERR_LINE_MASK;
	err |= errnum & MERR_ERRNO_MASK;

	return err;
}

static char *merr_strerror(merr_t err, char *buf, size_t bufsz)
{
	int errnum = merr_errno(err);
	const char *fmt;

	fmt = (errnum == EBUG) ? "mpool software bug" : "errno %d";

	snprintf(buf, bufsz, fmt, errnum);

	return buf;
}

char *merr_strinfo(merr_t err, char *buf, size_t bufsz)
{
	int n = 0;

	if (!err) {
		strlcpy(buf, "Success", bufsz);
		return buf;
	}

	if (merr_file(err))
		n = snprintf(buf, bufsz, "%s:%d: ", merr_file(err), merr_lineno(err));

	if (n >= 0 && n < bufsz)
		merr_strerror(err, buf + n, bufsz - n);

	return buf;
}
