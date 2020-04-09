// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>

#include <mpcore/merr.h>

static char merr_bug1[] _merr_attributes = "mpool_merr_bug1k";
static char merr_bug2[] _merr_attributes = "mpool_merr_bug2k";
static char merr_bug3[] _merr_attributes = "mpool_merr_bug3k";
static char merr_base[] _merr_attributes = "mpool_merr_bug0k";

merr_t merr_to_user(merr_t err, char __user *ubuf)
{
	const char *file;

	s64 len = MERR_BASE_SZ / 2;
	s64 off;
	int rc;

	if (err == 0 || !ubuf)
		return (err & ~MERR_FILE_MASK);

	if (!IS_ALIGNED((ulong)ubuf, MERR_ALIGN)) {
		WARN_ONCE(1, "ubuf misaligned: err %lx, ubuf %px",
			  (ulong)err, ubuf);
		return (err & ~MERR_FILE_MASK);
	}

	file = merr_file(err);
	if (!file)
		file = merr_bug3;

	off = (s64)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;
	off *= MERR_ALIGN;

	if (off < -len || off > len) {
		WARN_ONCE(1, "%s: ubuf bounds: err %lx, ubuf %px, off %ld len %ld, file %s",
			  __func__, (ulong)err, ubuf, (long)off, (long)len, file);
		return (err & ~MERR_FILE_MASK);
	}

	rc = copy_to_user(ubuf + off + len, file, strlen(file) + 1);
	if (rc) {
		WARN_ONCE(1, "%s: ubuf copyout: err %lx, ubuf %lx, off %ld, len %ld, file %s",
			  __func__, (ulong)err, (ulong)ubuf, (long)off, (long)len, file);
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

const char *merr_file(merr_t err)
{
	s32 off;

	if (err == 0 || err == -1 || (err & MERR_RSVD_MASK))
		return NULL;

	off = (s64)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;

	/* Rough guess, the offset shouldn't be larger than the number
	 * of .c files in the module.  Better to check the bounds of
	 * the "mpool_merr" segment, but how?
	 */
	if (off < -32 || off > 32)
		return merr_bug2;

	return merr_base + (off * MERR_ALIGN);
}

char *merr_strerror(merr_t err, char *buf, size_t bufsz)
{
	int errnum = merr_errno(err);
	const char *fmt = NULL;

	if (errnum == EBUG)
		fmt = "mpool software bug";

	snprintf(buf, bufsz, fmt ?: "errno %d", errnum);

	return buf;
}

char *merr_strinfo(merr_t err, char *buf, size_t bufsz)
{
	int n;

	if (!err) {
		strlcpy(buf, "Success", bufsz);
		return buf;
	}

	n = snprintf(buf, bufsz, "%s:%d: ",
		     merr_file(err) ?: "?", merr_lineno(err));

	if (n >= 0 && n < bufsz)
		merr_strerror(err, buf + n, bufsz - n);

	return buf;
}
