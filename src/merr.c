// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>

#include <mpcore/merr.h>

static char merr_bug1[] _merr_attributes = "merr_bug1k";
static char merr_bug2[] _merr_attributes = "merr_bug2k";
static char merr_bug3[] _merr_attributes = "merr_bug3k";
static char merr_base[] _merr_attributes = "merr_bug0k";

merr_t merr_to_user(merr_t err, char __user *ubuf)
{
	s64 len = MERR_BASE_SZ / 2;
	s64 off;
	const char *file;
	int rc;

	if (err == 0 || !ubuf)
		return (err & ~MERR_FILE_MASK);

	if (!IS_ALIGNED((ulong)ubuf, MERR_ALIGN)) {
		WARN_ONCE(1, "ubuf misaligned: err %lx, ubuf %lx",
			  (ulong)err, (ulong)ubuf);
		return (err & ~MERR_FILE_MASK);
	}

	file = merr_file(err);
	if (!file)
		file = merr_bug3;

	off = (s64)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;
	off *= MERR_ALIGN;

	if (off < -len || off > len + MERR_ALIGN) {
		WARN_ONCE(1, "ubuf bounds: err %lx, ubuf %lx, off %ld len %ld, file %s",
			  (ulong)err, (ulong)ubuf, (long)off, (long)len, file);
		return (err & ~MERR_FILE_MASK);
	}

	rc = copy_to_user(ubuf + off + len, file, strlen(file) + 1);
	if (rc) {
		WARN_ONCE(1, "ubuf copyout: err %lx, ubuf %lx, off %ld, len %ld, file %s",
			  (ulong)err, (ulong)ubuf, (long)off, (long)len, file);
		return (err & ~MERR_FILE_MASK);
	}

	err &= ~MERR_FILE_MASK;
	err |= ((u64)((off + len) / MERR_ALIGN) << MERR_FILE_SHIFT);

	return err;
}

merr_t merr_pack(int errnum, const char *file, int line)
{
	s64 len = MERR_BASE_SZ / 2;
	merr_t err = 0;
	s64 off;

	if (errnum == 0)
		return 0;

	if (errnum < 0)
		errnum = -errnum;

	if (!file || !IS_ALIGNED((ulong)file, MERR_ALIGN))
		file = merr_bug1;

	off = (file - merr_base) / MERR_ALIGN;

	if (((s64)((u64)off << MERR_FILE_SHIFT) >> MERR_FILE_SHIFT) == off)
		err = (u64)off << MERR_FILE_SHIFT;

	err |= ((u64)line << MERR_LINE_SHIFT) & MERR_LINE_MASK;
	err |= errnum & MERR_ERRNO_MASK;

	if (off < -len || off > len + MERR_ALIGN) {
		WARN_ONCE(1, "%s: %d line %d, off %lx/%ld, err %lx %s\n",
			  __func__, errnum, line, (ulong)off,
			  (long)off, (ulong)err, file);
	}

	return err;
}

const char *merr_file(merr_t err)
{
	const char *file;
	size_t len;
	int slash;
	s32 off;

	if (err == 0 || err == -1)
		return NULL;

	off = (s64)(err & MERR_FILE_MASK) >> MERR_FILE_SHIFT;
	off *= MERR_ALIGN;

	file = merr_base + off;
	len = strnlen(file, 1024);
	file += len;

	for (slash = 0; len-- > 0; --file) {
		if (*file && !isprint(*file))
			return merr_bug2;

		if (file[-1] == '/' && ++slash >= 2)
			break;
	}

	return file;
}

char *merr_strerror(merr_t err, char *buf, size_t bufsz)
{
	int errnum = merr_errno(err);
	const char *fmt = NULL;

	if (errnum == EBUG)
		fmt = "Software bug";

	snprintf(buf, bufsz, fmt ?: "errno %d", errnum);

	return buf;
}

char *merr_strinfo(merr_t err, char *buf, size_t bufsz)
{
	int off = 0;

	if (err) {
		const char *file = merr_file(err);

		if (file)
			off = snprintf(buf, bufsz, "%s:%d: ",
				       file, merr_lineno(err));
		if (off >= 0 && off < bufsz)
			merr_strerror(err, buf + off, bufsz - off);
	} else {
		snprintf(buf, bufsz, "Success");
	}

	return buf;
}
