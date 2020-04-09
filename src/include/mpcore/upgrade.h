/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/* DOC: Module info.
 *
 * Mpool core private header used used for mpool metadta upgrades.
 *
 */
#ifndef MPOOL_MPCORE_UPGRADE_PRIV_H
#define MPOOL_MPCORE_UPGRADE_PRIV_H

/*
 * Size of version converted to string.
 * 4*(5 bytes for a u16) + 3*(1 byte for the '.') + 1 byte for \0
 */
#define MAX_MDCCVERSTR 24

/**
 * upg_mdccver_latest() - return the latest mpool MDC content version
 *	understood by this binary.
 */
struct omf_mdccver *upg_mdccver_latest(void);

/**
 * upg_mdccver_latest2() - write in "mdccver" the latest mpool MDC content
 *      version understood by this binary.
 * @mdccver:
 */
void upg_mdccver_latest2(struct omf_mdccver *mdccver);

/**
 * upg_mdccver_latest_comment() - returns the comment on the latest mpool MDC
 *	content version understood by this binary.
 */
const char *upg_mdccver_latest_comment(void);

/**
 * upg_mdccver_comment() - returns the comment on the mpool MDC
 *	content version passed in via "mdccver".
 * @mdccver:
 */
const char *upg_mdccver_comment(struct omf_mdccver *mdccver);

/**
 * upg_mdccver2str() - convert a version into a string.
 * @mdcver: version to convert
 * @buf: buffer in which to place the conversion.
 * @sz: size of "buf" in bytes.
 *
 * Returns "buf"
 */
char *upg_mdccver2str(struct omf_mdccver *mdccver, char *buf, size_t sz);

/**
 * upg_ver_cmp() - compare two versions a and b
 * @a: a version
 * @op: compare operator (C syntax)
 *	can be "<", "<=", ">", ">=", "==".
 * @b: a version
 *
 * Return (a op b)
 */
bool upg_ver_cmp(struct omf_mdccver *a, char *op, struct omf_mdccver *b);

/**
 * upg_ver_cmp2() - compare two versions
 * @a: a version
 * @op: compare operator (C syntax)
 *	can be "<", "<=", ">", ">=", "==".
 * @major: major, minor, patch and dev compose the version "b" to compare
 * @minor: with "a".
 * @patch:
 * @dev:
 *
 * Return true (a op b)
 */
bool
upg_ver_cmp2(
	struct omf_mdccver *a,
	char		   *op,
	u16		    major,
	u16		    minor,
	u16		    patch,
	u16		    dev);

#endif
