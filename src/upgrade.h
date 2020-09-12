/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Defines structures for upgrading MPOOL meta data
 */

#ifndef MPOOL_UPGRADE_H
#define MPOOL_UPGRADE_H

#include "omf_if.h"

/*
 * Size of version converted to string.
 * 4 * (5 bytes for a u16) + 3 * (1 byte for the '.') + 1 byte for \0
 */
#define MAX_MDCVERSTR          24

/**
 * Naming conventions:
 *
 * omf structures:
 * ---------------
 * The old structure names end with _omf_v<version number>.
 * For example: layout_descriptor_omf_v1
 * The current/latest structure name end simply with _omf.
 * For example: layout_descriptor_omf
 *
 * Conversion functions:
 * ---------------------
 * They are named like:
 * omf_convert_<blabla>_<maj>_<min>_<patch>_<dev>to<maj>_<min>_<patch>_<dev>()
 *
 * For example: omf_convert_sb_1_0_0_0to1_0_0_1()
 *
 * They are not named like omf_convert_<blabla>_v1tov2() because sometimes the
 * input and output structures are exactly the same and the conversion is
 * related to some subtle interpretation of structure filed[s] content.
 *
 * Unpack functions:
 * -----------------
 * They are named like:
 * omf_<blabla>_unpack_letoh_v<version number>()
 * <version number> being the version of the structure.
 *
 * For example: omf_layout_unpack_letoh_v1()
 * Note that for the latest/current version of the structure we cannot
 * name the unpack function omf_<blabla>_unpack_letoh() because that would
 * introduce a name conflict with the top unpack function that calls
 * omf_unpack_letoh_and_convert()
 *
 * For example for layout we have:
 * omf_layout_unpack_letoh_v1() unpacks layout_descriptor_omf_v1
 * omf_layout_unpack_letoh_v2() unpacks layout_descriptor_omf
 * omf_layout_unpack_letoh() calls one of the two above.
 */

/**
 * struct upgrade_history -
 *
 * Every time we update a nested structure in superblock or MDC, we need to
 * save the following information about this update, such that we can keep the
 * update history of this structure
 *
 * @uh_size:    size of the current version in-memory structure
 * @uh_unpack:  unpacking function from on-media format to in-memory format
 * @uh_conv:    conversion function from previous version to current version,
 *              set to NULL for the first version
 * @uh_sbver:   corresponding superblock version since which the change has
 *              been introduced. If this structure is not used by superblock
 *              set uh_sbver =  OMF_SB_DESC_UNDEF.
 * @uh_mdcver: corresponding mdc ver since which the change has been
 *              introduced
 */
struct upgrade_history {
	size_t                      uh_size;
	int (*uh_unpack)(void *out, const char *inbuf);
	int (*uh_conv)(const void *pre, void *cur);
	enum sb_descriptor_ver_omf  uh_sbver;
	struct omf_mdcver          uh_mdcver;
};

/**
 * omfu_mdcver_cur() -
 *
 * Returns the latest mpool MDC content version understood by this binary.
 */
struct omf_mdcver *omfu_mdcver_cur(void);

/**
 * omfu_mdcver_comment() -
 * @mdcver:
 *
 * Returns the comment on the mpool MDC content version passed in via "mdcver".
 */
const char *omfu_mdcver_comment(struct omf_mdcver *mdcver);

/**
 * omfu_mdcver_to_str() - convert a version into a string.
 *
 * @mdcver: version to convert
 * @buf:    buffer in which to place the conversion.
 * @sz:     size of "buf" in bytes.
 *
 * Returns "buf"
 */
char *omfu_mdcver_to_str(struct omf_mdcver *mdcver, char *buf, size_t sz);

/**
 * omfu_mdcver_cmp() - compare two versions a and b
 * @a:  first version
 * @op: compare operator (C syntax), can be "<", "<=", ">", ">=", "==".
 * @b:  second version
 *
 * Return (a op b)
 */
bool omfu_mdcver_cmp(struct omf_mdcver *a, char *op, struct omf_mdcver *b);

/**
 * omfu_mdcver_cmp2() - compare two versions
 * @a:     first version
 * @op:    compare operator (C syntax), can be "<", "<=", ">", ">=", "==".
 * @major: major, minor, patch and dev which composes the second version
 * @minor:
 * @patch:
 * @dev:
 *
 * Return true (a op b)
 */
bool omfu_mdcver_cmp2(struct omf_mdcver *a, char *op, u16 major, u16 minor, u16 patch, u16 dev);

#endif /* MPOOL_UPGRADE_H */
