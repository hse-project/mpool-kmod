/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Defines structures for upgrading MPOOL meta data
 */

#ifndef MPOOL_UPGRADE_PRIV_H
#define MPOOL_UPGRADE_PRIV_H

#include "omf.h"
#include "omf_if.h"

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
 * For example: omf_convert_sb_1_0_0_0to1_0_0_1()
 * They are not named like omf_convert_<blabla>_v1tov2() because sometimes the
 * input and output structures are exactly the same and the conversion is
 * related to some subtle interpretation of structure filed[s] content.
 *
 * Unpack functions:
 * -----------------
 * They are named like:
 * omf_<blabla>_unpack_letoh_v<version number>()
 * <version number> being the version of the structure.
 * For example: omf_layout_unpack_letoh_v1()
 * Note that for the latest/current version of the structure we cannot
 * name the unpack function omf_<blabla>_unpack_letoh() because that would
 * introduce a name conflict with the top unpack function that calls
 * omf_unpack_letoh_and_convert()
 * For example for layout we have:
 * omf_layout_unpack_letoh_v1() unpacks layout_descriptor_omf_v1
 * omf_layout_unpack_letoh_v2() unpacks layout_descriptor_omf
 * omf_layout_unpack_letoh() calls one of the two above.
 */

/**
 * struct upg_history:
 *      Every time we update a nested structure in superblock or MDC,
 *      we need to save the following information about this update,
 *      such that we can keep the update history of this structure
 * @upgh_size: size of the current version in-memory structure
 * @upgh_unpack: unpacking function from on-media format to in-memory format
 * @upgh_conv: conversion function from previous version to current version,
 *              set to NULL for the first version
 * @upgh_sbver: corresponding superblock version since which the change has
 *              been introduced. If this structure is not used by superblock
 *              set upgh_sbver =  OMF_SB_DESC_UNDEF.
 * @upgh_mdccver: corresponding mdc ver since which the change has been
 *              introduced
 */
struct upg_history {
	size_t                      upgh_size;
	merr_t (*upgh_unpack)(void *out, const char *inbuf);
	merr_t (*upgh_conv)(const void *pre, void *cur);
	enum sb_descriptor_ver_omf  upgh_sbver;
	struct omf_mdccver          upgh_mdccver;
};

#endif /* MPOOL_UPGRADE_PRIV_H */
