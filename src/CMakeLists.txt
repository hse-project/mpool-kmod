#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

message(STATUS "Configuring mpool in ${CMAKE_CURRENT_SOURCE_DIR}")

set(MPOOL_INCLUDE_DIRS
  ${MPOOL_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(MPCORE_SRC
    cmn.c
    ecio.c
    evc.c
    init.c
    mblock.c
    mclass.c
    merr.c
    mlog.c
    mp.c
    mpcore_params.c
    omf.c
    pd.c
    pd_bio_k.c
    pmd.c
    sb.c
    smap.c
    upgrade.c
)

MPOOL_KMOD(
    NAME mpool
    TARGET mpool-kmod
    SRCS
        ${MPCORE_SRC}
        mpctl.c
        mpctl_params.c
        mpctl_reap.c
        mdc.c

    INCLUDES
        ${MPOOL_INCLUDE_DIRS}
        ${CMAKE_BINARY_DIR}/stage/include
)
