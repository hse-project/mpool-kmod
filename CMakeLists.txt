#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

cmake_minimum_required( VERSION 3.6 )

project( kmod-mpool NONE )

message( STATUS "Configuring ${PROJECT_NAME}-${KREL} common ..." )

set( PKG_DIR                         "${CMAKE_CURRENT_SOURCE_DIR}/${BUILD_PKG}" )
set( CPACK_PACKAGING_INSTALL_PREFIX  "${DESTDIR}" )

INSTALL(
    FILES "${PROJECT_SOURCE_DIR}/src/mpool.ko"
    DESTINATION lib/modules/${KREL}/extra
    COMPONENT runtime
    )

# Package options
#
set( CPACK_PACKAGE_NAME           "${PROJECT_NAME}-${KREL}" )
set( CPACK_PACKAGE_LICENSE        "GPLv2 and MIT" )
set( CPACK_PACKAGE_HOMEPAGE_URL   "https://github.com/hse-project/mpool-kmod" )

set( CPACK_PACKAGE_VERSION_MAJOR  "${MPOOL_VERSION_MAJOR}" )
set( CPACK_PACKAGE_VERSION_MINOR  "${MPOOL_VERSION_MINOR}" )
set( CPACK_PACKAGE_VERSION_PATCH  "${MPOOL_VERSION_PATCH}" )

# Explicitly set CPACK_PACKAGE_VERSION first, otherwise CMake may generate
# nonsense version strings within generated spec files

set( CPACK_PACKAGE_VERSION
    "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}" )

# If it's a managed build (e.g, Jenkins) or a dirty git clone
# then include the build number and git describe tag in the
# package file name.  Otherwise, the file name will contain
# only the simple version and no build type/number.
#
if( BUILD_NUMBER GREATER 0 OR "${MPOOL_TAG}" MATCHES "dirty$" )
    set( BUILD_STYPE "-${BUILD_STYPE}${BUILD_NUMBER}" )
else()
    set( MPOOL_TAG "${CPACK_PACKAGE_VERSION}" )
    set( BUILD_STYPE  "" )
endif()

set( CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Object Storage Media Pool (mpool) ${BUILD_TYPE} kernel module" )

set( CPACK_PACKAGE_DESCRIPTION
    "${CPACK_PACKAGE_DESCRIPTION_SUMMARY} ${MPOOL_TAG} for kernel ${KREL}" )

set( CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${MPOOL_TAG}${BUILD_STYPE}.${KARCH}" )

include( ${BUILD_PKG}/CMakeLists.txt )

include( CPack )
