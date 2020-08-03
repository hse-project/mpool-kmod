#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

cmake_minimum_required( VERSION 3.6 )

project( kmod-mpool C )

set( PROJECT_VERSION            "${BUILD_PKG_VERSION}" )
set( PROJECT_HOMEPAGE_URL       "https://github.com/hse-project/mpool-kmod" )

set( CMAKE_PROJECT_VERSION      "${PROJECT_VERSION}" )
set( CMAKE_PROJECT_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}" )

message( STATUS "Configuring ${PROJECT_NAME}-${KREL} common ..." )

set( SCRIPTS_DIR  "${PROJECT_SOURCE_DIR}/scripts/${BUILD_PKG_TYPE}" )

set( CPACK_PACKAGING_INSTALL_PREFIX  "${DESTDIR}" )

INSTALL(
    FILES "${PROJECT_SOURCE_DIR}/src/mpool.ko"
    DESTINATION lib/modules/${KREL}/extra
    COMPONENT runtime
    )

# Common package options
#
set( CPACK_PACKAGE_NAME         "${PROJECT_NAME}-${KREL}" )
set( CPACK_PACKAGE_LICENSE      "GPLv2 and MIT" )
set( CPACK_PACKAGE_VENDOR       "${BUILD_PKG_VENDOR}" )
set( CPACK_PACKAGE_VERSION      "${PROJECT_VERSION}${BUILD_PKG_VQUAL}" )

set( CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Object Storage Media Pool (mpool) ${BUILD_TYPE} kernel module" )

set( CPACK_PACKAGE_DESCRIPTION
    "${CPACK_PACKAGE_DESCRIPTION_SUMMARY} ${MPOOL_TAG} for kernel ${KREL}" )

if( "${BUILD_NUMBER}" )
    set( BUILD_RTYPE "${BUILD_STYPE}${BUILD_NUMBER}" )
else()
    set( BUILD_RTYPE "" )
endif()

set( CPACK_PACKAGE_RELEASE      "${BUILD_PKG_REL}${BUILD_RTYPE}${BUILD_PKG_DIST}" )

include( ${SCRIPTS_DIR}/CMakeLists.txt )
include( CPack )
