#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

project( kmod-mpool )
cmake_minimum_required(VERSION 3.6)

message(STATUS "Configuring mpool kmod RPM packaging...")

set( CMAKE_INSTALL_PREFIX /usr )

INSTALL(
    FILES "${PROJECT_SOURCE_DIR}/../src/mpool.ko"
    DESTINATION lib/modules/${KREL}/extra
    COMPONENT runtime
    )

# Package options
#
set( CPACK_PACKAGE_NAME           "kmod-mpool-${KREL}" )
set( CPACK_PACKAGE_VERSION_MAJOR  "${MPOOL_VERSION_MAJOR}" )
set( CPACK_PACKAGE_VERSION_MINOR  "${MPOOL_VERSION_MINOR}" )
set( CPACK_PACKAGE_VERSION_PATCH  "${MPOOL_VERSION_PATCH}" )

# Explicitly set CPACK_PACKAGE_VERSION first, otherwise CMake may generate
# nonsense version strings within generated spec files

set( CPACK_PACKAGE_VERSION
    "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}" )

message(STATUS "Configuring package ${CPACK_PACKAGE_NAME}" )
message(STATUS "Configuring version ${CPACK_PACKAGE_VERSION}")


set( CPACK_GENERATOR                "RPM" )
set( CPACK_RPM_PACKAGE_URL          "https://github.com/hse-project/mpool-kmod" )
set( CPACK_RPM_PACKAGE_LICENSE      "GPLv2 and MIT" )
set( CPACK_RPM_PACKAGE_GROUP        "Unspecified" )
set( CPACK_RPM_PACKAGE_VENDOR       "Unspecified" )
set( CPACK_RPM_PACKAGE_VERSION      "${CPACK_PACKAGE_VERSION}" )
set( CPACK_RPM_PACKAGE_RELEASE      "${BUILD_NUMBER}")
set( CPACK_RPM_COMPONENT_INSTALL    "ON" )
set( CPACK_RPM_PACKAGE_RELOCATABLE  "ON" )
set( CPACK_RPM_RELOCATION_PATHS     /usr /etc )


# If it's a managed build (e.g, Jenkins) or a dirty git clone
# then include the build number and git describe tag in the
# package file name.  Otherwise, the file name will contain
# only the simple version and no build type/number.
#
if( BUILD_NUMBER GREATER 0 OR "${MPOOL_TAG}" MATCHES "dirty$" )
    set( BUILD_NUMBER "-${BUILD_STYPE}${BUILD_NUMBER}" )
else()
    set( MPOOL_TAG "${CPACK_PACKAGE_VERSION}" )
    set( BUILD_NUMBER  "" )
endif()


# We don't want to claim ownership of these directories, lest there be
# conflicts.
#
set( CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
  /usr/lib
  /usr/lib/modules
  /usr/lib/modules/${KREL}
  /usr/lib/modules/${KREL}/extra
)

# Setting this keeps CMake 3.7+ from generating nonsense filenames
set( CPACK_RPM_FILE_NAME "RPM-DEFAULT" )

# How to generate the RPM spec file template for your version of CMake, so it
# can be passed to CPACK_RPM_RUNTIME_USER_BINARY_SPECFILE:
#
#   cd builds/release.fc25  # (or whatever build/dist you're working on)
#   cpack -D CPACK_RPM_GENERATE_USER_BINARY_SPECFILE_TEMPLATE=1 -G RPM
#
# https://cmake.org/cmake/help/latest/cpack_gen/rpm.html#variable:CPACK_RPM_GENERATE_USER_BINARY_SPECFILE_TEMPLATE
#

SET( CPACK_COMPONENTS_ALL runtime )

# Runtime
#
set( CPACK_RPM_RUNTIME_PACKAGE_NAME  "${CPACK_PACKAGE_NAME}" )

set( CPACK_RPM_RUNTIME_PACKAGE_SUMMARY
    "Object Storage Media Pool (mpool) ${BUILD_TYPE} kernel module" )

set(CPACK_RPM_RUNTIME_PACKAGE_DESCRIPTION
    "${CPACK_RPM_RUNTIME_PACKAGE_SUMMARY} ${MPOOL_TAG} for kernel ${KREL}")

set( CPACK_RPM_RUNTIME_FILE_NAME
    "${CPACK_RPM_RUNTIME_PACKAGE_NAME}-${MPOOL_TAG}${BUILD_NUMBER}.${KARCH}.rpm" )

message(STATUS "Configuring RPM file ${CPACK_RPM_RUNTIME_FILE_NAME}")

set( CPACK_RPM_RUNTIME_PACKAGE_RELEASE             "${CPACK_RPM_PACKAGE_RELEASE}")
#set( CPACK_RPM_RUNTIME_USER_BINARY_SPECFILE        "${PROJECT_SOURCE_DIR}/mpool.spec.in")
set( CPACK_RPM_RUNTIME_PRE_INSTALL_SCRIPT_FILE     "${PROJECT_SOURCE_DIR}/rpm-pre-install.sh" )
set( CPACK_RPM_RUNTIME_POST_INSTALL_SCRIPT_FILE    "${PROJECT_SOURCE_DIR}/rpm-post-install.sh" )
set( CPACK_RPM_RUNTIME_PRE_UNINSTALL_SCRIPT_FILE   "${PROJECT_SOURCE_DIR}/rpm-pre-uninstall.sh" )
set( CPACK_RPM_RUNTIME_POST_UNINSTALL_SCRIPT_FILE  "${PROJECT_SOURCE_DIR}/rpm-post-uninstall.sh" )

set( CPACK_RPM_RUNTIME_PACKAGE_REQUIRES "sos >= 3.2" )

include( CPack )
