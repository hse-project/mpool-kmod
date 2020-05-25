#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

message( STATUS "Configuring ${PROJECT_NAME}-${KREL} rpm ..." )

set( CPACK_GENERATOR "RPM" )
set( CPACK_RPM_COMPONENT_INSTALL    "ON" )

set( CPACK_RPM_PACKAGE_LICENSE      "${CPACK_PACKAGE_LICENSE}" )
set( CPACK_RPM_PACKAGE_GROUP        "Unspecified" )
set( CPACK_RPM_PACKAGE_RELEASE      "${BUILD_NUMBER}")
set( CPACK_RPM_PACKAGE_DESCRIPTION  "${CPACK_PACKAGE_DESCRIPTION}" )

set( CPACK_RPM_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${MPOOL_TAG}${BUILD_NUMBER}.${KARCH}.rpm" )

set( CPACK_RPM_PACKAGE_RELOCATABLE  "ON" )
set( CPACK_RPM_RELOCATION_PATHS     /usr /etc )

# We don't want to claim ownership of these directories, lest there be
# conflicts.
#
set( CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    ${DESTDIR}
    /lib
    /lib/modules
    /lib/modules/${KREL}
    /lib/modules/${KREL}/extra
)

# How to generate the RPM spec file template for your version of CMake, so it
# can be passed to CPACK_RPM_RUNTIME_USER_BINARY_SPECFILE:
#
#   cd builds/release.fc25  # (or whatever build/dist you're working on)
#   cpack -D CPACK_RPM_GENERATE_USER_BINARY_SPECFILE_TEMPLATE=1 -G RPM
#
# https://cmake.org/cmake/help/latest/cpack_gen/rpm.html#variable:CPACK_RPM_GENERATE_USER_BINARY_SPECFILE_TEMPLATE
#

SET( CPACK_COMPONENTS_ALL runtime )

set( CPACK_RPM_RUNTIME_PACKAGE_NAME         "${CPACK_PACKAGE_NAME}" )
set( CPACK_RPM_RUNTIME_FILE_NAME            "${CPACK_RPM_PACKAGE_FILE_NAME}" )
set( CPACK_RPM_RUNTIME_PACKAGE_RELEASE      "${CPACK_RPM_PACKAGE_RELEASE}" )
set( CPACK_RPM_RUNTIME_PACKAGE_DESCRIPTION  "${CPACK_RPM_PACKAGE_DESCRIPTON}" )

set( CPACK_RPM_RUNTIME_USER_BINARY_SPECFILE        "${PROJECT_SOURCE_DIR}/rpm/mpool.spec.in")
set( CPACK_RPM_RUNTIME_PRE_INSTALL_SCRIPT_FILE     "${PROJECT_SOURCE_DIR}/rpm/rpm-pre-install.sh" )
set( CPACK_RPM_RUNTIME_POST_INSTALL_SCRIPT_FILE    "${PROJECT_SOURCE_DIR}/rpm/rpm-post-install.sh" )
set( CPACK_RPM_RUNTIME_PRE_UNINSTALL_SCRIPT_FILE   "${PROJECT_SOURCE_DIR}/rpm/rpm-pre-uninstall.sh" )
set( CPACK_RPM_RUNTIME_POST_UNINSTALL_SCRIPT_FILE  "${PROJECT_SOURCE_DIR}/rpm/rpm-post-uninstall.sh" )

set( CPACK_RPM_RUNTIME_PACKAGE_REQUIRES "sos >= 3.2" )
