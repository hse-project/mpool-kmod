#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

message( STATUS "Configuring ${PROJECT_NAME}-${KREL} rpm ..." )

set( CPACK_GENERATOR                "RPM" )
set( CPACK_RPM_FILE_NAME            "RPM-DEFAULT" )

set( CPACK_RPM_PACKAGE_LICENSE      "${CPACK_PACKAGE_LICENSE}" )
set( CPACK_RPM_PACKAGE_RELEASE      "${CPACK_PACKAGE_RELEASE}" )
set( CPACK_RPM_PACKAGE_DESCRIPTION  "${CPACK_PACKAGE_DESCRIPTION}" )
set( CPACK_RPM_PACKAGE_ARCHITECTURE "${BUILD_PKG_ARCH}" )
set( CPACK_RPM_PACKAGE_VENDOR       "${CPACK_PACKAGE_VENDOR}" )
set( CPACK_RPM_PACKAGE_VERSION      "${CPACK_PACKAGE_VERSION}" )
set( CPACK_RPM_PACKAGE_URL          "${PROJECT_HOMEPAGE_URL}" )

set( CPACK_RPM_PACKAGE_RELOCATABLE  "ON" )
set( CPACK_RPM_RELOCATION_PATHS     /usr /etc )

set( CPACK_RPM_PACKAGE_REQUIRES "kernel-uname-r = ${KREL}" )

set( CPACK_RPM_PRE_INSTALL_SCRIPT_FILE     "${SCRIPTS_DIR}/rpm-pre-install.sh" )
set( CPACK_RPM_POST_INSTALL_SCRIPT_FILE    "${SCRIPTS_DIR}/rpm-post-install.sh" )
set( CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE   "${SCRIPTS_DIR}/rpm-pre-uninstall.sh" )
set( CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE  "${SCRIPTS_DIR}/rpm-post-uninstall.sh" )

set( CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    /lib
    /lib/modules
    /lib/modules/${KREL}
    /lib/modules/${KREL}/extra
)

