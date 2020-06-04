#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

message( STATUS "Configuring ${PROJECT_NAME}-${KREL} deb ..." )

set( CPACK_GENERATOR                   "DEB" )

set( CPACK_DEBIAN_PACKAGE_LICENSE      "${CPACK_PACKAGE_LICENSE}" )
set( CPACK_DEBIAN_PACKAGE_RELEASE      "${BUILD_PKG_REL}${BUILD_RTYPE}${BUILD_PKG_DIST}" )
set( CPACK_DEBIAN_PACKAGE_MAINTAINER   "Micron Technology, Inc." )
set( CPACK_DEBIAN_PACKAGE_DESCRIPTION  "${CPACK_PACKAGE_DESCRIPTION}" )
set( CPACK_DEBIAN_PACKAGE_SECTION      "kernel" )
set( CPACK_DEBIAN_PACKAGE_VERSION      "${PROJECT_VERSION}${BUILD_PKG_VQUAL}" )
set( CPACK_DEBIAN_FILE_NAME            "DEB-DEFAULT" )

set( CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${SCRIPTS_DIR}/preinst;${SCRIPTS_DIR}/postinst;${SCRIPTS_DIR}/prerm;${SCRIPTS_DIR}/postrm" )
