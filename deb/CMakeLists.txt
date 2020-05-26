#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

message( STATUS "Configuring ${PROJECT_NAME}-${KREL} deb ..." )

set( CPACK_GENERATOR  "DEB" )

set( CPACK_DEBIAN_PACKAGE_LICENSE        "${CPACK_PACKAGE_LICENSE}" )
set( CPACK_DEBIAN_PACKAGE_RELEASE        "${BUILD_NUMBER}")
set( CPACK_DEBIAN_PACKAGE_MAINTAINER     "Unspecified" )
set( CPACK_DEBIAN_PACKAGE_DESCRIPTION    "${CPACK_PACKAGE_DESCRIPTION}" )

set( CPACK_DEBIAN_PACKAGE_RELOCATABLE    "ON" )
set( CPACK_DEBIAN_RELOCATION_PATHS       /usr /etc )

set( CCSD  "${CMAKE_CURRENT_SOURCE_DIR}" )

set( CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CCSD}/deb/preinst;${CCSD}/deb/postinst;${CCSD}/deb/prerm;${CCSD}/deb/postrm" )

set( CPACK_DEBIAN_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    ${DESTDIR}
    /lib
    /lib/modules
    /lib/modules/${KREL}
    /lib/modules/${KREL}/extra
)
