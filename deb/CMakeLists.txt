#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

message( STATUS "Configuring ${PROJECT_NAME}-${KREL} deb ..." )

set( CPACK_GENERATOR                   "DEB" )
set( CPACK_DEB_COMPONENT_INSTALL       "ON" )

set( CPACK_DEBIAN_PACKAGE_LICENSE      "${CPACK_PACKAGE_LICENSE}" )
set( CPACK_DEBIAN_PACKAGE_GROUP        "Unspecified" )
set( CPACK_DEBIAN_PACKAGE_RELEASE      "${BUILD_NUMBER}")
set( CPACK_DEBIAN_PACKAGE_MAINTAINER   "gandalf" )
set( CPACK_DEBIAN_PACKAGE_DESCRIPTION  "${CPACK_PACKAGE_DESCRIPTION}" )

set( CPACK_DEBIAN_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${MPOOL_TAG}${BUILD_NUMBER}.${KARCH}.deb" )

set( CPACK_DEBIAN_PACKAGE_RELOCATABLE  "ON" )
set( CPACK_DEBIAN_RELOCATION_PATHS     /usr /etc )

# We don't want to claim ownership of these directories, lest there be
# conflicts.
#
set( CPACK_DEBIAN_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
    ${DESTDIR}
    /lib
    /lib/modules
    /lib/modules/${KREL}
    /lib/modules/${KREL}/extra
)

set( CPACK_COMPONENTS_ALL runtime )
