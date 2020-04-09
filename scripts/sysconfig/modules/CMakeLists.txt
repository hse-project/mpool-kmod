#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

if( "${MPOOL_DISTRO}" STREQUAL "el6" )
    install(
        FILES ${CMAKE_CURRENT_SOURCE_DIR}/mpool.modules
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        DESTINATION /etc/sysconfig/modules
        COMPONENT runtime
    )
endif()
