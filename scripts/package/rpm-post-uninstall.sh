# rpm-post-uninstall.sh

#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

# rpm will execute the contents of this file with /bin/sh
# https://fedoraproject.org/wiki/Packaging:Scriptlets

if [[ $1 -eq 0 ]]; then
    # this is a real uninstall, NOT an upgrade
    # remove symlink
    rm -f /lib/modules/`uname -r`/mpool
    depmod -a

    # reload udev rules
    udevadm control --reload-rules
fi

exit 0
