# rpm-post-install.sh

#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

# rpm will execute the contents of this file with /bin/sh
# https://fedoraproject.org/wiki/Packaging:Scriptlets

depmod -a

# load kernel modules
modprobe mpool || echo "Failed to load mpool module, run modprobe/insmod manually"

# additional work if we did a "force install" via /tmp/mpool-force-install
if [[ -f /tmp/mpool-needs-reboot ]]; then
    echo
    echo "*** WARNING - MUST REBOOT ***"
    echo
    echo "The package install is complete, but the kernel module from an old"
    echo "version of mpool could not be unloaded."
    echo
    echo "*** WARNING - MUST REBOOT ***"
    echo

    rm -vf /tmp/mpool-force-install
    rm -f /tmp/mpool-needs-reboot
fi

exit 0
