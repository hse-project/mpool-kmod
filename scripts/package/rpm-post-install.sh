# rpm-post-install.sh

#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

# rpm will execute the contents of this file with /bin/sh
# https://fedoraproject.org/wiki/Packaging:Scriptlets

# create a symlink under the kernel's module directory
rm -f /lib/modules/`uname -r`/mpool
ln -s /usr/lib/mpool/modules/ /lib/modules/`uname -r`/mpool

depmod -a

# load kernel modules
modprobe mpool

# sysctl config
echo
echo "*** NOTE ***"
echo
echo "This package configures the vm.max_map_count sysctl parameter."
echo "This is required for normal operation of mpool."
echo
sysctl -p /usr/lib/sysctl.d/90-mpool.conf

# reload udev rules
udevadm control --reload-rules

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
