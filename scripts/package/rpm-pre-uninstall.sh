# rpm-pre-uninstall.sh

#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

# rpm will execute the contents of this file with /bin/sh
# https://fedoraproject.org/wiki/Packaging:Scriptlets

if [[ $1 -eq 0 ]]; then
    # this is a real uninstall, NOT an upgrade

    if [[ -d /dev/mpool ]]; then
        echo "Deactivating mpools..."
        echo

	mpool scan --deactivate -v
    fi

    # remove existing module
    if modinfo mpool >/dev/null 2>&1; then
        modprobe -r mpool
        if [[ $? -ne 0 ]]; then
            echo "Failed to remove the mpool kernel module."
            echo "You must manually remove it after the uninstall is complete."
        fi
    fi
fi

exit 0
