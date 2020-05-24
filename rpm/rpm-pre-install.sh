# rpm-pre-install.sh

#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

# rpm will execute the contents of this file with /bin/sh
# https://fedoraproject.org/wiki/Packaging:Scriptlets

echo_error_cannot_unload_modules()
{
    if rpm -q systemd >/dev/null 2>&1
    then
        PERSISTENT_MODULE_FILE="/etc/modules-load.d/mpool.conf"
    else
        PERSISTENT_MODULE_FILE="/etc/sysconfig/modules/mpool.modules"
    fi

    echo
    echo "Failed to remove kernel modules from a previous install."
    echo
    echo "How to resolve this issue:"
    echo
    echo "1. This is likely because an application has open references to a"
    echo "   activated mpool.  You must stop the application, or ensure it has"
    echo "   no open references to an mpool, before updating the kernel"
    echo "   modules."
    echo
    echo "   The following command may help identify processes with an open"
    echo "   reference to an mpool:"
    echo
    echo "   sudo lsof | grep '/dev/mpool'"
    echo
    echo
    echo "2. If the kernel modules still cannot be removed, ensure the file"
    echo "   ${PERSISTENT_MODULE_FILE} is removed or disabled (to stop"
    echo "   modules from loading at boot time), then reboot:"
    echo
    echo "   sudo rm -f ${PERSISTENT_MODULE_FILE}"
    echo "   sudo reboot"
    echo
    echo
    echo "3. If you must install this package now and reboot at a later time,"
    echo "   create the file \"/tmp/mpool-force-install\" as follows:"
    echo
    echo "   sudo touch /tmp/mpool-force-install"
    echo
    echo "   If this file is present *AND* owned by root, the package install "
    echo "   will proceed even if the old kernel modules are loaded."
    echo "   After doing this, you MUST REBOOT to load the correct modules."
    echo
}

force_install_in_progress=0

function check_force_install()
{
    if [[ ${force_install_in_progress} -eq 1 ]]; then
        return
    fi

    if [[ -f /tmp/mpool-force-install ]]; then
        if [[ `/usr/bin/stat -c '%u' /tmp/mpool-force-install` == '0' ]]; then
            echo "*** WARNING ***"
            echo
            echo "/tmp/mpool-force-install exists, forcing install to " \
                 "continue without removing old modules"

            # Leave a marker file for post-install to look for
            touch /tmp/mpool-needs-reboot

            # Don't re-print messages during additional calls to this function
            force_install_in_progress=1
        else
            echo_error_cannot_unload_modules
            echo "*** WARNING ***"
            echo
            echo "/tmp/mpool-force-install exists, but is not owned by root."
            echo
            echo "Change owner to root to force the package install to proceed."
            echo
            exit 1
        fi
    else
        echo_error_cannot_unload_modules
        exit 1
    fi
}

deactivate_done=0

if [[ $1 -gt 1 ]] && [[ -d /dev/mpool ]]; then
    # upgrade - use the existing mpool executable to deactivate mpools
    # before installing new files
    echo "Deactivating mpools..."
    echo

    mpool scan --deactivate -v

    if [[ $? -eq 0 ]]; then
        deactivate_done=1
    fi
fi

#
# If the modules have been properly installed via a prior RPM install,
# the modinfo and modprobe commands should work normally.
#
MODPROBE_MODULES=(mpool)

for module in ${MODPROBE_MODULES[@]}
do
    if modinfo "$module" >/dev/null 2>&1; then
        modprobe -r "$module"
        if [[ $? -ne 0 ]]; then
            check_force_install
        fi
    fi
done

#
# We also need to handle the case where the RPM was uninstalled some time
# in the past, but the removal of the kernel modules failed.  In this case,
# modinfo/modprobe don't work, and we need to directly remove each module.
#
# However, at this point it is likely the user needs to reboot;
# /usr/bin/mpool is not available, therefore there is no way to submit an mpool
# deactivate command to the kernel, and there is no way to remove the last mpool
# reference(s) that prevent mpool from being removed.
#
# If a user gets stuck in this case, we could provide them with a copy of
# /usr/bin/mpool; that should allow them to complete deactivating mpools and
# remove the kernel modules, without a reboot.
#
RAW_MODULES=(
    mpool
)

for module in ${RAW_MODULES[@]}
do
    if grep -q "$module" /proc/modules; then
        rmmod "$module"
        if [[ $? -ne 0 ]]; then
            check_force_install
        fi
    fi
done

rm -rf /lib/modules/`uname -r`/mpool
if [[ $1 -eq 2 ]]; then
    rm -rf /usr/lib/mpool/modules/*
else
    rm -rf /usr/lib/mpool
fi

if [[ ${deactivate_done} -eq 1 ]]; then
    echo
    echo "You will need to manually reactivate mpools after the package " \
         "upgrade is complete."
fi

exit 0
