#!/usr/bin/bash

#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

# This script tries to report the 'uname -r' string for a kernel pointed to
# $1 (aka KDIR).
#
# On success, we echo the uname string and exit with 0 status
#
# On failure, we exit with an error message and a non-0 status
#
KDIR=$1

if [[ -z "$KDIR" ]] ; then
    echo "KDIR is empty"
    exit 1
fi

if [[ ! -e "$KDIR" ]] ; then
    echo "KDIR ($KDIR) does not exist"
    exit 1
fi

running_kernel_uname=`uname -r`
running_kdir="/lib/modules/$running_kernel_uname"

#
# Are we building against /lib/modules/`uname -r`/build ?
# If so, `uname -r` is the kdir_uname
#
tmp=$(dirname "$KDIR")
if [[ "$tmp" = $running_kdir ]];
then
    echo "$running_kernel_uname"
    exit 0
fi

#
# The kernel we are building against (KDIR) may or may not be the running
# kernel on this system; Find a kernel module in KDIR to inspect, and
# determine the 'uname -r' string
#
kmod=$(find "$tmp" -name null_blk.ko.xz -print)
rc=$?
if [ "$kmod" = '' ];
then
    kmod=$(find "$tmp" -name null_blk.ko -print)
fi
if [[ "$kmod" = '' ]];
then
    echo "KDIR ($KDIR) has no modules to get uname from"
    exit 1
fi
kdir_uname=$(/sbin/modinfo "$kmod" | awk '/vermagic/ {print $2}')
echo "$kdir_uname"
exit 0
