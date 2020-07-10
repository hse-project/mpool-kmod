#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

#
# Top-level mpool-kmod Makefile.
#

define HELP_TEXT

mpool kmod Makefile Help
-------------------

Primary Targets:

  all       -- Build mpool module
  clean     -- Delete most build outputs
  distclean -- Delete all build outputs
  install   -- Install mpool kmod locally
  package   -- Build "all" and generate RPMs
  help      -- Print this message.

Target Modiiers:

  asan      -- Enable address sanity checking
  debug     -- Create a debug build
  optdebug  -- Create a debug build with -Og
  release   -- Create a release build
  relassert -- Create a release build with assert enabled
  ubsan     -- Enable undefined behavior checking

Configuration Variables:

  The following configuration variables can be set on the command line
  to customize the build.

    BUILD_DIR    -- The top-level build output directory for building packages
    BUILD_PKG    -- The type of package to build (rpm, deb)
    BUILD_NUMBER -- Build job number (as set by Jenkins)
    KCFLAGS      -- kmod build CFLAGS
    KDIR         -- Location of pre-built Linux kernel source tree

  Defaults (not all are customizable):
    BUILD_DIR          $(BUILD_DIR)
    BUILD_NODE         $(BUILD_NODE)
    BUILD_NUMBER       $(BUILD_NUMBER)
    BUILD_TYPE         $(BUILD_TYPE)
    BUILD_STYPE        $(BUILD_STYPE)
    BUILD_PKG_ARCH     ${BUILD_PKG_ARCH}
    BUILD_PKG_DIR      ${BUILD_PKG_DIR}
    BUILD_PKG_DIST     ${BUILD_PKG_DIST}
    BUILD_PKG_REL      ${BUILD_PKG_REL}
    BUILD_PKG_TAG      ${BUILD_PKG_TAG}
    BUILD_PKG_TYPE     ${BUILD_PKG_TYPE}
    BUILD_PKG_VERSION  ${BUILD_PKG_VERSION}
    BUILD_PKG_VENDOR   ${BUILD_PKG_VENDOR}
    BUILD_PKG_VQUAL    ${BUILD_PKG_VQUAL}
    KCFLAGS            ${KCFLAGS}
    KDIR               ${KDIR}
    KREL               ${KREL}
    KARCH              ${KARCH}

Examples:

  Build just the mpool module:

    make -j

  Build the mpool module and generate a package (.rpm or .deb):

    make -j package

  Rebuild the bulk of mpool module code:

    make -j clean all

  Create a 'release-assert' mpool module:

    make -j relassert

  Create a 'debug' mpool module:

    make debug

  Build against a debug kernel that is not the running kernel:

    make debug KDIR=/lib/modules/`uname -r`+debug/build

endef


.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.NOTPARALLEL:

# Edit the package VERSION and QUALifier when we cut a release branch or tag:
BUILD_PKG_VERSION := 1.9.0
BUILD_PKG_VQUAL := '~dev'

BUILD_PKG_VENDOR ?= "Micron Technology, Inc."

BUILD_PKG_TAG := $(shell test -d ".git" && \
	git describe --always --long --tags --dirty --abbrev=10 2>/dev/null)

ifeq (${BUILD_PKG_TAG},)
BUILD_PKG_TAG := ${BUILD_PKG_VERSION}
BUILD_PKG_REL := 0
else
BUILD_PKG_REL := $(shell echo ${BUILD_PKG_TAG} | \
	sed -En 's/.*-([0-9]+)-[a-z0-9]{7,}(-dirty){0,1}$$/\1/p')
BUILD_PKG_VQUAL := $(shell echo ${BUILD_PKG_TAG} | \
	sed -En 's/.*-([^-]+)-[0-9]+-[a-z0-9]{7,}(-dirty){0,1}$$/~\1/p')
endif

ifneq ($(shell egrep -i 'id=(ubuntu|debian)' /etc/os-release),)
BUILD_PKG_TYPE ?= deb
BUILD_PKG_ARCH ?= $(shell dpkg-architecture -q DEB_HOST_ARCH)
BUILD_PKG_DIST :=
else
BUILD_PKG_TYPE ?= rpm
BUILD_PKG_ARCH ?= $(shell uname -m)
BUILD_PKG_DIST := $(shell rpm --eval '%{?dist}')
endif

ifeq ($(wildcard scripts/${BUILD_PKG_TYPE}/CMakeLists.txt),)
$(error "Unable to create a ${BUILD_PKG_TYPE} package, try rpm or deb")
endif


# Find the top-level directory of the mpool kmod source tree
MPOOL_TOP_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# Set vars according to build type...
#
ifeq ($(findstring release,$(MAKECMDGOALS)),release)
	BUILD_TYPE := release
	BUILD_STYPE := r
	KCFLAGS += -O2 -DNDEBUG
else ifeq ($(findstring relassert,$(MAKECMDGOALS)),relassert)
	BUILD_TYPE := relassert
	BUILD_STYPE := a
	KCFLAGS += -O2
else ifeq ($(findstring relwithdebug,$(MAKECMDGOALS)),relwithdebug)
	BUILD_TYPE := relwithdebug
	BUILD_STYPE := i
	KCFLAGS += -O2 -DNDEBUG
else ifeq ($(findstring optdebug,$(MAKECMDGOALS)),optdebug)
	BUILD_TYPE := optdebug
	BUILD_STYPE := o
	KCFLAGS += -Og -DDEBUG
else ifeq ($(findstring debug,$(MAKECMDGOALS)),debug)
	BUILD_TYPE := debug
	BUILD_STYPE := d
	KCFLAGS += -Og -DDEBUG
else
	BUILD_TYPE := release
	BUILD_STYPE := r
	KCFLAGS += -O2 -DNDEBUG
endif

KDIR  ?= /lib/modules/$(shell uname -r)/build
KREL  ?= $(patsubst /lib/modules/%/build,%,${KDIR})

ifeq (${KREL},${KDIR})
KREL := $(patsubst /usr/src/kernels/%,%,${KDIR})
endif

ifeq (${KREL},${KDIR})
$(error "Unable to determine kernel release from KDIR.  Try setting it via the KREL= variable")
endif

DESTDIR       ?= /
BUILD_DIR     ?= ${MPOOL_TOP_DIR}/builds
BUILD_NODE    ?= $(shell uname -n)
BUILD_PKG_DIR ?= ${BUILD_DIR}/${BUILD_NODE}/${KREL}/${BUILD_PKG_TYPE}/${BUILD_TYPE}
BUILD_NUMBER  ?= 0


ifneq ($(shell egrep -i 'id=(ubuntu|debian)' /etc/os-release),)
BUILD_PKG ?= deb
KARCH ?= $(shell dpkg-architecture -q DEB_HOST_ARCH)
else
BUILD_PKG ?= rpm
KARCH ?= $(shell uname -m)
endif

ifeq ($(wildcard scripts/${BUILD_PKG}/CMakeLists.txt),)
$(error "Unable to create a ${BUILD_PKG} package, try rpm or deb")
endif

KCFLAGS += -DMPOOL_VERSION='\"${BUILD_PKG_TAG}-${BUILD_STYPE}${BUILD_NUMBER}\"'


# Compare mpool_config.h to CONFIG_H.  If they differ, mark
# mpool_config.h as a phony target so that it will be rebuilt.
#
CONFIG_H := config/config.h-${KREL}
ifneq ($(wildcard ${CONFIG_H}),)
RC := $(shell (cmp -s src/mpool_config.h ${CONFIG_H} || echo force))
ifeq (${RC},force)
.PHONY: src/mpool_config.h
endif
endif


define config-cmake =
	(echo '# Note: When a variable is set multiple times in this file,' ;\
	echo '#       it is the *first* setting that sticks!' ;\
	echo ;\
	echo 'Set( KDIR                "$(KDIR)" CACHE STRING "" )' ;\
	echo 'Set( KREL                "$(KREL)" CACHE STRING "" )' ;\
	echo 'Set( KARCH               "$(KARCH)" CACHE STRING "" )' ;\
	echo 'Set( DESTDIR             "$(DESTDIR)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_NUMBER        "$(BUILD_NUMBER)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_TYPE          "$(BUILD_TYPE)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_STYPE         "$(BUILD_STYPE)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_ARCH      "$(BUILD_PKG_ARCH)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_DIST      "$(BUILD_PKG_DIST)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_REL       "$(BUILD_PKG_REL)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_TAG       "$(BUILD_PKG_TAG)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_TYPE      "$(BUILD_PKG_TYPE)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_VERSION   "$(BUILD_PKG_VERSION)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_VENDOR    "'$(BUILD_PKG_VENDOR)'" CACHE STRING "" )' ;\
	echo 'Set( BUILD_PKG_VQUAL     "$(BUILD_PKG_VQUAL)" CACHE STRING "" )' ;\
	)
endef


# Allow devs to customize any vars set prior to this point.
#
MPOOL_CUSTOM_INC_DIR ?= $(HOME)
-include $(MPOOL_CUSTOM_INC_DIR)/mpool-kmod.mk


# If MAKECMDGOALS contains no goals other than any combination
# of BTYPES then make the given goals depend on the default goal.
# Otherwise they have no effect other than to set BUILD_TYPE.
#
BTYPES := debug release relwithdebug relassert optdebug
BTYPES := $(filter ${BTYPES},${MAKECMDGOALS})

ifneq (${BTYPES},)
ifeq ($(filter-out ${BTYPES},${MAKECMDGOALS}),)
BTYPESDEP := ${.DEFAULT_GOAL}
endif

${BTYPES}: ${BTYPESDEP}
	@true
endif


# Delete the cmake config file if it has changed.
#
CONFIG_PKG = $(BUILD_PKG_DIR)/config.cmake

ifeq ($(filter config-preview help print-% printq-% smoke load unload,$(MAKECMDGOALS)),)
$(shell $(config-cmake) | cmp -s - ${CONFIG_PKG} || rm -f ${CONFIG_PKG})
endif


.PHONY: all allv ${BTYPES} clean config distclean
.PHONY: help install load maintainer-clean
.PHONY: package rebuild scrub uninstall unload


# Goals in mostly alphabetical order.
#
allv: V=1
allv all: src/mpool_config.h
	KCFLAGS="${KCFLAGS}" $(MAKE) -C $(KDIR) M=$${PWD}/src V=$V modules

clean: MAKEFLAGS += --no-print-directory
clean:
	-test -f "${CONFIG_PKG}" && $(MAKE) -C $(BUILD_PKG_DIR) clean
	-$(MAKE) -C $(KDIR) M=$${PWD}/src clean 2>/dev/null
	$(MAKE) -C config clean
	rm -rf kmod-mpool-$(KREL)*.${BUILD_PKG} src/mpool_config.h

${CONFIG_H}: Makefile
	${MAKE} -j -C config KDIR=${KDIR} KREL=${KREL} all

src/mpool_config.h: ${CONFIG_H}
	cp $< $@

config: ${CONFIG_H} ${CONFIG_PKG}

config-preview:
ifneq ($(wildcard ${CONFIG_PKG}),)
	@sed -En 's/^[^#]*\((.*)CACHE.*/\1/p' ${CONFIG_PKG}
endif
	@true

distclean scrub: MAKEFLAGS += --no-print-directory
distclean scrub: clean
	${MAKE} -C config distclean
	rm -rf $(BUILD_DIR) *.rpm *.deb

help:
	$(info $(HELP_TEXT))
	@true

install: all
	$(MAKE) -C $(KDIR) M=$${PWD}/src INSTALL_MOD_PATH=${DESTDIR} modules_install
	depmod -A

load:
	modprobe mpool

maintainer-clean: distclean
	@true

${CONFIG_PKG}: CMakeLists.txt Makefile scripts/${BUILD_PKG_TYPE}/CMakeLists.txt
	mkdir -p $(@D)
	rm -rf $(@D)/*
	@$(config-cmake) > $@.tmp
	(cd $(@D) && cmake -C $@.tmp $(CMAKE_FLAGS) "$(MPOOL_TOP_DIR)")
	mv $@.tmp $@

package ${BUILD_PKG}: all ${CONFIG_PKG}
	$(MAKE) -C $(BUILD_PKG_DIR) package
	cp ${BUILD_PKG_DIR}/*.${BUILD_PKG_TYPE} .

rebuild: distclean all

uninstall:
	-rm /lib/modules/${KREL}/extra/mpool.ko
	depmod -A

unload:
	-modprobe -r mpool

print-%:
	$(info $*="$($*)")
	@true

printq-%:
	$(info $($*))
	@true

# mpool-kmod1.mk is used by developers to add their own targets
-include  $(MPOOL_CUSTOM_INC_DIR)/mpool-kmod1.mk

# BUILD_DIR may not be ., ./, ./., ./.., /, /., /.., nor empty,
# nor may it contain any whitespace.
#
ifeq ($(abspath ${BUILD_DIR}),)
$(error BUILD_DIR may not be [nil])
else ifeq ($(abspath ${BUILD_DIR}),/)
$(error BUILD_DIR may not be [/])
else ifeq ($(abspath ${BUILD_DIR}),$(abspath ${CURDIR}))
$(error BUILD_DIR may not be [${CURDIR}])
else ifeq ($(abspath ${BUILD_DIR}),$(abspath ${CURDIR}/..))
$(error BUILD_DIR may not be [${CURDIR}/..])
else ifneq ($(words ${BUILD_DIR}),1)
$(error BUILD_DIR may not contain whitespace)
endif
