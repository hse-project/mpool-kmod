#
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
#

#
# Top-level mpool-kmod Makefile.
#

define HELP_TEXT

mpool Makefile Help
-------------------

Primary Targets:

    all       -- Build binaries, libraries, tests, etc.
    clean     -- Delete most build outputs (saves external repos).
    config    -- Create build output directory and run cmake config.
    distclean -- Delete all build outputs (i.e., start over).
    install   -- Install build artifacts locally
    package   -- Build "all" and generate RPMs
    help      -- Print this message.

Configuration Variables:

  These configuration variables can be set on the command line
  or in ~/mpool-kmod.mk to customize the build.

  Used 'config' as well as 'clean', 'all', etc:
    BUILD_DIR -- The build output directory.  The default value is
                 BTOPDIR/BDIR.  BUILD_DIR can be set directly, in which
                 case BTOPDIR and BDIR are ignored, or BUILD_DIR can be
                 set indirectly via BTOPDIR and BDIR.  A common use case
                 is to set BTOPDIR in ~/mpool-kmod.mk and BDIR on the command
                 line.
    BTOPDIR   -- See BUILD_DIR.
    BDIR      -- See BUILD_DIR.

  Used only by 'config':
    CFILE         -- Name of file containing mpool config parameters.
    BUILD_NUMBER  -- Build job number; defaults to 0 if not set.
                     Deliberately named to inherit the BUILD_NUMBER
	             environment variable in Jenkins.
    BUILD_SHA     -- abbreviated git SHA to use in packaging
    DEPGRAPH      -- Set to "--graphviz=<filename_prefix>" to generate
                     graphviz dependency graph files
    KDIR          -- Location of pre-built Linux Kernel source tree
                     Typically <linux source tree>/builds/<config name>.
    KHEADERS      -- Set KHEADERS=force to build, even if the kernel-headers
                     do not match KDIR. You could get hurt doing this.
    REL_CANDIDATE -- When set builds a release candidate.

  Rules of use:
    * The 'config' target uses CFILE, KDIR, and BUILD_DIR.
      It creates the build output directory (BUILD_DIR)
      and stores the values of CFILE, and KDIR in
      BUILD_DIR/mpool_config.cmake.
    * Other build-related targets ('clean', 'all', etc.)
      require BUILD_DIR and ignore CFILE, and KDIR
      as their values are retrieved from BUILD_DIR/mpool_config.cmake.
    * A side-effect of the "clean" target it that config must be re-run,
      which means you have to keep specifying KDIR for that step.

  Defaults:
    BDIR           = $(BDIR_DEFAULT)      # note MPOOL_DISTRO is appended
    BTOPDIR        = $(BTOPDIR_DEFAULT)
    BUILD_DIR      = $$(BTOPDIR)/$$(BDIR)
    BUILD_NUMBER   = $(BUILD_NUMBER_DEFAULT)
    BUILD_SHA      = <none>
    CFILE          = $(CFILE_DEFAULT)
    REL_CANDIDATE  = $(REL_CANDIDATE_DEFAULT)

Get info about the build:

    etags     -- build TAGS file

Customizations:

  The behavior of this makefile can be customized by creating the following files in your home directory:

    ~/mpool-kmod.mk  -- included at the top of this makefile, can be
                  used to change default build directory, default
                  build targe, etc.
    ~/mpool-kmod1.mk  -- included at the end of this makefile, can be used
                  to extend existing targets or to create your own
                  custom targets

Debug and Release Convenience Targets:

  Convenience targets are keyboard shortcuts aimed at reducing the
  incidence of carpal tunnel syndrome among our highly valued
  development staff.  Including 'release' (or 'debug') on the command
  line changes the defaults for CFILE, BDIR to produce a release (or
  debug) build.

Examples:

  Use 'config-preview' to preview a configuration without modifying any
  files or directories.  This will show you which kernel is used, where
  the build outputs are located, etc.

    make config-preview
    make config-preview release
    make config-preview BTOPDIR=~/builds BDIR=yoyo

  Rebuild everything:

    make distclean all

  Rebuild the bulk of mpool code:

    make clean all

  Incremental rebuild after modifications to mpool code:

    make

  Create a 'release' build:

    make (or make release)

  Work in the 'release' build output dir, but with your own configuration file:

    make release config CFILE=myconfig.cmake
    make release all

  Create a 'debug' build:

    make debug

  Build against currently running kernel:

    make debug config KDIR=/lib/modules/`uname -r`/build
    make debug all

  Custom everything:

    make BDIR=mybuild config CFILE=mybuild.cmake KDIR=~/linux-stable
    make BDIR=mybuild all

endef


.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.NOTPARALLEL:


# MPOOL_SRC_DIR is set to the top of the mpool source tree.
MPOOL_SRC_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# Other dirs commonly accessed w/in this makefile:
S=$(MPOOL_SRC_DIR)/scripts

# Get some details about the distro environment
# Can override detection by passing DISTRO=el6.9 (where el6.9 is a
# specifically recognized by the get_distro.sh script)
MPOOL_DISTRO_CMD_OUTPUT := $(shell scripts/dev/get_distro.sh $(DISTRO))
MPOOL_DISTRO_PREFIX     := $(word 1,$(MPOOL_DISTRO_CMD_OUTPUT))
MPOOL_DISTRO            := $(word 2,$(MPOOL_DISTRO_CMD_OUTPUT))
MPOOL_DISTRO_MAJOR      := $(word 3,$(MPOOL_DISTRO_CMD_OUTPUT))
MPOOL_DISTRO_MINOR      := $(word 4,$(MPOOL_DISTRO_CMD_OUTPUT))
MPOOL_DISTRO_SUPPORTED  := $(word 5,$(MPOOL_DISTRO_CMD_OUTPUT))

ifeq ($(MPOOL_DISTRO_SUPPORTED),unsupported)
  $(error invalid MPOOL_DISTRO ($(MPOOL_DISTRO_CMD_OUTPUT)) )
endif

################################################################
#
# Set config var defaults.
#
################################################################
ifeq ($(findstring release,$(MAKECMDGOALS)),release)
  BDIR_DEFAULT  := release.$(MPOOL_DISTRO)
  CFILE_DEFAULT := $(S)/cmake/release.cmake
else ifeq ($(findstring relwithdebug,$(MAKECMDGOALS)),relwithdebug)
  BDIR_DEFAULT  := relwithdebug.$(MPOOL_DISTRO)
  CFILE_DEFAULT := $(S)/cmake/relwithdebug.cmake
else ifeq ($(findstring relassert,$(MAKECMDGOALS)),relassert)
  BDIR_DEFAULT  := relassert.$(MPOOL_DISTRO)
  CFILE_DEFAULT := $(S)/cmake/relassert.cmake
else ifeq ($(findstring optdebug,$(MAKECMDGOALS)),optdebug)
  BDIR_DEFAULT  := optdebug.$(MPOOL_DISTRO)
  CFILE_DEFAULT := $(S)/cmake/optdebug.cmake
else ifeq ($(findstring debug,$(MAKECMDGOALS)),debug)
  BDIR_DEFAULT  := debug.$(MPOOL_DISTRO)
  CFILE_DEFAULT := $(S)/cmake/debug.cmake
else
  BDIR_DEFAULT  := release.$(MPOOL_DISTRO)
  CFILE_DEFAULT := $(S)/cmake/release.cmake
endif

BTOPDIR_DEFAULT       := $(MPOOL_SRC_DIR)/builds
BUILD_DIR_DEFAULT     := $(BTOPDIR_DEFAULT)/$(BDIR_DEFAULT)
MPOOL_REL_KERNEL      := $(shell uname -r)
MPOOL_DBG_KERNEL      := $(MPOOL_REL_KERNEL)+debug
KDIR_REL              := /lib/modules/$(MPOOL_REL_KERNEL)/build
KDIR_DBG              := /lib/modules/$(MPOOL_DBG_KERNEL)/build
BUILD_NUMBER_DEFAULT  := 0
REL_CANDIDATE_DEFAULT := false

KDIR_DEFAULT          := $(KDIR_REL)

################################################################
#
# Set config var from defaults unless set by user on the command line.
#
################################################################
BTOPDIR       ?= $(BTOPDIR_DEFAULT)
BDIR          ?= $(BDIR_DEFAULT)
BUILD_DIR     ?= $(BTOPDIR)/$(BDIR)
CFILE         ?= $(CFILE_DEFAULT)
BUILD_NUMBER  ?= $(BUILD_NUMBER_DEFAULT)
KDIR          ?= $(KDIR_DEFAULT)
REL_CANDIDATE ?= $(REL_CANDIDATE_DEFAULT)

################################################################
# Git and external repos
################################################################

mpool_repo=.
mpool_branch=master


PERL_CMAKE_NOISE_FILTER := \
    perl -e '$$|=1;\
        while (<>) {\
            next if m/(Entering|Leaving) directory/;\
            next if m/Not a git repository/;\
            next if m/GIT_DISCOVERY_ACROSS_FILESYSTEM/;\
            next if m/^\[..\d%\]/;\
            next if m/cmake_progress/;\
            print;\
        }'


#   CFILE
#   DEPGRAPH
#   BUILD_NUMBER
define config-show
	(echo 'BUILD_DIR="$(BUILD_DIR)"';\
	  echo 'CFILE="$(CFILE)"';\
	  echo 'KDIR="$(KDIR)"';\
          echo 'KDIR_UNAME="$(KDIR_UNAME)"';\
	  echo 'BUILD_NUMBER="$(BUILD_NUMBER)"';\
	  echo 'MPOOL_DISTRO_PREFIX="$(MPOOL_DISTRO_PREFIX)"';\
	  echo 'MPOOL_DISTRO="$(MPOOL_DISTRO)"';\
	  echo 'MPOOL_DISTRO_MAJOR="$(MPOOL_DISTRO_MAJOR)"';\
	  echo 'MPOOL_DISTRO_MINOR="$(MPOOL_DISTRO_MINOR)"';\
	  echo 'MPOOL_DISTRO_SUPPORTED="$(MPOOL_DISTRO_SUPPORTED)"';\
	  echo 'REL_CANDIDATE="$(REL_CANDIDATE)"')
endef

define config-gen =
	(echo '# Note: When a variable is set multiple times in this file,' ;\
	echo '#       it is the *first* setting that sticks!' ;\
	echo ;\
	echo '# building kernel modules' ;\
	echo 'Set( MPOOL_KERNEL_DIR "$(KDIR)" CACHE STRING "" )' ;\
	echo 'Set( MPOOL_KDIR_UNAME "$(KDIR_UNAME)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_NUMBER "$(BUILD_NUMBER)" CACHE STRING "" )' ;\
	echo 'Set( REL_CANDIDATE "$(REL_CANDIDATE)" CACHE STRING "" )' ;\
	if test "$(BUILD_SHA)"; then \
		echo ;\
		echo '# Use input SHA' ;\
		echo 'Set( MPOOL_SHA "$(BUILD_SHA)" CACHE STRING "")' ;\
	fi ;\
	echo ;\
	echo '# Linux distro detection' ;\
	echo 'Set( MPOOL_DISTRO_PREFIX "$(MPOOL_DISTRO_PREFIX)" CACHE STRING "" )' ;\
	echo 'Set( MPOOL_DISTRO "$(MPOOL_DISTRO)" CACHE STRING "" )' ;\
	echo 'Set( MPOOL_DISTRO_MAJOR "$(MPOOL_DISTRO_MAJOR)" CACHE STRING "" )' ;\
	echo 'Set( MPOOL_DISTRO_MINOR "$(MPOOL_DISTRO_MINOR)" CACHE STRING "" )' ;\
	echo ;\
	echo '# BEGIN: $(CFILE)' ;\
	cat  "$(CFILE)" ;\
	echo '# END:   $(CFILE)' ;\
	echo ;\
	echo '# BEGIN: $(S)/cmake/defaults.cmake' ;\
	cat  "$(S)/cmake/defaults.cmake" ;\
	echo '# END:   $(S)/cmake/defaults.cmake')
endef


# Allow devs to customize any vars set prior to this point.
#
MPOOL_CUSTOM_INC_DIR ?= $(HOME)
-include $(MPOOL_CUSTOM_INC_DIR)/mpool-kmod.mk


# Verify that kernel-headers version matches KDIR version.
#
KDIR_UNAME := $(shell scripts/dev/get_kdir_uname.sh $(KDIR))

TMP = $(shell scripts/dev/check_kernel_headers "$(KDIR_UNAME)")
ifneq ($(findstring Congratulations,$(TMP)),Congratulations)
  # kernel-headers does not match KDIR
  ifneq ($(KHEADERS),force)
    $(warning kernel-headers/KDIR mismatch $(TMP))
  endif
endif


# If MAKECMDGOALS contains no goals other than any combination
# of BTYPES then make the given goals depend on the default goal.
#
BTYPES := debug release relwithdebug relassert optdebug
BTYPES := $(filter ${BTYPES},${MAKECMDGOALS})

ifeq ($(filter-out ${BTYPES},${MAKECMDGOALS}),)
BTYPESDEP := ${.DEFAULT_GOAL}
endif

CONFIG = $(BUILD_DIR)/mpool_config.cmake

.PHONY: all allv allq allqv allvq ${BTYPES}
.PHONY: checkfiles clean config config-preview distclean
.PHONY: etags help install install-pre maintainer-clean
.PHONY: load package rebuild scrub unload


# Goals in mostly alphabetical order.
#
all: config
	@$(MAKE) -C "$(BUILD_DIR)" $(MF)

allv: config
	$(MAKE) -C "$(BUILD_DIR)" VERBOSE=1 $(MF)

allq: config
	$(MAKE) -C "$(BUILD_DIR)" $(MF) 2>&1 | $(PERL_CMAKE_NOISE_FILTER)

allqv allvq: config
	$(MAKE) -C "$(BUILD_DIR)" VERBOSE=1 $(MF) 2>&1 | $(PERL_CMAKE_NOISE_FILTER)

ifneq (${BTYPES},)
${BTYPES}: ${BTYPESDEP}
	@true
endif

clean:
	@if test -f ${BUILD_DIR}/src/kbuild.mpool/Makefile ; then \
		$(MAKE) --no-print-directory -C "$(BUILD_DIR)/src/kbuild.mpool" clean ;\
		rm -rf "$(BUILD_DIR)"/*.rpm ;\
	fi

config-preview:
	@$(config-show)

${CONFIG}:
	@test -d "$(BUILD_DIR)" || mkdir -p "$(BUILD_DIR)"
	@echo "prune: true" > "$(BUILD_DIR)"/.checkfiles.yml
	@$(config-show) > $(BUILD_DIR)/config.sh
	@$(config-gen) > $@.tmp
	@cmp -s $@ $@.tmp || (cd "$(BUILD_DIR)" && cmake $(DEPGRAPH) -C $@.tmp $(CMAKE_FLAGS) "$(MPOOL_SRC_DIR)")
	@cp $@.tmp $@

config: ${CONFIG}

distclean scrub:
	@if test -f ${CONFIG} ; then \
		rm -rf "$(BUILD_DIR)" ;\
	fi

etags:
	@echo "Making emacs TAGS file"
	@find src include \
	        -type f -name "*.[ch]" -print | etags -

help:
	@true
	$(info $(HELP_TEXT))

install-pre: config
	@$(MAKE) -C "$(BUILD_DIR)" install

install: install-pre
	rm -f "/lib/modules/`uname -r`/mpool"
	ln -s "$(DESTDIR)/usr/lib/mpool/modules/" \
			"/lib/modules/`uname -r`/mpool" || exit 1
	udevadm control --reload-rules
	depmod -a || exit 1
	-modprobe -r mpool
	modprobe mpool

load:
	-modprobe -r mpool
	modprobe mpool

maintainer-clean: distclean
	@true

package: all
	-rm -f "$(BUILD_DIR)"/mpool*.rpm
	$(MAKE) -C "$(BUILD_DIR)" package

rebuild: distclean all

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
