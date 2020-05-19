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
    BDIR           = $(BDIR_DEFAULT)
    BTOPDIR        = $(BTOPDIR_DEFAULT)
    BUILD_DIR      = $$(BTOPDIR)/$$(BDIR)
    BUILD_NUMBER   = $(BUILD_NUMBER_DEFAULT)
    BUILD_SHA      = <none>
    CFILE          = $(CFILE_DEFAULT)
    REL_CANDIDATE  = $(REL_CANDIDATE_DEFAULT)

Get info about the build:

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

    make release CFILE=myconfig.cmake
    make release all

  Create a 'debug' build:

    make debug

  Build against currently running kernel:

    make debug KDIR=/lib/modules/`uname -r`/build
    make debug all

  Custom everything:

    make BDIR=mybuild CFILE=mybuild.cmake KDIR=~/linux-stable
    make BDIR=mybuild all

endef


.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.NOTPARALLEL:


# MPOOL_SRC_DIR is set to the top of the mpool source tree.
MPOOL_SRC_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# Other dirs commonly accessed w/in this makefile:
S=$(MPOOL_SRC_DIR)/scripts

################################################################
#
# Set config var defaults.
#
################################################################
ifeq ($(findstring release,$(MAKECMDGOALS)),release)
  BDIR_DEFAULT  := release
  CFILE_DEFAULT := $(S)/cmake/release.cmake
  KCFLAGS_DEFAULT += "-O2 -DNDEBUG"
else ifeq ($(findstring relwithdebug,$(MAKECMDGOALS)),relwithdebug)
  BDIR_DEFAULT  := relwithdebug
  CFILE_DEFAULT := $(S)/cmake/relwithdebug.cmake
  KCFLAGS_DEFAULT += "-O2 -DNDEBUG -g"
else ifeq ($(findstring relassert,$(MAKECMDGOALS)),relassert)
  BDIR_DEFAULT  := relassert
  CFILE_DEFAULT := $(S)/cmake/relassert.cmake
  KCFLAGS_DEFAULT += -O2
else ifeq ($(findstring optdebug,$(MAKECMDGOALS)),optdebug)
  BDIR_DEFAULT  := optdebug
  CFILE_DEFAULT := $(S)/cmake/optdebug.cmake
  KCFLAGS_DEFAULT += -Og
else ifeq ($(findstring debug,$(MAKECMDGOALS)),debug)
  BDIR_DEFAULT  := debug
  CFILE_DEFAULT := $(S)/cmake/debug.cmake
  KCFLAGS_DEFAULT += -g
else
  BDIR_DEFAULT  := release
  CFILE_DEFAULT := $(S)/cmake/release.cmake
  KCFLAGS_DEFAULT += "-O2 -DNDEBUG"
endif

BTOPDIR_DEFAULT       := $(MPOOL_SRC_DIR)/builds
BUILD_DIR_DEFAULT     := $(BTOPDIR_DEFAULT)/$(BDIR_DEFAULT)
BUILD_NUMBER_DEFAULT  := 0
REL_CANDIDATE_DEFAULT := false

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
REL_CANDIDATE ?= $(REL_CANDIDATE_DEFAULT)

KARCH ?= $(shell uname -m)
KDIR  ?= /lib/modules/$(shell uname -r)/build
KREL  ?= $(patsubst /lib/modules/%/build,%,${KDIR})

ifeq (${KREL},${KDIR})
  KREL := $(patsubst /usr/src/kernels/%,%,${KDIR})
endif

ifeq (${KREL},${KDIR})
  $(error "Unable to determine kernel release from KDIR.  Try setting it via the KREL= variable")
endif

#   CFILE
#   DEPGRAPH
#   BUILD_NUMBER
define config-show
	(echo 'BUILD_DIR="$(BUILD_DIR)"';\
	  echo 'CFILE="$(CFILE)"';\
	  echo 'KDIR="$(KDIR)"';\
	  echo 'KREL="$(KREL)"';\
	  echo 'KARCH="$(KARCH)"';\
	  echo 'BUILD_NUMBER="$(BUILD_NUMBER)"';\
	  echo 'REL_CANDIDATE="$(REL_CANDIDATE)"')
endef

define config-gen =
	(echo '# Note: When a variable is set multiple times in this file,' ;\
	echo '#       it is the *first* setting that sticks!' ;\
	echo ;\
	echo '# building kernel modules' ;\
	echo 'Set( KDIR "$(KDIR)" CACHE STRING "" )' ;\
	echo 'Set( KREL "$(KREL)" CACHE STRING "" )' ;\
	echo 'Set( KARCH "$(KARCH)" CACHE STRING "" )' ;\
	echo 'Set( BUILD_NUMBER "$(BUILD_NUMBER)" CACHE STRING "" )' ;\
	echo 'Set( REL_CANDIDATE "$(REL_CANDIDATE)" CACHE STRING "" )' ;\
	if test "$(BUILD_SHA)"; then \
		echo ;\
		echo '# Use input SHA' ;\
		echo 'Set( MPOOL_SHA "$(BUILD_SHA)" CACHE STRING "")' ;\
	fi ;\
	echo ;\
	echo '# Linux distro detection' ;\
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

# If MAKECMDGOALS contains no goals other than any combination
# of BTYPES then make the given goals depend on the default goal.
#
BTYPES := debug release relwithdebug relassert optdebug
BTYPES := $(filter ${BTYPES},${MAKECMDGOALS})

ifeq ($(filter-out ${BTYPES},${MAKECMDGOALS}),)
BTYPESDEP := ${.DEFAULT_GOAL}
endif

CONFIG = $(BUILD_DIR)/mpool_config.cmake

.PHONY: all allv ${BTYPES}
.PHONY: clean config config-preview distclean
.PHONY: help install install-pre maintainer-clean
.PHONY: load package rebuild scrub unload


# Goals in mostly alphabetical order.
#
all: config
	KCFLAGS=$(KCFLAGS_DEFAULT) $(MAKE) -C $(KDIR) M=`pwd` modules

allv: config
	KCFLAGS=$(KCFLAGS_DEFAULT) $(MAKE) -C $(KDIR) M=`pwd` V=1 modules

ifneq (${BTYPES},)
${BTYPES}: ${BTYPESDEP}
	@true
endif

clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean
	${MAKE} -C config KDIR=${KDIR} KREL=${KREL} clean
	rm -rf "$(BUILD_DIR)"/*.rpm *.mod src/mpool_config.h

config-preview:
	@$(config-show)

config/config.h-${KREL}:
	${MAKE} -j -C config KDIR=${KDIR} KREL=${KREL}  all

src/mpool_config.h: config/config.h-${KREL}
	cp $< $@

${CONFIG}: src/mpool_config.h
	@test -d "$(BUILD_DIR)" || mkdir -p "$(BUILD_DIR)"
	@$(config-show) > $(BUILD_DIR)/config.sh
	@$(config-gen) > $@.tmp
	@cmp -s $@ $@.tmp || (cd "$(BUILD_DIR)" && cmake $(DEPGRAPH) -C $@.tmp $(CMAKE_FLAGS) "$(MPOOL_SRC_DIR)")
	@cp $@.tmp $@

config: ${CONFIG}

distclean scrub: clean
	${MAKE} -C config distclean
	@if test -f ${CONFIG} ; then \
		rm -rf "$(BUILD_DIR)" ;\
	fi

help:
	@true
	$(info $(HELP_TEXT))

module-cleanup:
	@rm -rf /lib/modules/`uname -r`/mpool /usr/lib/mpool

install-pre: module-cleanup config all

install: install-pre
	$(MAKE) -C $(KDIR) M=`pwd` modules_install
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
