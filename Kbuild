obj-m = mpool.o

mpool-objs = src/evc.o src/init.o src/mblock.o src/mclass.o src/merr.o src/mlog.o src/mp.o src/mpcore_params.o src/omf.o src/pd.o src/pmd.o src/sb.o src/smap.o src/upgrade.o src/mpctl.o src/mpctl_params.o src/mpctl_reap.o src/mdc.o

ccflags-y += -Wall
ccflags-y += -Werror
ccflags-y += -Wlogical-op
ccflags-y += -Wno-missing-field-initializers
ccflags-y += -Wuninitialized
ccflags-y += -Wmaybe-uninitialized
ccflags-y += -Wextra
ccflags-y += -Wno-conversion
ccflags-y += -Wno-sign-conversion
ccflags-y += -Wno-sign-compare
ccflags-y += -Wno-unused-parameter

ccflags-y +=  -I$M/include -I$M/src -I$M/src/include
