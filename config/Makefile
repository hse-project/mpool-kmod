
SUBDIRS := vm_fault_t vm_fault_func blkdev_issue_zeroout
SUBDIRS += bioset_init bioset_create bio_set_dev bio_set_op_attrs
SUBDIRS += iov_iter_init iov_iter_get_pages invalidatepage
SUBDIRS += mem_cgroup_count_vm_event count_memcg_event_mm
SUBDIRS += bdi_alloc backing_dev_info generate_random_guid
SUBDIRS += sched_clock shash_desc submit_bio

.PHONY: all clean distclean ${SUBDIRS}

.DELETE_ON_ERROR:

CF := config.h-$(shell uname -r)

MAKEFLAGS += --no-print-directory

all: ${CF}

clean distclean: ${SUBDIRS}
	rm -rf config.h-*

${CF}: ${SUBDIRS}
	echo "/* SPDX-License-Identifier: GPL-2.0-only */" > $@.tmp
	echo "/* *** Machine generated on $(date) *** */" >> $@.tmp
	cat */config.h >> $@.tmp
	mv $@.tmp $@

vm_fault_func: vm_fault_t

${SUBDIRS}:
	@cp Makefile.test $@/Makefile
	@cp Kbuild.test $@/Kbuild
	${MAKE} -C $@ ${MAKECMDGOALS}

