.. SPDX-License-Identifier: GPL-2.0-only

=============
Mpool Locking
=============

Hierarchy
---------
::

  mpool_s_lock
  pmd_s_lock
  eld_rwlock          object layout r/w lock (per layout)
  pds_oml_lock        "open mlog" rbtree lock
  mdi_slotvlock
  mmi_uqlock          unique ID generator lock
  mmi_compactlock     compaction lock (per MDC)
  mmi_uc_lock         uncommitted objects rbtree lock (per MDC)
  mmi_co_lock         committed objects rbtree lock (per MDC)
  pds_pdvlock
  pdi_rmlock[]
  sda_dalock

Nesting
-------

There are three nesting levels for mblocks, mlogs, and mpcore's own
metadata containers (MDCs):

1. PMD_OBJ_CLIENT for client mblocks and mlogs.
2. PMD_MDC_NORMAL for MDC-1/255 and their underlying mlog pairs.
3. PMD_MDC_ZERO for MDC-0 and its underlying mlog pair.

A thread of execution may obtain at most one instance of a given lock-class
at each nesting level, and must do so in the order specified above.

The following helper functions determine the nesting level and use the
appropriate _nested() primitive or lock pool::

  pmd_obj_rdlock() and _rdunlock()
  pmd_obj_wrlock() and _wrunlock()
  pmd_mdc_rdlock() and _rdunlock()
  pmd_mdc_wrlock() and _wrunlock()
  pmd_mdc_lock() and _unlock()

For additional information on the _nested() primitives, see
https://www.kernel.org/doc/Documentation/locking/lockdep-design.txt.

MDC Compaction Locking Patterns
-------------------------------

In addition to obeying the lock hierarchy and lock-class nesting levels, the
following locking rules must also be followed for object layouts and all
mpool properties stored in MDC-0 (e.g., the list of mpool drives pds_pdv[]).

Object layouts (struct pmd_layout):

- Readers must read-lock the layout using pmd_obj_rdlock().
- Updaters must both write-lock the layout using pmd_obj_wrlock() and lock
  the mmi_compactlock for the object's MDC using pmd_mdc_lock() before
  first logging the update in that MDC and then updating the layout.

Mpool properties stored in MDC-0:

- Readers must read-lock the data structure(s) associated with the property.
- Updaters must both write-lock the data structure(s) associated with the
  property and lock the mmi_compactlock for MDC-0 using pmd_mdc_lock() before
  first logging the update in MDC-0 and then updating the data structure(s).

This locking pattern achieves the following:

- For objects associated with a given MDC-0/255, layout readers can execute
  concurrent with compacting that MDC, whereas layout updaters cannot.
- For mpool properties stored in MDC-0, property readers can execute
  concurrent with compacting MDC-0, whereas property updaters cannot.
- To compact a given MDC-0/255, all in-memory and on-media state to be
  written is frozen by simply locking the mmi_compactlock for that MDC
  (because updates to the committed objects tree may take place only while
  holding both both the compaction mutex and the mmi_co_lock write lock).

Furthermore, taking the mmi_compactlock does not reduce concurrency for
object or property updaters because these are inherently serialized by the
requirement to synchronously append log records in the associated MDC.

Object Layout Reference Counts
------------------------------

The reference counts for an object layout (eld_ref) are protected
by mmi_co_lock or mmi_uc_lock of the object's MDC dependiing upon
which tree it is in at the time of acquisition.
