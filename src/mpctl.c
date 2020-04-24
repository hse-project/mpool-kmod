// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/log2.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <linux/memcontrol.h>
#include <linux/pagemap.h>
#include <linux/kobject.h>
#include <linux/mm_inline.h>
#include <linux/version.h>

#include <linux/backing-dev.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/migrate.h>
#include <linux/delay.h>
#include <linux/ctype.h>
#include <linux/uio.h>

#include <mpool/mpool_ioctl.h>

#include <mpcore/mpcore_printk.h>
#include <mpcore/mdc.h>
#include <mpcore/assert.h>
#include <mpcore/mpcore.h>
#include <mpcore/mlog.h>
#include <mpcore/qos.h>
#include <mpcore/init.h>
#include <mpcore/evc.h>

#include <mpctl_internal.h>
#include <mpool_version.h>

#include "mpctl_params.h"
#include "mpctl_reap.h"
#include "init.h"

#ifndef vm_fault_t
typedef int vm_fault_t;
#endif

#ifndef lru_to_page
#define lru_to_page(_head)  (list_entry((_head)->prev, struct page, lru))
#endif

/*
 * MPC_RA_IOV_MAX - Max pages per call to mblock read by a readahead
 * request.  Be careful about increasing this as it directly adds
 * (n * 24) bytes to the stack frame of mpc_readpages_cb().
 */
#define MPC_RA_IOV_MAX      (8)

#define NODEV               MKDEV(0, 0)    /* Non-existent device */


struct mpc_mpool;

/* mpc pseudo-driver instance data (i.e., all globals live here).
 */
struct mpc_softstate {
	dev_t               ss_devno;       /* Control device devno */
	struct cdev         ss_cdev;
	struct semaphore    ss_op_sema;     /* Serialize mgmt. ops */
	struct class       *ss_class;
	uint                ss_units_max;   /* Max mpool devices */
	struct mutex        ss_lock;        /* Protects unitv[], wq */
	struct mpc_unit    *ss_unitv[];     /* Flexible array!!! */
};

/* Unit-type specific information.
 */
struct mpc_uinfo {
	const char     *ui_typename;
	const char     *ui_subdirfmt;
};

/* There is one unit object for each device object created by the driver.
 */
struct mpc_unit {
	struct mpc_softstate       *un_ss;
	uint                        un_refcnt;
	struct semaphore            un_open_lock;   /* Protects un_open_* */
	struct backing_dev_info    *un_saved_bdi;
	bool                        un_open_excl;   /* Unit exclusively open */
	int                         un_open_cnt;    /* Unit open count */
	dev_t                       un_devno;
	struct device              *un_device;
	uid_t                       un_uid;
	gid_t                       un_gid;
	mode_t                      un_mode;
	bool                        un_transient;
	const struct mpc_uinfo     *un_uinfo;
	struct mpc_mpool           *un_mpool;
	struct mpc_metamap         *un_metamap;
	struct address_space       *un_mapping;
	struct mpc_reap            *un_ds_reap;
	struct ctl_table           *un_tab;
	struct ctl_table_header    *un_hdr;
	uint                        un_rawio;       /* log2(max_mblock_size) */
	u64                         un_ds_oidv[2];
	u32                         un_ra_pages_max;
	enum mp_media_classp        un_ds_mclassp;
	u64                         un_mdc_captgt;
	uuid_le                     un_utype;
	u8                          un_label[MPOOL_LABELSZ_MAX];
	char                        un_name[];      /* Flexible array!!! */
};

/* One mpc_mpool object per mpool
 */
struct mpc_mpool {
	struct mpc_softstate       *mp_ss;
	uint                        mp_refcnt;
	struct rw_semaphore         mp_lock;
	struct mpool_descriptor    *mp_desc;
	struct mp_mdc              *mp_mdc;
	uint                        mp_dpathc;
	char                      **mp_dpathv;
	char                        mp_name[];
};

/* Arguments required to initiate an asynchronous call to mblock_read()
 * and which must also be preserved across that call.
 *
 * Note: We could make things more efficient by changing a_pagev[]
 * to a struct iovec if mblock_read() would guarantee that it will
 * not alter the given iovec.
 */
struct readpage_args {
	void                       *a_meta;
	struct mblock_descriptor   *a_mbdesc;
	u64                         a_mboffset;
	int                         a_pagec;
	struct page                *a_pagev[];
};

struct readpage_work {
	struct work_struct      w_work;
	struct readpage_args    w_args;
};

/**
 * struct mpc_metabkt -
 * @mmb_lock:
 */
struct mpc_metabkt {
	spinlock_t      mmb_lock;
} ____cacheline_aligned;

/**
 * struct mpc_metamap -
 * @mm_rgnlock: serializes region alloc/free
 * @mm_rgnmap:  vma region allocator
 * @mm_refcnt;  metamap reference count
 * @mm_bktv:    lockpool to serialize mpc_vma updates
 */
struct mpc_metamap {
	struct mutex        mm_rgnlock;
	struct idr          mm_rgnmap;
	atomic_t            mm_refcnt;

	struct mpc_metabkt  mm_bktv[13];
};

static merr_t mpc_cf_journal(struct mpc_unit *unit);

static merr_t
mpc_physio(
	struct mpool_descriptor    *mpd,
	void                       *desc,
	struct iovec               *uiov,
	int                         uioc,
	off_t                       offset,
	enum mp_obj_type            objtype,
	int                         rw,
	void                       *stkbuf,
	size_t                      stkbufsz);

static int mpc_readpage_impl(struct page *page, struct mpc_vma *map);

#define ITERCB_DONE     (1)
#define ITERCB_NEXT     (2)

typedef int mpc_unit_itercb_t(struct mpc_unit *unit, void *arg);


/* The following structures are initialized at the end of this file.
 */
static const struct file_operations            mpc_fops_default;
static const struct vm_operations_struct       mpc_vops_default;
static const struct address_space_operations   mpc_aops_default;

static const struct mpc_uinfo mpc_uinfo_ctl = {
	.ui_typename = "mpoolctl",
	.ui_subdirfmt = "%s",
};

static const struct mpc_uinfo mpc_uinfo_mpool = {
	.ui_typename = "mpool",
	.ui_subdirfmt = "mpool/%s",
};

static struct mpc_softstate   *mpc_softstate __read_mostly;

static struct workqueue_struct *mpc_wq_trunc __read_mostly;
static struct workqueue_struct *mpc_wq_rav[8] __read_mostly;
static struct mpc_reap *mpc_reap __read_mostly;

static size_t mpc_vma_cachesz[2] __read_mostly;
static struct kmem_cache *mpc_vma_cache[2] __read_mostly;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
static struct backing_dev_info mpc_bdi = {
	.name          = "mpctl",
	.capabilities  = BDI_CAP_NO_ACCT_AND_WRITEBACK,
	.ra_pages      = MPOOL_RA_PAGES_MAX,
};
#endif

/* Module params...
 */
static unsigned int mpc_ctl_uid __read_mostly = 0;
module_param(mpc_ctl_uid, uint, 0444);
MODULE_PARM_DESC(mpc_ctl_uid, " control device uid");

static unsigned int mpc_ctl_gid __read_mostly = 6;
module_param(mpc_ctl_gid, uint, 0444);
MODULE_PARM_DESC(mpc_ctl_gid, " control device gid");

static unsigned int mpc_ctl_mode __read_mostly = 0664;
module_param(mpc_ctl_mode, uint, 0444);
MODULE_PARM_DESC(mpc_ctl_mode, " control device mode");

static unsigned int mpc_default_uid __read_mostly = 0;
module_param(mpc_default_uid, uint, 0644);
MODULE_PARM_DESC(mpc_default_uid, " default mpool device uid");

static unsigned int mpc_default_gid __read_mostly = 6;
module_param(mpc_default_gid, uint, 0644);
MODULE_PARM_DESC(mpc_default_gid, " default mpool device gid");

static unsigned int mpc_default_mode __read_mostly = 0660;
module_param(mpc_default_mode, uint, 0644);
MODULE_PARM_DESC(mpc_default_mode, " default mpool device mode");

static unsigned int mpc_units_max __read_mostly = 1024;
module_param(mpc_units_max, uint, 0444);
MODULE_PARM_DESC(mpc_units_max, " max mpools");

static unsigned int mpc_vma_max __read_mostly = 1048576 * 128;
module_param(mpc_vma_max, uint, 0444);
MODULE_PARM_DESC(mpc_vma_max, " max vma regions");

unsigned int mpc_vma_size_max __read_mostly = 30;
module_param(mpc_vma_size_max, uint, 0444);
MODULE_PARM_DESC(mpc_vma_size_max, " max vma size log2");

unsigned int mpc_rwsz_max __read_mostly = 32;
module_param(mpc_rwsz_max, uint, 0444);
MODULE_PARM_DESC(mpc_rwsz_max, " max mblock/mlog r/w size (mB)");

unsigned int mpc_rwconc_max __read_mostly = 8;
module_param(mpc_rwconc_max, uint, 0444);
MODULE_PARM_DESC(mpc_rwconc_max, " max mblock/mlog large r/w concurrency");

module_param(mpc_rsvd_bios_max, uint, 0444);
MODULE_PARM_DESC(mpc_rsvd_bios_max, "max reserved bios in mpool bioset");

/* mpc_chunker_size is the number of pages that fit in a one-page iovec list
 * (PAGE_SIZE / sizeof(struct iovec)) * PAGE_SIZE, because each iovec maps
 * one page
 */
int mpc_chunker_size __read_mostly = PAGE_SIZE * 32;
module_param(mpc_chunker_size, int, 0644);
MODULE_PARM_DESC(mpc_chunker_size, "Chunking size (in bytes) for device I/O");


static void
mpc_errinfo(
	struct mpioc_cmn   *cmn,
	enum mpool_rc       rcode,
	const char         *msg)
{
	size_t  len;
	ulong   rc;

	cmn->mc_rcode = rcode;

	if (!cmn->mc_msg)
		return;

	len = strnlen(msg, MPOOL_DEVRPT_SZ - 1);

	rc = copy_to_user(cmn->mc_msg, msg, len + 1);
	if (rc)
		mp_pr_err("copy_to_user(%s, %lu), rc %lu",
			  merr(EFAULT), msg, len + 1, rc);
}

static inline struct mpc_softstate *mpc_softstate_cdev2ss(struct cdev *cdev)
{
	if (ev(!cdev || cdev->owner != THIS_MODULE)) {
		merr_t err = merr(EINVAL);

		mp_pr_crit("module dissociated", err);
		return NULL;
	}

	return container_of(cdev, struct mpc_softstate, ss_cdev);
}

static inline bool mpc_unit_isctldev(const struct mpc_unit *unit)
{
	return (unit->un_uinfo == &mpc_uinfo_ctl);
}

static inline bool mpc_unit_ismpooldev(const struct mpc_unit *unit)
{
	return (unit->un_uinfo == &mpc_uinfo_mpool);
}

static uid_t mpc_current_uid(void)
{
	return from_kuid(current_user_ns(), current_uid());
}

static gid_t mpc_current_gid(void)
{
	return from_kgid(current_user_ns(), current_gid());
}

/**
 * mpc_mpool_get() - Acquire an additional reference on an mpool object.
 * @mpool:  mpool ptr
 *
 * Caller must already hold a reference.
 */
static void mpc_mpool_get(struct mpc_mpool *mpool)
{
	struct mpc_softstate   *ss;

	if (mpool) {
		ss = mpool->mp_ss;

		mutex_lock(&ss->ss_lock);
		++mpool->mp_refcnt;
		mutex_unlock(&ss->ss_lock);
	}
}

/**
 * mpc_mpool_put() - Release a reference on an mpool object.
 * @mpool:  mpool ptr
 *
 * Returns: merr_t, usually EBUSY or 0.
 */
static void mpc_mpool_put(struct mpc_mpool *mpool)
{
	struct mpc_softstate   *ss;
	bool                    destroyme;

	/* This is normal because mpc_unit_foo will call with NULL for
	 * MPC_DEV_CTLPATH, i.e. in mpc_init() or mpc_exit().
	 */
	if (ev(!mpool))
		return;

	ss = mpool->mp_ss;

	mutex_lock(&ss->ss_lock);
	destroyme = (0 == --mpool->mp_refcnt);
	mutex_unlock(&ss->ss_lock);

	if (!destroyme)
		return;

	if (mpool->mp_desc) {
		merr_t err;

		err = mpool_deactivate(mpool->mp_desc);
		if (err)
			mp_pr_err("mpool %s deactivate failed",
				  err, mpool->mp_name);

	}

	kfree(mpool->mp_dpathv);
	kfree(mpool);

	module_put(THIS_MODULE);
}

/**
 * mpc_toascii() - convert string to restricted ASCII
 *
 * Zeroes out the remainder of str[] and returns the length.
 */
static size_t mpc_toascii(char *str, size_t sz)
{
	size_t  len = 0;
	int     i;

	if (!str || sz < 1)
		return 0;

	if (str[0] == '-')
		str[0] = '_';

	for (i = 0; i < (sz - 1) && str[i]; ++i) {
		if (isalnum(str[i]) || strchr("_.-", str[i]))
			continue;

		str[i] = '_';
	}

	len = i;

	while (i < sz)
		str[i++] = '\000';

	return len;
}

static void mpool_params_merge_defaults(struct mpool_params *params)
{
	if (params->mp_spare_cap == MPOOL_SPARES_INVALID)
		params->mp_spare_cap = MPOOL_SPARES_DEFAULT;

	if (params->mp_spare_stg == MPOOL_SPARES_INVALID)
		params->mp_spare_stg = MPOOL_SPARES_DEFAULT;

	if (params->mp_mclassp == MPOOL_MCLASS_INVALID)
		params->mp_mclassp = MPOOL_MCLASS_DEFAULT;

	if (params->mp_ra_pages_max == U32_MAX)
		params->mp_ra_pages_max = MPOOL_RA_PAGES_MAX;
	params->mp_ra_pages_max = clamp_t(u32, params->mp_ra_pages_max,
					  0, MPOOL_RA_PAGES_MAX);

	if (params->mp_mode != -1)
		params->mp_mode &= 0777;

	params->mp_vma_size_max = mpc_vma_size_max;

	params->mp_rsvd1 = 0;
	params->mp_rsvd2 = 0;
	params->mp_rsvd3 = 0;
	params->mp_rsvd4 = 0;

	if (!strcmp(params->mp_label, MPOOL_LABEL_INVALID))
		strcpy(params->mp_label, MPOOL_LABEL_DEFAULT);

	mpc_toascii(params->mp_label, sizeof(params->mp_label));
}

static bool
mpool_params_merge_config(
	struct mpool_params *params,
	struct mpool_config *cfg)
{
	uuid_le uuidnull = { };
	bool    changed = false;

	if (params->mp_uid != -1 && params->mp_uid != cfg->mc_uid) {
		cfg->mc_uid = params->mp_uid;
		changed = true;
	}

	if (params->mp_gid != -1 && params->mp_gid != cfg->mc_gid) {
		cfg->mc_gid = params->mp_gid;
		changed = true;
	}

	if (params->mp_mode != -1 && params->mp_mode != cfg->mc_mode) {
		cfg->mc_mode = params->mp_mode;
		changed = true;
	}

	if (memcmp(&uuidnull, &params->mp_utype, sizeof(uuidnull)) &&
	    memcmp(&params->mp_utype, &cfg->mc_utype,
		   sizeof(params->mp_utype))) {
		memcpy(&cfg->mc_utype, &params->mp_utype,
		       sizeof(cfg->mc_utype));
		changed = true;
	}

	if (strcmp(params->mp_label, MPOOL_LABEL_DEFAULT) &&
	    strncmp(params->mp_label, cfg->mc_label,
		    sizeof(params->mp_label))) {
		strlcpy(cfg->mc_label, params->mp_label, sizeof(cfg->mc_label));
		changed = true;
	}

	return changed;
}

static void
mpool_to_mpcore_params(
	struct mpool_params    *params,
	struct mpcore_params   *mpc_params)
{
	u64    mdc0cap;
	u64    mdcncap;
	u32    mdcnum;

	mpcore_params_defaults(mpc_params);

	mdc0cap = (u64)params->mp_mdc0cap << 20;
	mdcncap = (u64)params->mp_mdcncap << 20;
	mdcnum  = params->mp_mdcnum;

	if (mdc0cap != 0)
		mpc_params->mp_mdc0cap = mdc0cap;

	if (mdcncap != 0)
		mpc_params->mp_mdcncap = mdcncap;

	if (mdcnum != 0)
		mpc_params->mp_mdcnum = mdcnum;
}

/**
 * mpc_mpool_open() - Open the mpool specified by the given drive paths,
 *                    and then create an mpool object to track the
 *                    underlying mpool.
 * @ss:     driver softstate
 * @dpathc: drive count
 * @dpathv: drive path name vector
 * @mpoolp: mpool ptr. Set only if success.
 * @devrpt:
 * @pd_prop: PDs properties
 *
 * Return:  Returns 0 if successful and sets *mpoolp.
 *          Returns -errno on error.
 */
static merr_t
mpc_mpool_open(
	struct mpc_softstate   *ss,
	uint                    dpathc,
	char                  **dpathv,
	struct mpc_mpool      **mpoolp,
	struct mpool_devrpt    *devrpt,
	struct pd_prop	       *pd_prop,
	struct mpool_params    *params,
	u32			flags)
{
	struct mpcore_params    mpc_params;
	struct mpc_mpool       *mpool;
	size_t                  mpoolsz;
	merr_t                  err;
	size_t                  len;

	if (!ss || !dpathv || !mpoolp || !params)
		return merr(EINVAL);

	len = mpc_toascii(params->mp_name, sizeof(params->mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return merr(len < 1 ? EINVAL : ENAMETOOLONG);

	mpoolsz = sizeof(*mpool) + len + 1;

	mpool = kzalloc(mpoolsz, GFP_KERNEL);
	if (!mpool)
		return merr(ENOMEM);

	if (!try_module_get(THIS_MODULE)) {
		kfree(mpool);
		return merr(EBUSY);
	}

	mpool_to_mpcore_params(params, &mpc_params);

	err = mpool_activate(dpathc, dpathv, pd_prop, false, MPOOL_ROOT_LOG_CAP,
			     &mpc_params, flags, &mpool->mp_desc, devrpt);
	if (err) {
		if (devrpt->mdr_off > -1)
			mp_pr_err("Activating %s failed: dev %s, rcode %d",
				  err, params->mp_name, dpathv[devrpt->mdr_off],
				  devrpt->mdr_rcode);
		else
			mp_pr_err("Activating %s failed", err, params->mp_name);

		module_put(THIS_MODULE);
		kfree(mpool);
		return err;
	}

	mpool->mp_ss = ss;
	mpool->mp_refcnt = 1;
	init_rwsem(&mpool->mp_lock);
	mpool->mp_dpathc = dpathc;
	mpool->mp_dpathv = dpathv;
	strcpy(mpool->mp_name, params->mp_name);

	*mpoolp = mpool;

	return 0;
}

/**
 * mpc_unit_create() - Create and install a unit object
 * @ss:           driver softstate
 * @path:         device path under "/dev/" to create
 * @mpool:        mpool ptr
 * @unitp:        unit ptr
 * @needs_refmap: is refmap relevant for this unit type
 *
 * Create a unit object and install a ptr to it in the units table, thereby
 * reserving a minor number.  The unit cannot be found by any of the lookup
 * routines until it leaves transient mode.
 *
 * A unit maps an mpool device (.e.g., /dev/mpool/foo)  to an mpool object
 * created by mpool_create().
 *
 * All units are born with two references, one for the caller and one that
 * can only be released by destroying the unit or unloading the module.
 *
 * Return:  Returns 0 if successful and sets *unitp.
 *          Returns -errno on error.
 */
static merr_t
mpc_unit_create(
	struct mpc_softstate   *ss,
	const char             *name,
	struct mpc_mpool       *mpool,
	struct mpc_unit       **unitp,
	bool                    needs_refmap)
{
	struct mpc_unit    *unit;
	size_t              unitsz;
	uint                minor;
	merr_t              err;
	uint                i;

	if (!ss || !name || !unitp)
		return merr(EINVAL);

	unitsz = sizeof(*unit) + strlen(name) + 1;

	unit = kzalloc(unitsz, GFP_KERNEL);
	if (!unit)
		return merr(ENOMEM);

	err = 0;
	minor = UINT_MAX;
	strcpy(unit->un_name, name);

	sema_init(&unit->un_open_lock, 1);
	unit->un_open_excl = false;
	unit->un_open_cnt = 0;
	unit->un_transient = true;
	unit->un_devno = NODEV;
	unit->un_refcnt = 2;
	unit->un_ss = ss;
	unit->un_mpool = mpool;

	mutex_lock(&ss->ss_lock);
	for (i = 0; i < ss->ss_units_max; ++i) {
		if (!ss->ss_unitv[i]) {
			if (minor == UINT_MAX)
				minor = i;
			continue;
		}

		/* Check to see if the desired name is in use.
		 */
		if (strcmp(ss->ss_unitv[i]->un_name, name) == 0) {
			err = merr(EEXIST);
			minor = UINT_MAX;
			break;
		}
	}

	if (minor < UINT_MAX) {
		unit->un_devno = MKDEV(MAJOR(ss->ss_cdev.dev), minor);
		ss->ss_unitv[minor] = unit;
	}
	mutex_unlock(&ss->ss_lock);

	if (minor == UINT_MAX)
		err = err ?: merr(ENFILE);

	if (err) {
		kfree(unit);
		unit = NULL;
	}

	*unitp = unit;

	return err;
}

/**
 * mpc_unit_destroy() - Destroy a unit object created by mpc_unit_create().
 * @unit:
 *
 * Do not call this function directly, call mpc_unit_put()
 * to release your reference and it will call this function
 * when the ref count reaches zero.
 *
 * Returns: merr_t, usually EBUSY or 0.
 */
static void mpc_unit_destroy(struct mpc_unit *unit)
{
	struct mpc_softstate   *ss = unit->un_ss;

	mutex_lock(&ss->ss_lock);
	ss->ss_unitv[MINOR(unit->un_devno)] = NULL;
	mutex_unlock(&ss->ss_lock);

	if (unit->un_mpool)
		mpc_mpool_put(unit->un_mpool);

	if (unit->un_device)
		device_destroy(ss->ss_class, unit->un_devno);

	kfree(unit);
}

/**
 * mpc_unit_iterate() - Iterate over all active unit objects
 * @ss:     driver softstate
 * @atomic: if true, keep unit table locked over entire iteration
 * @func:   function to call on each iteration
 * @arg:    arg to supply to func()
 *
 * Iterate over all active unit objects and call 'func(unit, arg)' for each.
 * If 'atomic' is true, the unit lock is held across the entire iteration.
 * If 'atomic' is false, a reference to each unit is acquired and held
 * across each call to func() (the unit lock is dropped before each
 * call to func() and reacquired when func() returns).
 */
static void
mpc_unit_iterate(
	struct mpc_softstate   *ss,
	bool                    atomic,
	mpc_unit_itercb_t      *func,
	void                   *arg)
{
	int     rc, i;

	mutex_lock(&ss->ss_lock);
	for (i = 0; i < ss->ss_units_max; ++i) {
		struct mpc_unit *unit = ss->ss_unitv[i];

		if (!unit || unit->un_transient)
			continue;

		if (!atomic) {
			++unit->un_refcnt;
			mutex_unlock(&ss->ss_lock);
		}

		rc = func(unit, arg);

		if (!atomic) {
			mutex_lock(&ss->ss_lock);
			--unit->un_refcnt;
		}

		if (rc == ITERCB_DONE)
			break;
	}
	mutex_unlock(&ss->ss_lock);
}

/**
 * mpc_unit_lookup() - Look up a unit by minor number.
 * @ss:     driver softstate
 * @minor:  minor number
 * @unitp:  unit ptr
 *
 * Returns a referenced ptr to the unit (via *unitp) if found,
 * otherwise it sets *unitp to NULL.
 * Caller must release the reference by calling mpc_unit_put();
 */
static void
mpc_unit_lookup(struct mpc_softstate *ss, uint minor, struct mpc_unit **unitp)
{
	*unitp = NULL;

	mutex_lock(&ss->ss_lock);
	if (minor < ss->ss_units_max) {
		struct mpc_unit *unit = ss->ss_unitv[minor];

		if (unit && !unit->un_transient) {
			++unit->un_refcnt;
			*unitp = unit;
		}
	}
	mutex_unlock(&ss->ss_lock);
}

/**
 * mpc_unit_lookup_by_name_itercb() - Test to see if unit matches arg.
 * @unit:   unit ptr
 * @arg:    argument vector base ptr
 *
 * This iterator callback is called by mpc_unit_iterate() on behalf
 * of mpc_unit_lookup_by_name() for each unit in the units table.
 *
 * Return:  Returns ITERCB_DONE if unit matches args.
 *          Returns ITERCB_NEXT if unit does not match args.
 */
static int mpc_unit_lookup_by_name_itercb(struct mpc_unit *unit, void *arg)
{
	void              **argv = arg;
	struct mpc_unit    *parent = argv[0];
	const char         *name = argv[1];

	if (mpc_unit_isctldev(parent) && !mpc_unit_ismpooldev(unit))
		return ITERCB_NEXT;

	if (parent->un_mpool && unit->un_mpool != parent->un_mpool)
		return ITERCB_NEXT;

	if (strcmp(unit->un_name, name) == 0) {
		++unit->un_refcnt;
		argv[2] = unit;
		return ITERCB_DONE;
	}

	return ITERCB_NEXT;
}

/**
 * mpc_unit_lookup_by_name() - Look up an mpool unit by name.
 * @parent: parent unit
 * @name:   unit name. This is not the mpool name.
 * @unitp:  unit ptr
 *
 * If a unit exists in the system which has the given name and parent
 * then it is referenced and returned via *unitp.  Otherwise, *unitp
 * is set to NULL.
 *
 * Caller must release the reference by calling mpc_unit_put().
 */
static void
mpc_unit_lookup_by_name(
	struct mpc_unit    *parent,
	const char         *name,
	struct mpc_unit   **unitp)
{
	void   *argv[] = { parent, (void *)name, NULL };

	mpc_unit_iterate(parent->un_ss, 1, mpc_unit_lookup_by_name_itercb,
			 argv);

	*unitp = argv[2];
}

/**
 * mpc_unit_put() -  Release a reference on a unit.
 * @unit:   unit ptr
 *
 * Causes the unit to be destroyed when the ref count drops to zero.
 */
static void mpc_unit_put(struct mpc_unit *unit)
{
	struct mpc_softstate   *ss;
	bool                    destroyme;

	if (ev(!unit))
		return;

	ss = unit->un_ss;

	mutex_lock(&ss->ss_lock);
	destroyme = (0 == --unit->un_refcnt);
	if (destroyme)
		unit->un_transient = true;
	mutex_unlock(&ss->ss_lock);

	if (destroyme)
		mpc_unit_destroy(unit);
}

/**
 * mpc_unit_setup() - Create a device unit object and special file
 * @ss:     driver softstate
 * @uinfo:
 * @name:
 * @cfg:
 * @mpool:
 * @unitp: unitp can be NULL. *unitp is updated only if unitp is not NULL
 *	and no error is returned.
 * @cmn:
 *
 * If successful, this function adopts mpool.  On failure, mpool
 * remains the responsibility of the caller.
 *
 * All units are born with two references, one for the caller and one
 * that can only be released by destroying the unit or unloading the
 * module. If the caller passes in nil for unitp then this function
 * will drop the caller's "caller reference" on his behalf.
 *
 * Return:  Returns 0 on success, -errno otherwise...
 */
static merr_t
mpc_unit_setup(
	struct mpc_softstate       *ss,
	const struct mpc_uinfo     *uinfo,
	const char                 *name,
	const struct mpool_config  *cfg,
	struct mpc_mpool           *mpool,
	struct mpc_unit           **unitp,
	struct mpioc_cmn           *cmn)
{
	struct mpc_unit    *unit;
	enum mpool_rc       rcode;
	struct device      *device;
	merr_t              err;

	if (!ss || !uinfo || !name || !name[0] || !cfg || !cmn)
		return merr(EINVAL);

	if (cfg->mc_uid == -1 || cfg->mc_gid == -1 || cfg->mc_mode == -1) {
		mpc_errinfo(cmn, MPCTL_RC_BADMNT, name);
		return merr(EINVAL);
	}

	if (!capable(CAP_MKNOD))
		return merr(EPERM);

	if (cfg->mc_uid != mpc_current_uid() && !capable(CAP_CHOWN))
		return merr(EPERM);

	if (cfg->mc_gid != mpc_current_gid() && !capable(CAP_CHOWN))
		return merr(EPERM);

	if (mpool && strcmp(mpool->mp_name, name))
		return merr(EINVAL);

	rcode = MPOOL_RC_NONE;
	unit = NULL;

	/* Try to create a new unit object.  If successful, then all error
	 * handling beyond this point must route through the errout label
	 * to ensure the unit is fully destroyed.
	 */
	err = mpc_unit_create(ss, name, mpool, &unit,
			      (uinfo == &mpc_uinfo_mpool));
	if (err)
		return err;

	unit->un_uid = cfg->mc_uid;
	unit->un_gid = cfg->mc_gid;
	unit->un_mode = cfg->mc_mode;

	unit->un_mdc_captgt = cfg->mc_captgt;
	unit->un_ds_mclassp = cfg->mc_mclassp;
	memcpy(&unit->un_utype, &cfg->mc_utype, sizeof(unit->un_utype));
	strlcpy(unit->un_label, cfg->mc_label, sizeof(unit->un_label));
	unit->un_ds_oidv[0] = cfg->mc_oid1;
	unit->un_ds_oidv[1] = cfg->mc_oid2;
	unit->un_ra_pages_max = cfg->mc_ra_pages_max;

	device = device_create(ss->ss_class, NULL, unit->un_devno, unit,
			       uinfo->ui_subdirfmt, name);
	if (ev(IS_ERR(device))) {
		err = merr(PTR_ERR(device));
		mp_pr_err("device_create %s failed", err, name);
		rcode = MPCTL_RC_BADMNT;
		goto errout;
	}

	unit->un_device = device;
	unit->un_uinfo = uinfo;

	mutex_lock(&ss->ss_lock);
	unit->un_transient = false;
	mutex_unlock(&ss->ss_lock);

	dev_info(unit->un_device,
		 "minor %u, uid %u, gid %u, mode 0%02o",
		 MINOR(unit->un_devno),
		 cfg->mc_uid, cfg->mc_gid, cfg->mc_mode);

	if (unitp)
		*unitp = unit;
	else
		mpc_unit_put(unit); /* caller doesn't need/want a reference */

errout:
	if (err) {
		mpc_errinfo(cmn, rcode, name);

		/* Acquire an additional reference on mpool so that it is not
		 * errantly destroyed along with the unit, then release both
		 * the unit's birth and caller's references which should
		 * destroy the unit.
		 */
		mpc_mpool_get(mpool);
		mpc_unit_put(unit);
		mpc_unit_put(unit);
	}

	return err;
}

static struct workqueue_struct *mpc_rgn2wq(uint rgn)
{
	return mpc_wq_rav[rgn % ARRAY_SIZE(mpc_wq_rav)];
}

static merr_t mpc_metamap_create(struct mpc_metamap **mmp)
{
	struct mpc_metamap *mm;

	size_t  sz;
	int     i;

	sz = roundup_pow_of_two(sizeof(*mm));

	mm = kzalloc(sz, GFP_KERNEL);
	if (ev(!mm))
		return merr(ENOMEM);

	mutex_init(&mm->mm_rgnlock);
	idr_init(&mm->mm_rgnmap);
	atomic_set(&mm->mm_refcnt, 0);

	for (i = 0; i < ARRAY_SIZE(mm->mm_bktv); ++i)
		spin_lock_init(&mm->mm_bktv[i].mmb_lock);

	*mmp = mm;

	return 0;
}

static void mpc_metamap_destroy(struct mpc_metamap *mm)
{
	if (!mm)
		return;

	/* Wait for all mpc_vma_free_cb() callbacks to complete, after
	 * which we must wait for the reaper to prune its lists.
	 */
	flush_workqueue(mpc_wq_trunc);

	while (atomic_read(&mm->mm_refcnt) > 0)
		usleep_range(100000, 150000);

	idr_destroy(&mm->mm_rgnmap);
	kfree(mm);
}

static struct mpc_vma *mpc_vma_lookup(struct mpc_metamap *mm, uint key)
{
	struct mpc_metabkt *bkt;
	struct mpc_vma     *vma;

	bkt = mm->mm_bktv + (key % ARRAY_SIZE(mm->mm_bktv));

	spin_lock(&bkt->mmb_lock);
	vma = idr_find(&mm->mm_rgnmap, key);
	if (vma)
		++vma->mcm_refcnt;
	spin_unlock(&bkt->mmb_lock);

	return vma;
}

void mpc_vma_free(struct mpc_vma *meta)
{
	struct mpc_metamap *mm;

	assert((u32)(uintptr_t)meta == meta->mcm_magic);
	assert(atomic_read(&meta->mcm_reapref) > 0);

again:
	mpc_reap_vma_evict(meta);

	if (atomic_dec_return(&meta->mcm_reapref) > 0) {
		atomic_inc(meta->mcm_freedp);
		return;
	}

	if (atomic64_read(&meta->mcm_nrpages) > 0) {
		atomic_cmpxchg(&meta->mcm_evicting, 1, 0);
		atomic_inc(&meta->mcm_reapref);
		usleep_range(10000, 30000);
		goto again;
	}

	mm = meta->mcm_metamap;

	mutex_lock(&mm->mm_rgnlock);
	idr_remove(&mm->mm_rgnmap, meta->mcm_rgn);
	mutex_unlock(&mm->mm_rgnlock);

	meta->mcm_magic = 0xbadcafe;
	meta->mcm_rgn = -1;

	kmem_cache_free(meta->mcm_cache, meta);

	atomic_dec(&mm->mm_refcnt);
}

static void mpc_vma_free_cb(struct work_struct *work)
{
	struct mpc_vma *vma = container_of(work, typeof(*vma), mcm_work);

	mpc_vma_free(vma);
}

static void mpc_vma_get(struct mpc_vma *vma)
{
	struct mpc_metamap *mm = vma->mcm_metamap;
	struct mpc_metabkt *bkt;

	bkt = mm->mm_bktv + (vma->mcm_rgn % ARRAY_SIZE(mm->mm_bktv));

	spin_lock(&bkt->mmb_lock);
	assert(vma->mcm_refcnt > 0);
	++vma->mcm_refcnt;
	spin_unlock(&bkt->mmb_lock);
}

static void mpc_vma_put(struct mpc_vma *vma)
{
	struct mpc_metamap *mm = vma->mcm_metamap;
	struct mpc_metabkt *bkt;

	bool closed;
	int  i;

	assert(vma);
	assert((u32)(uintptr_t)vma == vma->mcm_magic);

	bkt = mm->mm_bktv + (vma->mcm_rgn % ARRAY_SIZE(mm->mm_bktv));

	spin_lock(&bkt->mmb_lock);
	assert(vma->mcm_refcnt > 0);

	closed = (--vma->mcm_refcnt == 0);
	if (closed)
		idr_replace(&mm->mm_rgnmap, NULL, vma->mcm_rgn);
	spin_unlock(&bkt->mmb_lock);

	if (!closed)
		return;

	/* Wait for all in-progress readaheads to complete
	 * before we drop our mblock references.
	 */
	if (atomic_add_return(WQ_MAX_ACTIVE, &vma->mcm_rabusy) > 0)
		flush_workqueue(mpc_rgn2wq(vma->mcm_rgn));

	for (i = 0; i < vma->mcm_mbinfoc; ++i)
		mblock_put(vma->mcm_mpdesc, vma->mcm_mbinfov[i].mbdesc);

	INIT_WORK(&vma->mcm_work, mpc_vma_free_cb);
	queue_work(mpc_wq_trunc, &vma->mcm_work);
}

/*
 * MPCTL vm operations.
 */

static void mpc_vm_open(struct vm_area_struct *vma)
{
	mpc_vma_get(vma->vm_private_data);
}

static void mpc_vm_close(struct vm_area_struct *vma)
{
	mpc_vma_put(vma->vm_private_data);
}

static int
mpc_alloc_and_readpage(struct vm_area_struct *vma, pgoff_t offset, gfp_t gfp)
{
	struct file            *file;
	struct page            *page;
	struct address_space   *mapping;
	int                     rc;

	page = __page_cache_alloc(gfp | __GFP_NOWARN);
	if (ev(!page))
		return -ENOMEM;

	file    = vma->vm_file;
	mapping = file->f_mapping;

	rc = add_to_page_cache_lru(page, mapping, offset, gfp & GFP_KERNEL);
	if (rc == 0)
		rc = mpc_readpage_impl(page, vma->vm_private_data);
	else if (rc == -EEXIST)
		rc = 0;

	put_page(page);

	return rc;
}

static bool
mpc_lock_page_or_retry(struct page *page, struct mm_struct *mm, uint flags)
{
	might_sleep();

	if (trylock_page(page))
		return true;

	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		if (flags & FAULT_FLAG_RETRY_NOWAIT)
			return false;

		up_read(&mm->mmap_sem);
		/* _killable version is not exported by the kernel. */
		wait_on_page_locked(page);
		return false;
	}

	if (flags & FAULT_FLAG_KILLABLE) {
		int rc;

		rc = lock_page_killable(page);
		if (rc) {
			up_read(&mm->mmap_sem);
			return false;
		}
	} else {
		lock_page(page);
	}

	return true;
}

static int
mpc_handle_page_error(struct page *page, struct vm_area_struct *vma)
{
	int     rc;

	ClearPageError(page);

	rc = mpc_readpage_impl(page, vma->vm_private_data);
	if (rc == 0) {
		wait_on_page_locked(page);
		if (ev(!PageUptodate(page)))
			rc = -EIO;
	}

	put_page(page);

	return rc;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#define count_memcg_event_mm(_x, _y)   mem_cgroup_count_vm_event((_x), (_y))
#endif

static vm_fault_t
mpc_vm_fault_impl(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct address_space   *mapping;
	struct inode           *inode;
	vm_fault_t              vmfrc;
	pgoff_t                 offset;
	loff_t                  size;
	struct page            *page;

	mapping = vma->vm_file->f_mapping;
	inode   = mapping->host;
	offset  = vmf->pgoff;
	vmfrc   = 0;

	size = round_up(i_size_read(inode), PAGE_SIZE);
	if (ev(offset >= (size >> PAGE_SHIFT)))
		return VM_FAULT_SIGBUS;

retry_find:
	page = find_get_page(mapping, offset);
	if (!page) {
		int rc = mpc_alloc_and_readpage(vma, offset,
						mapping_gfp_mask(mapping));

		if (ev(rc < 0))
			return (rc == -ENOMEM) ? VM_FAULT_OOM : VM_FAULT_SIGBUS;

		vmfrc = VM_FAULT_MAJOR;
		goto retry_find;
	}

	/* At this point, page is not locked but has a ref. */
	if (vmfrc == VM_FAULT_MAJOR) {
		count_vm_event(PGMAJFAULT);
		count_memcg_event_mm(vma->vm_mm, PGMAJFAULT);
	}

	if (!mpc_lock_page_or_retry(page, vma->vm_mm, vmf->flags)) {
		put_page(page);
		return vmfrc | VM_FAULT_RETRY;
	}

	/* At this point, page is locked with a ref. */
	if (unlikely(page->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto retry_find;
	}

	VM_BUG_ON_PAGE(page->index != offset, page);

	if (unlikely(!PageUptodate(page))) {
		int rc = mpc_handle_page_error(page, vma);

		/* At this point, page is not locked and has no ref. */
		if (ev(rc))
			return VM_FAULT_SIGBUS;
		goto retry_find;
	}

	/* page is locked with a ref. */
	vmf->page = page;

	mpc_reap_vma_touch(vma->vm_private_data, page->index);

	return vmfrc | VM_FAULT_LOCKED;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define VM_FAULT_ARGS  struct vm_area_struct *vma, struct vm_fault *vmf
#else
#define VM_FAULT_ARGS  struct vm_fault *vmf
#endif

static vm_fault_t mpc_vm_fault(VM_FAULT_ARGS)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	struct vm_area_struct  *vma = vmf->vma;
#endif
	return mpc_vm_fault_impl(vma, vmf);
}

/*
 * MPCTL address-space operations.
 */

static int mpc_readpage_impl(struct page *page, struct mpc_vma *meta)
{
	struct mpc_mbinfo  *mbinfo;
	struct iovec        iov[1];
	off_t               offset;
	uint                mbnum;
	merr_t              err;

	offset  = page->index << PAGE_SHIFT;
	offset %= (1ul << mpc_vma_size_max);

	mbnum = offset / meta->mcm_bktsz;
	if (ev(mbnum >= meta->mcm_mbinfoc)) {
		unlock_page(page);
		return -EINVAL;
	}

	mbinfo = meta->mcm_mbinfov + mbnum;
	offset %= meta->mcm_bktsz;

	if (ev(offset >= mbinfo->mblen)) {
		unlock_page(page);
		return -EINVAL;
	}

	iov[0].iov_base = page_address(page);
	iov[0].iov_len = PAGE_SIZE;

	err = mblock_read(meta->mcm_mpdesc, mbinfo->mbdesc, iov, 1, offset);
	if (ev(err)) {
		unlock_page(page);
		return -merr_errno(err);
	}

	if (meta->mcm_hcpagesp)
		atomic64_inc(meta->mcm_hcpagesp);
	atomic64_inc(&meta->mcm_nrpages);

	SetPagePrivate(page);
	set_page_private(page, (ulong)meta);
	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}

#define MPC_RPARGSBUFSZ \
	(sizeof(struct readpage_args) + MPC_RA_IOV_MAX * sizeof(void *))

/**
 * mpc_readpages_cb() - mpc_readpages() callback
 * @work:   w_work.work from struct readpage_work
 *
 * The incoming arguments are in the first page (a_pagev[0]) which
 * we are about to overwrite, so we copy them to the stack.
 */
static void mpc_readpages_cb(struct work_struct *work)
{
	char                    argsbuf[MPC_RPARGSBUFSZ];
	struct readpage_args   *args = (void *)argsbuf;
	struct iovec           iovbuf[MPC_RA_IOV_MAX];
	struct iovec           *iov = iovbuf;
	struct mpc_vma         *meta;
	struct readpage_work   *w;

	size_t  argssz;
	int     pagec, i;
	merr_t  err;

	w = container_of(work, struct readpage_work, w_work);

	pagec = w->w_args.a_pagec;
	argssz = sizeof(*args) + sizeof(args->a_pagev[0]) * pagec;

	assert(pagec <= ARRAY_SIZE(iovbuf));
	assert(argssz <= sizeof(argsbuf));

	memcpy(args, &w->w_args, argssz);
	w = NULL; /* Do not touch! */

	meta = args->a_meta;

	/* Synchronize with mpc_vma_put() to prevent dropping our
	 * mblock references while there are reads in progress.
	 */
	if (atomic_inc_return(&meta->mcm_rabusy) > WQ_MAX_ACTIVE) {
		err = merr(ENXIO);
		goto errout;
	}

	for (i = 0; i < pagec; ++i) {
		iov[i].iov_base = page_address(args->a_pagev[i]);
		iov[i].iov_len = PAGE_SIZE;
	}

	err = mblock_read(meta->mcm_mpdesc, args->a_mbdesc,
			  iov, pagec, args->a_mboffset);
	if (!err) {
		atomic_dec(&meta->mcm_rabusy);

		if (meta->mcm_hcpagesp)
			atomic64_add(pagec, meta->mcm_hcpagesp);
		atomic64_add(pagec, &meta->mcm_nrpages);

		for (i = 0; i < pagec; ++i) {
			struct page *page = args->a_pagev[i];

			SetPagePrivate(page);
			set_page_private(page, (ulong)meta);
			SetPageUptodate(page);

			unlock_page(page);
			put_page(page);
		}

		return;
	}

errout:
	mp_pr_rl("mpool %s, vma %px, rgn %u, pagec %d, rabusy %d",
		 err, meta->mcm_unit->un_name,
		 meta, meta->mcm_rgn, pagec,
		 atomic_read(&meta->mcm_rabusy));

	atomic_dec(&meta->mcm_rabusy);

	for (i = 0; i < pagec; ++i) {
		unlock_page(args->a_pagev[i]);
		put_page(args->a_pagev[i]);
	}
}

int
mpc_readpages(
	struct file            *file,
	struct address_space   *mapping,
	struct list_head       *pages,
	uint                    nr_pages)
{
	struct workqueue_struct *wq;
	struct readpage_work   *w;
	struct work_struct     *work;
	struct mpc_mbinfo      *mbinfo;
	struct mpc_unit        *unit;
	struct mpc_vma         *meta;
	struct page            *page;

	off_t   offset, mbend;
	uint    mbnum, iovmax, i;
	uint    ra_pages_max;
	ulong   index;
	gfp_t   gfp;
	u32     key;
	int     rc;

	unit = file->private_data;

	ra_pages_max = unit->un_ra_pages_max;
	if (ra_pages_max < 1)
		return 0;

	page   = lru_to_page(pages);
	offset = page->index << PAGE_SHIFT;
	index  = page->index;
	work   = NULL;
	w      = NULL;

	key = offset >> mpc_vma_size_max;

	/* The idr value here (meta) is pinned for the lifetime
	 * of the address map.  Therefore, we can exit the rcu
	 * read-side critsec without worry that meta will be
	 * destroyed before put_page() has been called on each
	 * and every page in the given list of pages.
	 */
	rcu_read_lock();
	meta = idr_find(&unit->un_metamap->mm_rgnmap, key);
	rcu_read_unlock();

	if (!meta)
		return 0;

	offset %= (1ul << mpc_vma_size_max);

	mbnum = offset / meta->mcm_bktsz;
	if (mbnum >= meta->mcm_mbinfoc)
		return 0;

	mbinfo = meta->mcm_mbinfov + mbnum;

	mbend = mbnum * meta->mcm_bktsz + mbinfo->mblen;
	iovmax = MPC_RA_IOV_MAX;

	gfp = mapping_gfp_mask(mapping) & GFP_KERNEL;
	wq = mpc_rgn2wq(meta->mcm_rgn);

	if (mpc_reap_vma_duress(meta))
		nr_pages = min_t(uint, nr_pages, 8);

	nr_pages = min_t(uint, nr_pages, ra_pages_max);

	for (i = 0; i < nr_pages; ++i) {
		page    = lru_to_page(pages);
		offset  = page->index << PAGE_SHIFT;
		offset %= (1ul << mpc_vma_size_max);

		/* Don't read past the end of the mblock.
		 */
		if (offset >= mbend)
			break;

		/* mblock reads must be logically contiguous.
		 */
		if (page->index != index && work) {
			queue_work(wq, work);
			work = NULL;
		}

		index = page->index + 1; /* next expected page index */

		prefetchw(&page->flags);
		list_del(&page->lru);

		rc = add_to_page_cache_lru(page, mapping, page->index, gfp);
		if (rc) {
			if (work) {
				queue_work(wq, work);
				work = NULL;
			}
			put_page(page);
			continue;
		}

		if (!work) {
			w = page_address(page);
			INIT_WORK(&w->w_work, mpc_readpages_cb);
			w->w_args.a_meta = meta;
			w->w_args.a_mbdesc = mbinfo->mbdesc;
			w->w_args.a_mboffset = offset % meta->mcm_bktsz;
			w->w_args.a_pagec = 0;
			work = &w->w_work;

			iovmax = MPC_RA_IOV_MAX;
			iovmax -= page->index % MPC_RA_IOV_MAX;
		}

		w->w_args.a_pagev[w->w_args.a_pagec++] = page;

		/* Restrict batch size to the number of struct iovecs
		 * that will fit into a page (minus our header).
		 */
		if (w->w_args.a_pagec >= iovmax) {
			queue_work(wq, work);
			work = NULL;
		}
	}

	if (work)
		queue_work(wq, work);

	return 0;
}

/**
 * mpc_releasepage() - Linux VM calls the release page when pages are released.
 * @page:
 * @gfp:
 *
 * The function is added as part of tracking incoming and outgoing pages.
 * When the number of pages owned exceeds the limit (if defined) reap function
 * will get invoked to trim down the usage.
 */
int mpc_releasepage(struct page *page, gfp_t gfp)
{
	struct mpc_vma *meta;

	if (ev(!PagePrivate(page)))
		return 0;

	meta = (void *)page_private(page);
	if (ev(!meta))
		return 0;

	ClearPagePrivate(page);
	set_page_private(page, 0);

	assert((u32)(uintptr_t)meta == meta->mcm_magic);

	if (meta->mcm_hcpagesp)
		atomic64_dec(meta->mcm_hcpagesp);
	atomic64_dec(&meta->mcm_nrpages);

	return 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
#define INVALIDATEPAGE_ARGS    struct page *page, ulong offset
#else
#define INVALIDATEPAGE_ARGS    struct page *page, uint offset, uint length
#endif

static void mpc_invalidatepage(INVALIDATEPAGE_ARGS)
{
	mpc_releasepage(page, 0);
}

/**
 * mpc_migratepage() -  Callback for handling page migration.
 *
 * @mapping:
 * @newpage:
 * @page:
 * @mode:
 *
 * The drivers having private pages are supplying this callback.
 * Not sure the page migration releases or invalidates the page being migrated,
 * or else the tracking of incoming and outgoing pages will be in trouble. The
 * callback is added to deal with uncertainties around migration. The migration
 * will be declined so long as the page is private and it belongs to mpctl.
 */
int
mpc_migratepage(
	struct address_space   *mapping,
	struct page            *newpage,
	struct page            *page,
	enum migrate_mode       mode)
{
	if (page_has_private(page) &&
	    !try_to_release_page(page, GFP_KERNEL))
		return -EAGAIN;

	assert(PageLocked(page));

	return migrate_page(mapping, newpage, page, mode);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
static int mpc_bdi_alloc(void)
{
	int    rc;

	rc = bdi_init(&mpc_bdi);
	if (ev(rc))
		return rc;

	return 0;
}

static void mpc_bdi_free(void)
{
	bdi_destroy(&mpc_bdi);
}
#endif /* LINUX_VERSION_CODE */

/*
 * MPCTL file operations.
 */

/**
 * mpc_open() - Open an mpool or dataset device.
 * @ip: inode ptr
 * @fp: file ptr
 *
 * Return:  Returns 0 on success, -errno otherwise...
 */
static int mpc_open(struct inode *ip, struct file *fp)
{
	struct mpc_softstate       *ss;
	struct mpc_unit            *unit;

	int     open_cnt = 0;
	bool    firstopen;
	merr_t  err = 0;
	int     rc;

	ss = mpc_softstate_cdev2ss(ip->i_cdev);
	if (!ss)
		return -EBADFD;

	/* Acquire a reference on the unit object.  We'll release it
	 * in mpc_release().
	 */
	mpc_unit_lookup(ss, iminor(fp->f_inode), &unit);
	if (!unit)
		return -ENODEV;

	if (down_trylock(&unit->un_open_lock)) {
		rc = (fp->f_flags & O_NONBLOCK) ? -EWOULDBLOCK :
			down_interruptible(&unit->un_open_lock);

		if (rc) {
			err = merr(rc);
			goto errout;
		}
	}

	firstopen = (unit->un_open_cnt == 0);

	if (!(firstopen || !(unit->un_open_excl || (fp->f_flags & O_EXCL)))) {
		err = merr(EBUSY);
		goto unlock;
	}

	nonseekable_open(ip, fp);

	if (fp->f_flags & O_EXCL)
		unit->un_open_excl = true;

	fp->private_data = unit;
	open_cnt = 1;

	if (firstopen && mpc_unit_ismpooldev(unit)) {
		if (!fp->f_mapping || fp->f_mapping != ip->i_mapping) {
			err = merr(EINVAL);
			goto unlock;
		}

		err = mpc_metamap_create(&unit->un_metamap);
		if (ev(err))
			goto unlock;

		fp->f_op = &mpc_fops_default;
		fp->f_mapping->a_ops = &mpc_aops_default;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
		unit->un_saved_bdi = fp->f_mapping->backing_dev_info;
		fp->f_mapping->backing_dev_info = &mpc_bdi;
#endif

		unit->un_mapping = fp->f_mapping;
		unit->un_ds_reap = mpc_reap;

		inode_lock(ip);
		i_size_write(ip, 1ul << 63);
		inode_unlock(ip);
	}

unlock:
	if (!err)
		unit->un_open_cnt += open_cnt;
	up(&unit->un_open_lock);

errout:
	if (err) {
		if (merr_errno(err) != EBUSY)
			mp_pr_err("open %s failed", err, unit->un_name);
		mpc_unit_put(unit);
	}

	return -merr_errno(err);
}

/**
 * mpc_release() - Close the specified mpool or dataset device.
 * @ip: inode ptr
 * @fp: file ptr
 *
 * Return:  Returns 0 on success, -errno otherwise...
 */
static int mpc_release(struct inode *ip, struct file *fp)
{
	struct mpc_unit    *unit;
	bool                lastclose;

	unit = fp->private_data;
	if (!unit)
		return -EBADFD;

	down(&unit->un_open_lock);
	lastclose = (--unit->un_open_cnt == 0);
	if (!lastclose)
		goto errout;

	if (mpc_unit_ismpooldev(unit)) {
		mpc_metamap_destroy(unit->un_metamap);
		unit->un_metamap = NULL;

		unit->un_ds_reap = NULL;
		unit->un_mapping = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
		fp->f_mapping->backing_dev_info = unit->un_saved_bdi;
#endif
	}

	unit->un_open_excl = false;

errout:
	up(&unit->un_open_lock);

	mpc_unit_put(unit);

	return 0;
}

static int mpc_mmap(struct file *fp, struct vm_area_struct *vma)
{
	struct mpc_vma     *meta;
	struct mpc_unit    *unit;

	off_t   off;
	ulong   len;
	u32     key;

	unit = fp->private_data;

	/* Verify that the request doesn't cross a vma region boundary.
	 */
	off = vma->vm_pgoff << PAGE_SHIFT;
	len = vma->vm_end - vma->vm_start - 1;
	if ((off >> mpc_vma_size_max) != ((off + len) >> mpc_vma_size_max))
		return -EINVAL;

	/* Acquire a reference on the metamap for this region.
	 */
	key = off >> mpc_vma_size_max;

	meta = mpc_vma_lookup(unit->un_metamap, key);
	if (!meta)
		return -EINVAL;

	vma->vm_ops = &mpc_vops_default;

	vma->vm_flags &= ~(VM_RAND_READ | VM_SEQ_READ);
	vma->vm_flags &= ~(VM_MAYWRITE | VM_MAYEXEC);

	vma->vm_flags = (VM_DONTEXPAND | VM_DONTDUMP | VM_NORESERVE);
	vma->vm_flags |= VM_MAYREAD | VM_READ | VM_RAND_READ;

	vma->vm_private_data = meta;

	fp->f_ra.ra_pages = unit->un_ra_pages_max;

	mpc_reap_vma_add(unit->un_ds_reap, meta);

	return 0;
}

/**
 * mpioc_mp_add() - add a device to an existing mpool
 * @unit:   control device unit ptr
 * @cmd:    MPIOC_MP_DRV_ADD
 * @drv:    mpool device parameter block
 *
 * MPIOC_MP_ADD ioctl handler to add a drive to a activated mpool
 *
 * Return:  Returns 0 if successful,
 *          Returns merr_t otherwise...
 */
static merr_t
mpioc_mp_add(struct mpc_unit *unit, uint cmd, struct mpioc_drive *drv)
{
	struct mpool_descriptor    *desc = unit->un_mpool->mp_desc;
	struct pd_prop             *pd_prop;

	size_t  pd_prop_sz;
	size_t  dpathvsz;
	merr_t  err = 0;
	char  **dpathv;
	char   *dpaths;
	int     rc, i;

	/* The device path names are in one long string separated by
	 * newlines.  Here we allocate one chunk of memory to hold
	 * all the device paths and a vector of ptrs to them.
	 */
	dpathvsz = drv->drv_dpathc * sizeof(*dpathv) + drv->drv_dpathssz;
	if (drv->drv_dpathc > MPOOL_DRIVES_MAX ||
	    dpathvsz > MPOOL_DRIVES_MAX * (PATH_MAX + sizeof(*dpathv))) {
		mpc_errinfo(&drv->drv_cmn, MPCTL_RC_TOOMANY, "member drives");
		return merr(E2BIG);
	}

	dpathv = kmalloc(dpathvsz, GFP_KERNEL);
	if (!dpathv) {
		mpool_devrpt(&drv->drv_devrpt, MPOOL_RC_ERRMSG, -1,
			     "%s: alloc dpathsz %zu failed",
			     __func__, dpathvsz);
		return merr(ENOMEM);
	}

	dpaths = (char *)dpathv + drv->drv_dpathc * sizeof(*dpathv);
	rc = copy_from_user(dpaths, drv->drv_dpaths, drv->drv_dpathssz);
	if (rc) {
		mpool_devrpt(&drv->drv_devrpt, MPOOL_RC_ERRMSG, -1,
			     "%s: copyin dpaths %zu failed",
			     __func__, drv->drv_dpathssz);
		kfree(dpathv);
		return merr(EFAULT);
	}

	for (i = 0; i < drv->drv_dpathc; ++i) {
		dpathv[i] = strsep(&dpaths, "\n");
		if (!dpathv[i] || (strlen(dpathv[i]) > PATH_MAX - 1)) {
			mpool_devrpt(&drv->drv_devrpt, MPCTL_RC_NLIST, -1, NULL);
			kfree(dpathv);
			return merr(EINVAL);
		}
	}

	/* Get the PDs properties from user space buffer.
	 */
	pd_prop_sz = drv->drv_dpathc * sizeof(*pd_prop);

	pd_prop = kmalloc(pd_prop_sz, GFP_KERNEL);
	if (!pd_prop) {
		mpool_devrpt(&drv->drv_devrpt, MPOOL_RC_ERRMSG, -1,
			     "%s: alloc pd prop %zu failed",
			     __func__, pd_prop_sz);
		kfree(dpathv);
		return merr(ENOMEM);
	}

	rc = copy_from_user(pd_prop, drv->drv_pd_prop, pd_prop_sz);
	if (rc) {
		mpool_devrpt(&drv->drv_devrpt, MPOOL_RC_ERRMSG, -1,
			     "%s: copyin pd prop %zu failed",
			     __func__, pd_prop_sz);
		kfree(pd_prop);
		kfree(dpathv);
		return merr(EFAULT);
	}

	for (i = 0; i < drv->drv_dpathc; ++i) {
		err = mpool_drive_add(desc, dpathv[i], &pd_prop[i],
				      &drv->drv_devrpt);
		if (ev(err))
			break;
	}

	kfree(pd_prop);
	kfree(dpathv);

	return err;
}

/**
 * mpc_mp_chown() - Change ownership of an mpool.
 * @unit: mpool unit ptr
 * @mps:
 *
 * Return:  Returns 0 if successful, errno via merr_t otherwise...
 */
static merr_t mpc_mp_chown(struct mpc_unit *unit, struct mpool_params *params)
{
	uid_t  uid;
	gid_t  gid;
	mode_t mode;
	int    rc = 0;

	if (!mpc_unit_ismpooldev(unit))
		return merr(EINVAL);

	uid  = params->mp_uid;
	gid  = params->mp_gid;
	mode = params->mp_mode;

	if (mode != -1)
		mode &= 0777;

	if (uid != -1 && uid != unit->un_uid && !capable(CAP_CHOWN))
		return merr(EPERM);

	if (gid != -1 && gid != unit->un_gid && !capable(CAP_CHOWN))
		return merr(EPERM);

	if (mode != -1 && mode != unit->un_mode && !capable(CAP_FOWNER))
		return merr(EPERM);

	if (-1 != uid)
		unit->un_uid = uid;
	if (-1 != gid)
		unit->un_gid = gid;
	if (-1 != mode)
		unit->un_mode = mode;

	if (uid != -1 || gid != -1 || mode != -1)
		rc = kobject_uevent(&unit->un_device->kobj, KOBJ_CHANGE);

	return merr(rc);
}

/**
 * mpioc_params_get() - get parameters of an activated mpool
 * @unit:   mpool device unit ptr
 * @cmd:    MPIOC_PARAMS_GET
 * @get:    mpool params
 *
 * MPIOC_PARAMS_GET ioctl handler to get mpool parameters
 *
 * Return:  Returns 0 if successful
 *          Returns merr_t otherwise...
 */
static merr_t
mpioc_params_get(struct mpc_unit *unit, uint cmd, struct mpioc_params *get)
{
	struct mpool_descriptor    *desc;
	struct mpc_softstate       *ss;
	struct mpool_params        *params;
	struct mpool_xprops         xprops = { };
	u8                          mclass;

	if (!mpc_unit_ismpooldev(unit))
		return merr(EINVAL);

	ss = unit->un_ss;
	desc = unit->un_mpool->mp_desc;

	mutex_lock(&ss->ss_lock);

	params = &get->mps_params;
	memset(params, 0, sizeof(*params));
	params->mp_uid = unit->un_uid;
	params->mp_gid = unit->un_gid;
	params->mp_mode = unit->un_mode;
	params->mp_mclassp = unit->un_ds_mclassp;
	params->mp_mdc_captgt = MPOOL_ROOT_LOG_CAP;
	params->mp_oidv[0] = unit->un_ds_oidv[0];
	params->mp_oidv[1] = unit->un_ds_oidv[1];
	params->mp_ra_pages_max = unit->un_ra_pages_max;
	params->mp_vma_size_max = mpc_vma_size_max;
	memcpy(&params->mp_utype, &unit->un_utype, sizeof(params->mp_utype));
	strlcpy(params->mp_label, unit->un_label, sizeof(params->mp_label));
	strlcpy(params->mp_name, unit->un_name, sizeof(params->mp_name));

	/* Get mpool properties..
	 */
	mpool_get_xprops(desc, &xprops);

	for (mclass = 0; mclass < MP_MED_NUMBER; mclass++)
		params->mp_mblocksz[mclass] =
			xprops.ppx_params.mp_mblocksz[mclass];

	params->mp_spare_cap = xprops.ppx_drive_spares[MP_MED_CAPACITY];
	params->mp_spare_stg = xprops.ppx_drive_spares[MP_MED_STAGING];

	memcpy(params->mp_poolid.b, xprops.ppx_params.mp_poolid.b,
	       MPOOL_UUID_SIZE);

	mutex_unlock(&ss->ss_lock);

	return 0;
}

/**
 * mpioc_params_set() - set parameters of an activated mpool
 * @unit:   control device unit ptr
 * @cmd:    MPIOC_PARAMS_SET
 * @set:    mpool params
 *
 * MPIOC_PARAMS_SET ioctl handler to set mpool parameters
 *
 * Return:  Returns 0 if successful
 *          Returns merr_t otherwise...
 */
static merr_t
mpioc_params_set(struct mpc_unit *unit, uint cmd, struct mpioc_params *set)
{
	struct mpool_descriptor    *mp;
	struct mpc_softstate       *ss;
	struct mpool_params        *params;
	struct mpioc_cmn           *cmn;

	uuid_le uuidnull = { };
	merr_t  rerr = 0, err = 0;
	bool    journal = false;

	if (!mpc_unit_ismpooldev(unit))
		return merr(EINVAL);

	ss = unit->un_ss;
	cmn = &set->mps_cmn;
	params = &set->mps_params;

	params->mp_vma_size_max = mpc_vma_size_max;

	mutex_lock(&ss->ss_lock);
	if (params->mp_uid != -1 || params->mp_gid != -1 ||
	    params->mp_mode != -1) {
		err = mpc_mp_chown(unit, params);
		if (ev(err)) {
			mutex_unlock(&ss->ss_lock);
			return err;
		}
		journal = true;
	}

	if (params->mp_label[0]) {
		mpc_toascii(params->mp_label, sizeof(params->mp_label));
		strlcpy(unit->un_label, params->mp_label,
			sizeof(unit->un_label));
		journal = true;
	}

	if (memcmp(&uuidnull, &params->mp_utype, sizeof(uuidnull))) {
		memcpy(&unit->un_utype, &params->mp_utype,
		       sizeof(unit->un_utype));
		journal = true;
	}

	if (params->mp_ra_pages_max != U32_MAX) {
		unit->un_ra_pages_max = clamp_t(u32, params->mp_ra_pages_max,
						0, MPOOL_RA_PAGES_MAX);
		journal = true;
	}

	if (journal)
		err = mpc_cf_journal(unit);
	mutex_unlock(&ss->ss_lock);

	if (ev(err)) {
		mpc_errinfo(cmn, MPOOL_RC_EIO, "mpool params commit metadata");
		return err;
	}

	mp = unit->un_mpool->mp_desc;

	if (params->mp_spare_cap != MPOOL_SPARES_INVALID) {
		err = mpool_drive_spares(mp, MP_MED_CAPACITY,
					 params->mp_spare_cap);
		if (ev(err) && merr_errno(err) != ENOENT)
			rerr = err;
	}

	if (params->mp_spare_stg != MPOOL_SPARES_INVALID) {
		err = mpool_drive_spares(mp, MP_MED_STAGING,
					 params->mp_spare_stg);
		if (ev(err) && merr_errno(err) != ENOENT)
			rerr = err;
	}

	return rerr;
}

/**
 * mpioc_mp_mclass_get() - get information regarding an mpool's mclasses
 * @unit:   control device unit ptr
 * @cmd:    MPIOC_MP_MCLASS_GET
 * @mcl:    mclass info struct
 *
 * MPIOC_MP_MCLASS_GET ioctl handler to get mclass information
 *
 * Return:  Returns 0 if successful
 *          Returns merr_t otherwise...
 */
static merr_t
mpioc_mp_mclass_get(struct mpc_unit *unit, uint cmd, struct mpioc_mclass *mcl)
{
	struct mpool_descriptor   *desc = unit->un_mpool->mp_desc;
	struct mpool_mclass_xprops mcxv[MP_MED_NUMBER];
	uint32_t                   mcxc = ARRAY_SIZE(mcxv);
	merr_t                     err;
	int                        rc;

	if (!mcl || !desc)
		return merr(EINVAL);

	if (!mcl->mcl_xprops) {
		mpool_mclass_get_cnt(desc, &mcl->mcl_cnt);
		return 0;
	}

	memset(mcxv, 0, sizeof(mcxv));

	err = mpool_mclass_get(desc, &mcxc, mcxv);
	if (err)
		return err;

	if (mcxc > mcl->mcl_cnt)
		mcxc = mcl->mcl_cnt;
	mcl->mcl_cnt = mcxc;

	rc = copy_to_user(mcl->mcl_xprops, mcxv, sizeof(mcxv[0]) * mcxc);

	return rc ? merr(EFAULT) : 0;
}

#define MPC_PARAMS_CNT     8

static merr_t mpc_params_register(struct mpc_unit *unit)
{
	struct ctl_table   *tab, *oid;
	merr_t              err;
	int                 compc, tabc, oidc;

	if (ev(!unit))
		return merr(EINVAL);

	compc = MPC_SYSCTL_RCNT + 2 * MPC_SYSCTL_DCNT;
	oidc  = MPC_PARAMS_CNT;
	tabc  = compc + oidc;

	tab = kcalloc(tabc, sizeof(*tab), GFP_KERNEL);
	if (ev(!tab))
		return merr(ENOMEM);

	oid = tab + compc;

	err = mpc_sysctl_path(tab, tab + MPC_SYSCTL_RCNT,
			      tab + MPC_SYSCTL_RCNT + MPC_SYSCTL_DCNT, oid,
			      unit->un_mpool->mp_name, MPC_SYSCTL_DMODE);
	if (ev(err))
		goto errout;

	mpc_sysctl_oid(oid++, "uid", 0444, &unit->un_uid,
		       sizeof(unit->un_uid), proc_dointvec);

	mpc_sysctl_oid(oid++, "gid", 0444, &unit->un_gid,
		       sizeof(unit->un_gid), proc_dointvec);

	mpc_sysctl_oid(oid++, "mode", 0444, &unit->un_mode,
		       sizeof(unit->un_mode), mpc_mode_proc_handler);

	mpc_sysctl_oid(oid++, "ra", 0444, &unit->un_ra_pages_max,
		       sizeof(unit->un_ra_pages_max), proc_douintvec);

	mpc_sysctl_oid(oid++, "label", 0444, &unit->un_label,
		       sizeof(unit->un_label), proc_dostring);

	mpc_sysctl_oid(oid++, "vma", 0444, &mpc_vma_size_max,
		       sizeof(mpc_vma_size_max), proc_douintvec);

	mpc_sysctl_oid(oid++, "type", 0444, unit->un_utype.b,
		       sizeof(unit->un_utype.b), mpc_uuid_proc_handler);

	unit->un_hdr = mpc_sysctl_register(tab);
	if (ev(!unit->un_hdr))
		goto errout;

	unit->un_tab = tab;

	return 0;

errout:
	kfree(tab);
	return err;
}

static void mpc_params_unregister(struct mpc_unit *unit)
{
	mpc_sysctl_unregister(unit->un_hdr);
	kfree(unit->un_tab);
}

/**
 * mpioc_mp_create() - create an mpool.
 * @mp:      mpool parameter block
 * @pd_prop:
 * @dpathv:
 *
 * MPIOC_MP_CREATE ioctl handler to create an mpool.
 *
 * Return:  Returns 0 if the mpool is created.
 *          Returns merr_t otherwise...
 */
static merr_t
mpioc_mp_create(
	struct mpc_unit      *ctl,
	struct mpioc_mpool   *mp,
	struct pd_prop       *pd_prop,
	char               ***dpathv)
{
	struct mpool_config          cfg = { };
	struct mpool_devrpt         *devrpt;
	struct mpcore_params         mpc_params;
	struct mpool_mdparm          mdparm;
	struct mpc_unit             *mpool_unit = NULL;
	struct mpc_mpool            *mpool      = NULL;
	size_t                       len;
	merr_t                       err;
	mode_t                       mode;
	uid_t                        uid;
	gid_t                        gid;

	if (!ctl || !mp || !pd_prop || !dpathv)
		return merr(EINVAL);

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return merr(len < 1 ? EINVAL : ENAMETOOLONG);

	devrpt = &mp->mp_devrpt;

	mpool_params_merge_defaults(&mp->mp_params);

	uid  = mp->mp_params.mp_uid;
	gid  = mp->mp_params.mp_gid;
	mode = mp->mp_params.mp_mode;

	if (uid == -1)
		uid = mpc_default_uid;
	if (gid == -1)
		gid = mpc_default_gid;
	if (mode == -1)
		mode = mpc_default_mode;

	mode &= 0777;

	if (uid != mpc_current_uid() && !capable(CAP_CHOWN)) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "chown permission denied");
		return merr(EPERM);
	}

	if (gid != mpc_current_gid() && !capable(CAP_CHOWN)) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "chown permission denied");
		return merr(EPERM);
	}

	if (!capable(CAP_SYS_ADMIN)) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "chmod/activate permission denied");
		return merr(EPERM);
	}

	mpool_to_mpcore_params(&mp->mp_params, &mpc_params);

	mdparm.mdp_mclassp = mp->mp_params.mp_mclassp;

	err = mpool_create(mp->mp_params.mp_name, mp->mp_flags, &mdparm,
			   *dpathv, pd_prop, &mpc_params, MPOOL_ROOT_LOG_CAP,
			   devrpt);
	if (err) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "%s: mpool %s, create failed",
			     __func__, mp->mp_params.mp_name);
		return err;
	}

	/*
	 * Create an mpc_mpool object through which we can (re)open and manage
	 * the mpool.  If successful, mpc_mpool_open() adopts dpathv.
	 */
	mpool_params_merge_defaults(&mp->mp_params);

	err = mpc_mpool_open(ctl->un_ss, mp->mp_dpathc,
			     *dpathv, &mpool, &mp->mp_devrpt, pd_prop,
			     &mp->mp_params, mp->mp_flags);
	if (err) {
		if (mp->mp_devrpt.mdr_off == -1)
			mpc_errinfo(&mp->mp_cmn, MPOOL_RC_STAT,
				    mp->mp_params.mp_name);
		mpool_destroy(mp->mp_dpathc, *dpathv, pd_prop, mp->mp_flags,
			      devrpt);
		goto errout;
	}

	*dpathv = NULL;

	mlog_lookup_rootids(&cfg.mc_oid1, &cfg.mc_oid2);
	cfg.mc_uid = uid;
	cfg.mc_gid = gid;
	cfg.mc_mode = mode;
	cfg.mc_mclassp = mdparm.mdp_mclassp;
	cfg.mc_captgt = MPOOL_ROOT_LOG_CAP;
	cfg.mc_ra_pages_max = mp->mp_params.mp_ra_pages_max;
	cfg.mc_vma_size_max = mp->mp_params.mp_vma_size_max;
	cfg.mc_rsvd1 = mp->mp_params.mp_rsvd1;
	cfg.mc_rsvd2 = mp->mp_params.mp_rsvd2;
	cfg.mc_rsvd3 = mp->mp_params.mp_rsvd3;
	cfg.mc_rsvd4 = mp->mp_params.mp_rsvd4;
	memcpy(&cfg.mc_utype, &mp->mp_params.mp_utype, sizeof(cfg.mc_utype));
	strlcpy(cfg.mc_label, mp->mp_params.mp_label, sizeof(cfg.mc_label));

	err = mpool_config_store(mpool->mp_desc, &cfg);
	if (err) {
		mp_pr_err("%s: %s config store failed",
			  err, __func__, mp->mp_params.mp_name);
		goto errout;
	}

	err = mpc_unit_setup(ctl->un_ss, &mpc_uinfo_mpool,
			     mp->mp_params.mp_name, &cfg,
			     mpool, &mpool_unit, &mp->mp_cmn);
	if (err) {
		mp_pr_err("%s unit setup failed", err, mp->mp_params.mp_name);
		goto errout;
	}

	/* Return resolved params to caller.
	 */
	mp->mp_params.mp_uid = uid;
	mp->mp_params.mp_gid = gid;
	mp->mp_params.mp_mode = mode;
	mp->mp_params.mp_mclassp = cfg.mc_mclassp;
	mp->mp_params.mp_mdc_captgt = cfg.mc_captgt;
	mp->mp_params.mp_oidv[0] = cfg.mc_oid1;
	mp->mp_params.mp_oidv[1] = cfg.mc_oid2;

	err = mpc_params_register(mpool_unit);
	if (ev(err))
		goto errout;

	mpool = NULL;

errout:
	if (mpool_unit)
		mpc_unit_put(mpool_unit); /* Release ctl device caller's ref */

	if (mpool)
		mpc_mpool_put(mpool);

	return err;
}

/**
 * mpioc_mp_activate() - activate an mpool.
 * @mp:      mpool parameter block
 * @pd_prop:
 * @dpathv:
 *
 * MPIOC_MP_ACTIVATE ioctl handler to activate an mpool.
 *
 * Return:  Returns 0 if the mpool is activated.
 *          Returns merr_t otherwise...
 */
static merr_t
mpioc_mp_activate(
	struct mpc_unit      *ctl,
	struct mpioc_mpool   *mp,
	struct pd_prop       *pd_prop,
	char               ***dpathv)
{
	struct mpool_config     cfg;
	struct mpc_mpool       *mpool      = NULL;
	struct mpc_unit        *mpool_unit = NULL;
	struct mpool_devrpt    *devrpt;
	merr_t                  err;
	size_t                  len;

	if (!capable(CAP_SYS_ADMIN))
		return merr(EPERM);

	if (!ctl || !mp || !pd_prop || !dpathv)
		return merr(EINVAL);

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return merr(len < 1 ? EINVAL : ENAMETOOLONG);

	devrpt = &mp->mp_devrpt;

	mpool_params_merge_defaults(&mp->mp_params);

	/*
	 * Create an mpc_mpool object through which we can (re)open and manage
	 * the mpool.  If successful, mpc_mpool_open() adopts dpathv.
	 */
	err = mpc_mpool_open(ctl->un_ss, mp->mp_dpathc,
			     *dpathv, &mpool, &mp->mp_devrpt, pd_prop,
			     &mp->mp_params, mp->mp_flags);
	if (err) {
		if (mp->mp_devrpt.mdr_off == -1)
			mpc_errinfo(&mp->mp_cmn, MPOOL_RC_STAT,
				    mp->mp_params.mp_name);
		goto errout;
	}

	*dpathv = NULL; /* Was adopted by successful mpc_mpool_open() */

	err = mpool_config_fetch(mpool->mp_desc, &cfg);
	if (err) {
		mp_pr_err("%s config fetch failed", err, mp->mp_params.mp_name);
		goto errout;
	}

	if (mpool_params_merge_config(&mp->mp_params, &cfg))
		mpool_config_store(mpool->mp_desc, &cfg);

	err = mpc_unit_setup(ctl->un_ss, &mpc_uinfo_mpool,
			     mp->mp_params.mp_name, &cfg,
			     mpool, &mpool_unit, &mp->mp_cmn);
	if (err) {
		mp_pr_err("%s unit setup failed", err, mp->mp_params.mp_name);
		goto errout;
	}

	/* Return resolved params to caller.
	 */
	mp->mp_params.mp_uid = cfg.mc_uid;
	mp->mp_params.mp_gid = cfg.mc_gid;
	mp->mp_params.mp_mode = cfg.mc_mode;
	mp->mp_params.mp_mclassp = cfg.mc_mclassp;
	mp->mp_params.mp_mdc_captgt = cfg.mc_captgt;
	mp->mp_params.mp_oidv[0] = cfg.mc_oid1;
	mp->mp_params.mp_oidv[1] = cfg.mc_oid2;
	mp->mp_params.mp_ra_pages_max = cfg.mc_ra_pages_max;
	mp->mp_params.mp_vma_size_max = cfg.mc_vma_size_max;
	memcpy(&mp->mp_params.mp_utype, &cfg.mc_utype,
	       sizeof(mp->mp_params.mp_utype));
	strlcpy(mp->mp_params.mp_label, cfg.mc_label,
		sizeof(mp->mp_params.mp_label));

	err = mpc_params_register(mpool_unit);
	if (ev(err))
		goto errout;

	mpool = NULL;

errout:
	if (mpool_unit)
		mpc_unit_put(mpool_unit); /* Release ctl device caller's ref */

	if (mpool)
		mpc_mpool_put(mpool);

	return err;
}

/**
 * mpioc_mp_deactivate() - deactivate an mpool.
 * @unit:   control device unit ptr
 * @mp:     mpool parameter block
 *
 * MPIOC_MP_DEACTIVATE ioctl handler to deactivate an mpool.
 */
static merr_t
mp_deactivate_impl(
	struct mpc_unit    *ctl,
	uint                cmd,
	struct mpioc_mpool *mp,
	bool                locked)
{
	struct mpc_softstate    *ss;
	struct mpc_unit        **unitv;
	struct mpc_unit         *mpunit = NULL;

	int     unitc, i, rc;
	merr_t  err = 0;
	size_t  len;

	if (!ctl || !mp)
		return merr(EINVAL);

	if (!mpc_unit_isctldev(ctl))
		return merr(ENOTTY);

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return merr(len < 1 ? EINVAL : ENAMETOOLONG);

	unitv = kmalloc_array(mpc_units_max, sizeof(*unitv), GFP_KERNEL);
	if (!unitv)
		return merr(ENOMEM);

	ss = ctl->un_ss;
	if (!locked) {
		rc = down_interruptible(&ss->ss_op_sema);
		if (rc) {
			kfree(unitv);
			return merr(rc);
		}
	}

	mpc_unit_lookup_by_name(ctl, mp->mp_params.mp_name, &mpunit);
	if (!mpunit) {
		err = merr(ENXIO);
		goto err_exit;
	}

	unitc = 0;
	err = 0;

	/* The following loop builds a list of all the units in the given
	 * mpool.  If they all appear to be idle, then they all are removed
	 * from the units table and released.  If any one appears to be in
	 * use, then no state changes occur and we simply return an error.
	 *
	 * In order to be determined idle, a unit shall not be open nor in
	 * a transient state, and shall have a ref count no greater than
	 * one, with the following exceptions:
	 *
	 * - An idle mpool unit will have an additional reference because
	 * we acquired one via mpc_unit_lookup_by_name() (above).
	 */
	mutex_lock(&ss->ss_lock);
	for (i = ss->ss_units_max - 1; i >= 0; --i) {
		struct mpc_unit    *un = ss->ss_unitv[i];
		int                 reftgt = 1;

		if (!un || un->un_mpool != mpunit->un_mpool)
			continue;

		if (mpc_unit_ismpooldev(un))
			++reftgt;

		/* If the unit is not idle we set unitc to zero to prevent
		 * the ensuing loops from making any state changes.
		 */
		if (un->un_open_cnt > 0 || un->un_refcnt > reftgt ||
		    un->un_transient) {
			mpc_errinfo(&mp->mp_cmn, MPOOL_RC_STAT, un->un_name);
			err = merr(EBUSY);
			unitc = 0;
			break;
		}

		unitv[unitc++] = un;
	}

	for (i = 0; i < unitc; ++i)
		ss->ss_unitv[MINOR(unitv[i]->un_devno)] = NULL;
	mutex_unlock(&ss->ss_lock);

	for (i = 0; i < unitc; ++i)
		mpc_unit_put(unitv[i]); /* release birth ref */

	dev_dbg(mpunit->un_device,
		"mpool %s deactivated, %d units",
		mp->mp_params.mp_name, unitc);

	mpc_params_unregister(mpunit);

	mpc_unit_put(mpunit);

err_exit:
	if (!locked)
		up(&ss->ss_op_sema);

	kfree(unitv);

	return err;
}

static merr_t
mpioc_mp_deactivate(struct mpc_unit *ctl, uint cmd, struct mpioc_mpool *mp)
{
	return mp_deactivate_impl(ctl, cmd, mp, false);
}

static merr_t
mpioc_mp_cmd(struct mpc_unit *ctl, uint cmd, struct mpioc_mpool *mp)
{
	struct mpc_softstate   *ss;
	struct mpc_unit        *mpool_unit = NULL;
	struct pd_prop         *pd_prop    = NULL;
	char                  **dpathv     = NULL;
	struct mpool_devrpt    *devrpt;
	merr_t                  err = 0;
	size_t                  dpathvsz;
	char                   *dpaths;
	int                     rc, i;
	u64                     pd_prop_sz;
	const char             *action;
	size_t                  len;

	if (ev(!ctl || !mp))
		return merr(EINVAL);

	if (ev(!mpc_unit_isctldev(ctl)))
		return merr(ENOTSUPP);

	if (ev(mp->mp_dpathc < 1 || mp->mp_dpathc > MPOOL_DRIVES_MAX))
		return merr(EDOM);

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return merr(len < 1 ? EINVAL : ENAMETOOLONG);

	devrpt = &mp->mp_devrpt;

	switch (cmd) {
	case MPIOC_MP_CREATE:
		action = "create";
		break;

	case MPIOC_MP_DESTROY:
		action = "destroy";
		break;

	case MPIOC_MP_ACTIVATE:
		action = "activate";
		break;

	case MPIOC_MP_RENAME:
		action = "rename";
		break;

	default:
		return merr(EINVAL);
	}

	if (!mp->mp_pd_prop || !mp->mp_dpaths) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool %s, %s: (%d drives), drives names %p or PDs properties %p not provided",
			     mp->mp_params.mp_name, action, mp->mp_dpathc,
			     mp->mp_dpaths, mp->mp_pd_prop);

		return merr(EINVAL);
	}

	if (ev(mp->mp_dpathssz > (mp->mp_dpathc + 1) * PATH_MAX))
		return merr(EINVAL);

	ss = ctl->un_ss;
	rc = down_interruptible(&ss->ss_op_sema);
	if (rc)
		return merr(rc);

	/* If mpc_unit_lookup_by_name() succeeds it will have acquired
	 * a reference on mpool_unit.  We release that reference at the
	 * end of this function by calling mpc_unit_put().
	 */
	mpc_unit_lookup_by_name(ctl, mp->mp_params.mp_name, &mpool_unit);

	if (mpool_unit && cmd != MPIOC_MP_DESTROY) {
		if (cmd == MPIOC_MP_ACTIVATE)
			goto errout;
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "already activated");
		err = merr(EEXIST);
		goto errout;
	}

	/* The device path names are in one long string separated by
	 * newlines.  Here we allocate one chunk of memory to hold
	 * all the device paths and a vector of ptrs to them.
	 */
	dpathvsz = mp->mp_dpathc * sizeof(*dpathv) + mp->mp_dpathssz;
	if (dpathvsz > MPOOL_DRIVES_MAX * (PATH_MAX + sizeof(*dpathv))) {
		mpc_errinfo(&mp->mp_cmn, MPCTL_RC_TOOMANY, "member drives");
		err = merr(E2BIG);
		goto errout;
	}

	dpathv = kmalloc(dpathvsz, GFP_KERNEL);
	if (!dpathv) {
		err = merr(ENOMEM);
		goto errout;
	}

	dpaths = (char *)dpathv + mp->mp_dpathc * sizeof(*dpathv);

	rc = copy_from_user(dpaths, mp->mp_dpaths, mp->mp_dpathssz);
	if (rc) {
		err = merr(EFAULT);
		goto errout;
	}

	for (i = 0; i < mp->mp_dpathc; ++i) {
		dpathv[i] = strsep(&dpaths, "\n");
		if (!dpathv[i]) {
			err = merr(EINVAL);
			goto errout;
		}
	}

	/* Get the PDs properties from user space buffer. */
	pd_prop_sz = mp->mp_dpathc * sizeof(*pd_prop);
	pd_prop = kmalloc(pd_prop_sz, GFP_KERNEL);
	if (!pd_prop) {
		mpool_devrpt(&mp->mp_devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool %s, %s: pd prop alloc %zu failed",
			     mp->mp_params.mp_name, action, pd_prop_sz);
		err = merr(ENOMEM);
		goto errout;
	}

	rc = copy_from_user(pd_prop, mp->mp_pd_prop, pd_prop_sz);
	if (rc) {
		mpool_devrpt(&mp->mp_devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool %s, %s: pd prop %zu copyin failed",
			     mp->mp_params.mp_name, action, pd_prop_sz);
		err = merr(EFAULT);
		goto errout;
	}

	switch (cmd) {
	case MPIOC_MP_CREATE:
		err = mpioc_mp_create(ctl, mp, pd_prop, &dpathv);
		break;

	case MPIOC_MP_ACTIVATE:
		err = mpioc_mp_activate(ctl, mp, pd_prop, &dpathv);
		break;

	case MPIOC_MP_DESTROY:
		if (mpool_unit) {
			mpc_unit_put(mpool_unit);
			mpool_unit = NULL;

			err = mp_deactivate_impl(ctl, cmd, mp, true);
			if (ev(err)) {
				action = "deactivate";
				break;
			}
		}
		err = mpool_destroy(mp->mp_dpathc, dpathv, pd_prop,
				    mp->mp_flags, &mp->mp_devrpt);
		break;

	case MPIOC_MP_RENAME:
		err = mpool_rename(mp->mp_dpathc, dpathv, pd_prop,
				   mp->mp_flags, mp->mp_params.mp_name,
				   &mp->mp_devrpt);
		break;
	}

	if (ev(err))
		mpool_devrpt(&mp->mp_devrpt, MPOOL_RC_ERRMSG, -1,
			     "mpool %s, %s failed",
			     mp->mp_params.mp_name, action);

errout:
	if (mpool_unit)
		mpc_unit_put(mpool_unit);

	up(&ss->ss_op_sema);

	kfree(pd_prop);
	kfree(dpathv);

	return err;
}

/**
 * mpioc_prop_get() - Get mpool properties.
 * @unit:   mpool unit ptr
 * @cmd:    MPIOC_PROP_GET
 *
 * MPIOC_PROP_GET ioctl handler to retrieve properties for the specified device.
 */
static void
mpioc_prop_get(struct mpc_unit *unit, struct mpioc_prop *kprop, int cmd)
{
	struct mpool_descriptor    *desc = unit->un_mpool->mp_desc;
	struct mpool_params        *params;
	struct mpool_xprops        *xprops;

	memset(kprop, 0, sizeof(*kprop));

	/* Get unit properties..
	 */
	params = &kprop->pr_xprops.ppx_params;
	params->mp_uid = unit->un_uid;
	params->mp_gid = unit->un_gid;
	params->mp_mode = unit->un_mode;
	params->mp_mclassp = unit->un_ds_mclassp;
	params->mp_mdc_captgt = unit->un_mdc_captgt;
	params->mp_oidv[0] = unit->un_ds_oidv[0];
	params->mp_oidv[1] = unit->un_ds_oidv[1];
	params->mp_ra_pages_max = unit->un_ra_pages_max;
	params->mp_vma_size_max = mpc_vma_size_max;
	memcpy(&params->mp_utype, &unit->un_utype, sizeof(params->mp_utype));
	strlcpy(params->mp_label, unit->un_label, sizeof(params->mp_label));
	strlcpy(params->mp_name, unit->un_name, sizeof(params->mp_name));

	/* Get mpool properties..
	 */
	xprops = &kprop->pr_xprops;
	mpool_get_xprops(desc, xprops);
	mpool_get_usage(desc, MCLASS_ALL, &kprop->pr_usage);

	params->mp_spare_cap = xprops->ppx_drive_spares[MP_MED_CAPACITY];
	params->mp_spare_stg = xprops->ppx_drive_spares[MP_MED_STAGING];

	kprop->pr_mcxc = ARRAY_SIZE(kprop->pr_mcxv);
	mpool_mclass_get(desc, &kprop->pr_mcxc, kprop->pr_mcxv);
}

/**
 * mpioc_devprops_get() - Get device properties
 * @unit:   mpool unit ptr
 *
 * MPIOC_PROP_GET ioctl handler to retrieve properties for the specified device.
 */
static merr_t
mpioc_devprops_get(struct mpc_unit *unit, struct mpioc_devprops *devprops)
{
	merr_t err = 0;

	if (unit->un_mpool) {
		struct mpool_descriptor *mp = unit->un_mpool->mp_desc;

		err = mpool_get_devprops_by_name(mp, devprops->dpr_pdname,
						 &devprops->dpr_devprops);
	}

	return ev(err);
}

/**
 * mpioc_proplist_get_itercb() - Get properties iterator callback.
 * @unit:   mpool or dataset unit ptr
 * @arg:    argument list
 *
 * Return:  Returns ITERCB_DONE when the iteratior is complete or an
 *          error is encountered (erroris returned in argv[3]).
 *          Returns ITERCB_NEXT to continue the iteration.
 */
static int
mpioc_proplist_get_itercb(struct mpc_unit *unit, void *arg)
{
	struct mpioc_prop  *uprop, kprop;
	struct mpc_unit    *match;
	struct mpioc_list  *ls;
	void              **argv = arg;
	int                *cntp, rc;
	merr_t             *errp;

	match = argv[0];
	ls = argv[1];

	if (mpc_unit_isctldev(match) && !mpc_unit_ismpooldev(unit) &&
	    ls->ls_cmd != MPIOC_LIST_CMD_PROP_GET)
		return ITERCB_NEXT;

	if (mpc_unit_ismpooldev(match) && !mpc_unit_ismpooldev(unit) &&
	    ls->ls_cmd != MPIOC_LIST_CMD_PROP_GET)
		return ITERCB_NEXT;

	if (mpc_unit_ismpooldev(match) && unit->un_mpool != match->un_mpool)
		return ITERCB_NEXT;

	cntp = argv[2];
	errp = argv[3];

	mpioc_prop_get(unit, &kprop, ls->ls_cmd);

	uprop = (struct mpioc_prop *)ls->ls_listv + *cntp;

	rc = copy_to_user(uprop, &kprop, sizeof(*uprop));
	if (rc) {
		*errp = merr(EFAULT);
		return ITERCB_DONE;
	}

	return (++(*cntp) >= ls->ls_listc) ? ITERCB_DONE : ITERCB_NEXT;
}

/**
 * mpioc_proplist_get() - Get mpool or dataset properties.
 * @unit:   mpool or dataset unit ptr
 * @cmd     MPIOC_PROP_GET
 * @ls:     properties parameter block
 *
 * MPIOC_PROP_GET ioctl handler to retrieve properties for one or all mpools
 * or datasets.
 *
 * Return:  Returns 0 if successful, errno via merr_t otherwise...
 */
static merr_t
mpioc_proplist_get(struct mpc_unit *unit, uint cmd, struct mpioc_list *ls)
{
	merr_t      err = 0;
	int         cnt = 0;
	void       *argv[] = { unit, ls, &cnt, &err };

	if (!ls || ls->ls_listc < 1 || ls->ls_cmd == MPIOC_LIST_CMD_INVALID)
		return merr(EINVAL);

	mpc_unit_iterate(unit->un_ss, 0, mpioc_proplist_get_itercb, argv);

	ls->ls_listc = cnt;

	return err;
}

/**
 * mpioc_mb_alloc() - Allocate an mblock object.
 * @unit:   mpool or dataset unit ptr
 * @mb:     mblock parameter block
 *
 * MPIOC_MB_ALLOC ioctl handler to allocate a single mblock.
 *
 * Return:  Returns 0 if successful, errno via merr_t otherwise...
 */
static merr_t
mpioc_mb_alloc(struct mpc_unit *unit, struct mpioc_mblock *mb)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;
	struct mblock_props         props;
	merr_t                      err;

	if (!unit || !mb || !unit->un_mpool)
		return merr(EINVAL);

	mpool = unit->un_mpool->mp_desc;

	err = mblock_alloc(mpool, mb->mb_mclassp, mb->mb_spare,
			   &mblock, &props);
	if (ev(err))
		return err;

	mblock_get_props_ex(mpool, mblock, &mb->mb_props);
	mblock_put(mpool, mblock);

	mb->mb_objid  = props.mpr_objid;
	mb->mb_offset = -1;

	return 0;
}

/**
 * mpioc_mb_find() - Find an mblock object by its objid
 * @unit:   mpool or dataset unit ptr
 * @mb:     mblock parameter block
 *
 * Return:  Returns 0 if successful, errno via merr_t otherwise...
 */
static merr_t
mpioc_mb_find(struct mpc_unit *unit, struct mpioc_mblock *mb)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;
	merr_t                      err;

	if (!unit || !mb || !unit->un_mpool)
		return merr(EINVAL);

	if (!mblock_objid(mb->mb_objid))
		return merr(EINVAL);

	mpool = unit->un_mpool->mp_desc;

	err = mblock_find_get(mpool, mb->mb_objid, 0, NULL, &mblock);
	if (ev(err))
		return err;

	(void)mblock_get_props_ex(mpool, mblock, &mb->mb_props);

	mblock_put(mpool, mblock);

	mb->mb_offset = -1;

	return 0;
}

/**
 * mpioc_mb_abcomdel() - Abort, commit, or delete an mblock.
 * @unit:   mpool or dataset unit ptr
 * @cmd     MPIOC_MB_ABORT, MPIOC_MB_COMMIT, or MPIOC_MB_DELETE
 * @mi:     mblock parameter block
 *
 * MPIOC_MB_ACD ioctl handler to either abort, commit, or delete
 * the specified mblock.
 *
 * Return:  Returns 0 if successful, errno via merr_t otherwise...
 */
static merr_t
mpioc_mb_abcomdel(struct mpc_unit *unit, uint cmd, struct mpioc_mblock_id *mi)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;

	int     which;
	bool    drop;
	merr_t  err;

	if (!unit || !mi || !unit->un_mpool)
		return merr(EINVAL);

	if (!mblock_objid(mi->mi_objid))
		return merr(EINVAL);

	which = (cmd == MPIOC_MB_DELETE) ? 1 : -1;
	mpool = unit->un_mpool->mp_desc;
	drop = true;

	err = mblock_find_get(mpool, mi->mi_objid, which, NULL, &mblock);
	if (ev(err))
		return err;

	switch (cmd) {
	case MPIOC_MB_COMMIT:
		err = mblock_commit(mpool, mblock);
		break;

	case MPIOC_MB_ABORT:
		err = mblock_abort(mpool, mblock);
		drop = !!err;
		break;

	case MPIOC_MB_DELETE:
		err = mblock_delete(mpool, mblock);
		drop = !!err;
		break;

	default:
		err = merr(ENOTTY);
		break;
	}

	if (drop)
		mblock_put(mpool, mblock);

	return err;
}

/**
 * mpioc_mb_rw() - read/write mblock ioctl handler
 * @unit:   dataset unit ptr
 * @cmd:    MPIOC_MB_READ or MPIOC_MB_WRITE
 * @mbiov:  mblock parameter block
 */
__attribute__((__noinline__))
static merr_t
mpioc_mb_rw(struct mpc_unit *unit, uint cmd, struct mpioc_mblock_rw *mbrw,
	    void *stkbuf, size_t stkbufsz)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;
	struct iovec               *kiov;

	bool    xfree = false;
	int     which;
	size_t  kiovsz;
	merr_t  err;

	if (!unit || !mbrw || !unit->un_mpool)
		return merr(EINVAL);

	if (!mblock_objid(mbrw->mb_objid))
		return merr(EINVAL);

	/* For small iovec counts we simply copyin the array of iovecs
	 * to local storage (stkbuf).  Otherwise, we must kmalloc a
	 * buffer into which to perform the copyin.
	 */
	if (mbrw->mb_iov_cnt > MPIOC_KIOV_MAX)
		return merr(EINVAL);

	kiovsz = mbrw->mb_iov_cnt * sizeof(*kiov);

	if (kiovsz > stkbufsz) {
		kiov = kmalloc(kiovsz, GFP_KERNEL);
		if (!kiov)
			return merr(ENOMEM);

		xfree = true;
	} else {
		kiov = stkbuf;
		stkbuf += kiovsz;
		stkbufsz -= kiovsz;
	}

	which = (cmd == MPIOC_MB_READ) ? 1 : -1;
	mpool = unit->un_mpool->mp_desc;

	err = mblock_find_get(mpool, mbrw->mb_objid, which, NULL, &mblock);
	if (err)
		goto errout;

	if (copy_from_user(kiov, mbrw->mb_iov, kiovsz)) {
		err = merr(EFAULT);
	} else {
		err = mpc_physio(mpool, mblock,
				 kiov, mbrw->mb_iov_cnt, mbrw->mb_offset,
				 MP_OBJ_MBLOCK,
				 (cmd == MPIOC_MB_READ) ? READ : WRITE,
				 stkbuf, stkbufsz);
	}

	mblock_put(mpool, mblock);

errout:
	if (xfree)
		kfree(kiov);

	return err;
}

/**
 * mpioc_mb_props() - mblock getprops ioctl handler
 * @unit: dataset unit ptr
 * @mb:   mblock parameter block
 */
static merr_t
mpioc_mb_props(struct mpc_unit *unit, struct mpioc_mblock *mb)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;
	merr_t                      err;

	if (!unit || !unit->un_mpool || !mb)
		return merr(EINVAL);

	if (!mblock_objid(mb->mb_objid))
		return merr(EINVAL);

	mpool = unit->un_mpool->mp_desc;

	err = mblock_find_get(mpool, mb->mb_objid, 0, NULL, &mblock);
	if (!err) {
		err = mblock_get_props_ex(mpool, mblock, &mb->mb_props);
		mblock_put(mpool, mblock);
	}

	return err;
}

/*
 * Mpctl mlog ioctl handlers
 */
merr_t
mpioc_mlog_alloc(struct mpc_unit *unit, uint cmd, struct mpioc_mlog *ml)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct mlog_props           props;
	merr_t                      err;

	if (!unit || !unit->un_mpool || !ml)
		return merr(EINVAL);

	mpool = unit->un_mpool->mp_desc;

	switch (cmd) {
	case MPIOC_MLOG_ALLOC:
		err = mlog_alloc(mpool, &ml->ml_cap, ml->ml_mclassp,
				 &props, &mlog);
		break;

	case MPIOC_MLOG_REALLOC:
		err = mlog_realloc(mpool, ml->ml_objid, &ml->ml_cap,
				   ml->ml_mclassp, &props, &mlog);
		break;

	default:
		err = merr(EINVAL);
		break;
	}

	if (ev(err))
		return err;

	mlog_get_props_ex(mpool, mlog, &ml->ml_props);
	mlog_put(mpool, mlog);

	ml->ml_objid = props.lpr_objid;

	return 0;
}

merr_t mpioc_mlog_find(struct mpc_unit *unit, uint cmd, struct mpioc_mlog *ml)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	merr_t                      err;

	if (!unit || !unit->un_mpool || !ml || !mlog_objid(ml->ml_objid))
		return merr(EINVAL);

	mpool = unit->un_mpool->mp_desc;

	err = mlog_find_get(mpool, ml->ml_objid, 0, NULL, &mlog);
	if (!err) {
		err = mlog_get_props_ex(mpool, mlog, &ml->ml_props);
		mlog_put(mpool, mlog);
	}

	return err;
}

merr_t
mpioc_mlog_abcomdel(struct mpc_unit *unit, uint cmd, struct mpioc_mlog_id *mi)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct mlog_props_ex        props;
	int                         which;
	bool                        drop;
	merr_t                      err;

	if (!unit || !unit->un_mpool || !mi || !mlog_objid(mi->mi_objid))
		return merr(EINVAL);

	which = (cmd == MPIOC_MLOG_DELETE) ? 1 : -1;
	mpool = unit->un_mpool->mp_desc;
	drop = true;

	err = mlog_find_get(mpool, mi->mi_objid, which, NULL, &mlog);
	if (err)
		return err;

	switch (cmd) {
	case MPIOC_MLOG_COMMIT:
		err = mlog_commit(mpool, mlog);
		if (!err) {
			mlog_get_props_ex(mpool, mlog, &props);
			mi->mi_gen   = props.lpx_props.lpr_gen;
			mi->mi_state = props.lpx_state;
		}
		break;

	case MPIOC_MLOG_ABORT:
		err = mlog_abort(mpool, mlog);
		drop = !!err;
		break;

	case MPIOC_MLOG_DELETE:
		err = mlog_delete(mpool, mlog);
		drop = !!err;
		break;

	default:
		err = merr(ENOTTY);
		break;
	}

	if (drop)
		mlog_put(mpool, mlog);

	return err;
}

__attribute__((__noinline__))
merr_t mpioc_mlog_rw(struct mpc_unit *unit, struct mpioc_mlog_io *mi,
		     void *stkbuf, size_t stkbufsz)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct iovec               *kiov;

	bool    xfree = false;
	size_t  kiovsz;
	merr_t  err;

	if (!unit || !unit->un_mpool || !mi || !mlog_objid(mi->mi_objid))
		return merr(EINVAL);

	/* For small iovec counts we simply copyin the array of iovecs
	 * to the the stack (kiov_buf). Otherwise, we must kmalloc a
	 * buffer into which to perform the copyin.
	 */
	if (mi->mi_iovc > MPIOC_KIOV_MAX)
		return merr(EINVAL);

	kiovsz = mi->mi_iovc * sizeof(*kiov);

	if (kiovsz > stkbufsz) {
		kiov = kmalloc(kiovsz, GFP_KERNEL);
		if (!kiov)
			return merr(ENOMEM);

		xfree = true;
	} else {
		kiov = stkbuf;
		stkbuf += kiovsz;
		stkbufsz -= kiovsz;
	}

	mpool = unit->un_mpool->mp_desc;

	err = mlog_find_get(mpool, mi->mi_objid, 1, NULL, &mlog);
	if (err)
		goto errout;

	if (copy_from_user(kiov, mi->mi_iov, kiovsz)) {
		err = merr(EFAULT);
	} else {
		err = mpc_physio(mpool, mlog, kiov,
				 mi->mi_iovc, mi->mi_off, MP_OBJ_MLOG,
				 (mi->mi_op == MPOOL_OP_READ) ? READ : WRITE,
				 stkbuf, stkbufsz);
	}

	mlog_put(mpool, mlog);

errout:
	if (xfree)
		kfree(kiov);

	return err;
}

merr_t mpioc_mlog_erase(struct mpc_unit *unit, struct mpioc_mlog_id *mi)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct mlog_props_ex        props;
	merr_t                      err;

	if (!unit || !unit->un_mpool || !mi || !mlog_objid(mi->mi_objid))
		return merr(EINVAL);

	mpool = unit->un_mpool->mp_desc;

	err = mlog_find_get(mpool, mi->mi_objid, 0, NULL, &mlog);
	if (err)
		return err;

	err = mlog_erase(mpool, mlog, mi->mi_gen);
	if (!err) {
		mlog_get_props_ex(mpool, mlog, &props);
		mi->mi_gen   = props.lpx_props.lpr_gen;
		mi->mi_state = props.lpx_state;
	}

	mlog_put(mpool, mlog);

	return err;
}

/**
 * mpioc_vma_create() - create an mpctl map
 * @unit:
 * @arg:
 */
static merr_t mpioc_vma_create(struct mpc_unit *unit, struct mpioc_vma *vma)
{
	struct mpool_descriptor    *mpdesc;
	struct mpc_metamap         *mm;
	struct mpc_mbinfo          *mbinfov;
	struct kmem_cache          *cache;
	struct mpc_vma             *meta;

	u64     *mbidv;
	size_t  largest, sz;
	uint    mbidc, mult;
	merr_t  err;
	int     rc, i;

	if (ev(!unit || !unit->un_mapping || !vma))
		return merr(EINVAL);

	if (vma->im_mbidc < 1)
		return merr(EINVAL);

	if (vma->im_advice > MPC_VMA_PINNED)
		return merr(EINVAL);

	mult = 1;
	if (vma->im_advice == MPC_VMA_WARM)
		mult = 10;
	else if (vma->im_advice == MPC_VMA_HOT)
		mult = 100;

	mpdesc = unit->un_mpool->mp_desc;
	mbidc = vma->im_mbidc;

	sz = sizeof(*meta) + sizeof(*mbinfov) * mbidc;
	if (sz > mpc_vma_cachesz[1])
		return merr(EINVAL);
	else if (sz > mpc_vma_cachesz[0])
		cache = mpc_vma_cache[1];
	else
		cache = mpc_vma_cache[0];

	sz = mbidc * sizeof(mbidv[0]);

	mbidv = kmalloc(sz, GFP_KERNEL);
	if (!mbidv)
		return merr(ENOMEM);

	rc = copy_from_user(mbidv, vma->im_mbidv, sz);
	if (rc) {
		kfree(mbidv);
		return merr(EFAULT);
	}

	meta = kmem_cache_zalloc(cache, GFP_KERNEL);
	if (!meta) {
		kfree(mbidv);
		return merr(ENOMEM);
	}

	meta->mcm_mbinfoc = mbidc;
	meta->mcm_mpdesc = unit->un_mpool->mp_desc;
	meta->mcm_metamap = unit->un_metamap;
	meta->mcm_unit = unit;
	meta->mcm_advice = vma->im_advice;
	meta->mcm_magic = (u32)(uintptr_t)meta;

	atomic_set(&meta->mcm_evicting, 0);
	atomic_set(&meta->mcm_reapref, 1);
	atomic_set(&meta->mcm_rabusy, 0);
	INIT_LIST_HEAD(&meta->mcm_list);
	atomic64_set(&meta->mcm_nrpages, 0);
	meta->mcm_mapping = unit->un_mapping;
	meta->mcm_cache = cache;

	largest = 0;
	err = 0;

	mbinfov = meta->mcm_mbinfov;

	for (i = 0; i < mbidc; ++i) {
		struct mpc_mbinfo *mbinfo = mbinfov + i;
		struct mblock_props props;

		err = mblock_find_get(mpdesc, mbidv[i], 1,
				      &props, &mbinfo->mbdesc);
		if (err) {
			mbidc = i;
			goto errout;
		}

		mbinfo->mblen = ALIGN(props.mpr_write_len, PAGE_SIZE);
		mbinfo->mbmult = mult;
		atomic64_set(&mbinfo->mbatime, 0);

		largest = max_t(size_t, largest, mbinfo->mblen);
	}

	meta->mcm_bktsz = roundup_pow_of_two(largest);

	if (meta->mcm_bktsz * mbidc > (1ul << mpc_vma_size_max)) {
		err = merr(E2BIG);
		goto errout;
	}

	mm = unit->un_metamap;

	idr_preload(GFP_KERNEL);

	mutex_lock(&mm->mm_rgnlock);
	meta->mcm_rgn = idr_alloc(&mm->mm_rgnmap, NULL, 1, -1, GFP_ATOMIC);
	if (meta->mcm_rgn < 1) {
		mutex_unlock(&mm->mm_rgnlock);

		err = merr(meta->mcm_rgn ?: EINVAL);
		idr_preload_end();
		goto errout;
	}

	vma->im_offset = (ulong)meta->mcm_rgn << mpc_vma_size_max;
	vma->im_bktsz = meta->mcm_bktsz;
	vma->im_len = meta->mcm_bktsz * mbidc;
	vma->im_len = ALIGN(vma->im_len, (1ul << mpc_vma_size_max));

	atomic_inc(&mm->mm_refcnt);

	idr_replace(&mm->mm_rgnmap, meta, meta->mcm_rgn);
	mutex_unlock(&mm->mm_rgnlock);

	idr_preload_end();

errout:
	if (err) {
		for (i = 0; i < mbidc; ++i)
			mblock_put(mpdesc, mbinfov[i].mbdesc);
		kmem_cache_free(cache, meta);
	}

	kfree(mbidv);

	return err;
}

/**
 * mpioc_vma_destroy() - destroy an mpctl map that is not in use
 * @unit:
 * @arg:
 */
static merr_t mpioc_vma_destroy(struct mpc_unit *unit, struct mpioc_vma *vma)
{
	struct mpc_vma *meta;
	u64             rgn;

	if (ev(!unit || !vma))
		return merr(EINVAL);

	rgn = vma->im_offset >> mpc_vma_size_max;

	meta = mpc_vma_lookup(unit->un_metamap, rgn);
	if (!meta)
		return merr(ENOENT);

	mpc_vma_put(meta);

	return 0;
}

static merr_t mpioc_vma_purge(struct mpc_unit *unit, struct mpioc_vma *vma)
{
	struct mpc_vma *meta;
	u64             rgn;

	if (ev(!unit || !vma))
		return merr(EINVAL);

	rgn = vma->im_offset >> mpc_vma_size_max;

	meta = mpc_vma_lookup(unit->un_metamap, rgn);
	if (!meta)
		return merr(ENOENT);

	mpc_reap_vma_evict(meta);

	mpc_vma_put(meta);

	return 0;
}

static merr_t mpioc_vma_vrss(struct mpc_unit *unit, struct mpioc_vma *vma)
{
	struct mpc_vma *meta;
	u64             rgn;

	if (ev(!unit || !vma))
		return merr(EINVAL);

	rgn = vma->im_offset >> mpc_vma_size_max;

	meta = mpc_vma_lookup(unit->un_metamap, rgn);
	if (!meta)
		return merr(ENOENT);

	vma->im_vssp = mpc_vma_pglen(meta);
	vma->im_rssp = atomic64_read(&meta->mcm_nrpages);

	mpc_vma_put(meta);

	return 0;
}

static merr_t mpioc_test(struct mpc_unit *unit, struct mpioc_test *test)
{
	merr_t err = 0;

	if (ev(!unit || !test))
		return merr(EINVAL);

	switch (test->mpt_cmd) {
	case 0:
		test->mpt_sval[1] = merr((int)test->mpt_sval[0]);
		err = test->mpt_sval[1];
		break;

	default:
		err = merr(EINVAL);
		break;
	}

	return err;
}

/**
 * mpc_ioctl() - mpc driver ioctl entry point
 * @fp:     file pointer
 * @cmd:    an mpool ioctl command (i.e.,  MPIOC_*)
 * @arg:    varies..
 *
 * Perform the specified mpool ioctl command.  The MPIOC_* command
 * handlers return an merr_t which we save in the common area of
 * the command's parameter block (if possible).  In this case,
 * mpc_ioctl() returns zero and the caller must examine the merr_t
 * to determine the actual result.  If the ioctl call fails for any
 * other reason, then -errno is returned and the state of merr_t
 * cannot be relied upon by the caller.
 *
 * Return:  Returns 0 on success, -errno otherwise...
 */
static long mpc_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	union mpioc_union   argbuf;
	struct mpc_unit    *unit;

	void       *argp, *stkbuf = NULL;
	size_t      stkbufsz = 0;
	merr_t      err;
	ulong       iosz;
	int         rc;

	unit = fp->private_data;

	if (_IOC_TYPE(cmd) != MPIOC_MAGIC)
		return ev(-ENOTTY);

	if ((fp->f_flags & O_ACCMODE) == O_RDONLY) {
		switch (cmd) {
		case MPIOC_PROP_GET:
		case MPIOC_DEVPROPS_GET:
		case MPIOC_MB_FIND:
		case MPIOC_MB_READ:
		case MPIOC_MP_MCLASS_GET:
		case MPIOC_MLOG_FIND:
		case MPIOC_MLOG_READ:
		case MPIOC_MLOG_PROPS:
		case MPIOC_TEST:
			break;

		default:
			return ev(-EBADF);
		}
	}

	iosz = _IOC_SIZE(cmd);
	argp = (void *)arg;

	if (iosz > sizeof(argbuf))
		return -EINVAL;

	/* Copy in write requests, and reject requests that won't
	 * fit comfortably on the stack (i.e., larger than argbuf).
	 */
	if (_IOC_DIR(cmd) & (_IOC_READ | _IOC_WRITE)) {
		if (iosz < sizeof(struct mpioc_cmn))
			return -EINVAL;

		argp = &argbuf;

		if (_IOC_DIR(cmd) & _IOC_WRITE) {
			if (copy_from_user(argp, (void *)arg, iosz))
				return ev(-EFAULT);

			if (argbuf.mpu_cmn.mc_rcode || argbuf.mpu_cmn.mc_err)
				return -EINVAL;
		} else {
			memset(&argbuf.mpu_cmn, 0, sizeof(argbuf.mpu_cmn));
		}
	}

	switch (cmd) {
	case MPIOC_MP_CREATE:
	case MPIOC_MP_ACTIVATE:
	case MPIOC_MP_DESTROY:
	case MPIOC_MP_RENAME:
		err = mpioc_mp_cmd(unit, cmd, argp);
		break;

	case MPIOC_MP_DEACTIVATE:
		err = mpioc_mp_deactivate(unit, cmd, argp);
		break;

	case MPIOC_DRV_ADD:
		err = mpioc_mp_add(unit, cmd, argp);
		break;

	case MPIOC_PARAMS_SET:
		err = mpioc_params_set(unit, cmd, argp);
		break;

	case MPIOC_PARAMS_GET:
		err = mpioc_params_get(unit, cmd, argp);
		break;

	case MPIOC_MP_MCLASS_GET:
		err = mpioc_mp_mclass_get(unit, cmd, argp);
		break;

	case MPIOC_PROP_GET:
		err = mpioc_proplist_get(unit, cmd, argp);
		break;

	case MPIOC_DEVPROPS_GET:
		err = mpioc_devprops_get(unit, argp);
		break;

	case MPIOC_MB_ALLOC:
		err = mpioc_mb_alloc(unit, argp);
		break;

	case MPIOC_MB_FIND:
		err = mpioc_mb_find(unit, argp);
		break;

	case MPIOC_MB_COMMIT:
	case MPIOC_MB_DELETE:
	case MPIOC_MB_ABORT:
		err = mpioc_mb_abcomdel(unit, cmd, argp);
		break;

	case MPIOC_MB_PROPS:
		err = mpioc_mb_props(unit, argp);
		break;

	case MPIOC_MB_READ:
	case MPIOC_MB_WRITE:
		assert(roundup(iosz, 16) < sizeof(argbuf));
		stkbufsz = sizeof(argbuf) - roundup(iosz, 16);
		stkbuf = (char *)&argbuf + roundup(iosz, 16);

		err = mpioc_mb_rw(unit, cmd, argp, stkbuf, stkbufsz);
		break;

	case MPIOC_MLOG_ALLOC:
	case MPIOC_MLOG_REALLOC:
		err = mpioc_mlog_alloc(unit, cmd, argp);
		break;

	case MPIOC_MLOG_FIND:
	case MPIOC_MLOG_PROPS:
		err = mpioc_mlog_find(unit, cmd, argp);
		break;

	case MPIOC_MLOG_ABORT:
	case MPIOC_MLOG_COMMIT:
	case MPIOC_MLOG_DELETE:
		err = mpioc_mlog_abcomdel(unit, cmd, argp);
		break;

	case MPIOC_MLOG_READ:
	case MPIOC_MLOG_WRITE:
		assert(roundup(iosz, 16) < sizeof(argbuf));
		stkbufsz = sizeof(argbuf) - roundup(iosz, 16);
		stkbuf = (char *)&argbuf + roundup(iosz, 16);

		err = mpioc_mlog_rw(unit, argp, stkbuf, stkbufsz);
		break;

	case MPIOC_MLOG_ERASE:
		err = mpioc_mlog_erase(unit, argp);
		break;

	case MPIOC_VMA_CREATE:
		err = mpioc_vma_create(unit, argp);
		break;

	case MPIOC_VMA_DESTROY:
		err = mpioc_vma_destroy(unit, argp);
		break;

	case MPIOC_VMA_PURGE:
		err = mpioc_vma_purge(unit, argp);
		break;

	case MPIOC_VMA_VRSS:
		err = mpioc_vma_vrss(unit, argp);
		break;

	case MPIOC_TEST:
		err = mpioc_test(unit, argp);
		break;

	default:
		err = merr(ENOTTY);
		mp_pr_err("invalid command %x: dir=%u type=%c nr=%u size=%u",
			  err, cmd, _IOC_DIR(cmd), _IOC_TYPE(cmd),
			  _IOC_NR(cmd), _IOC_SIZE(cmd));
		break;
	}

	rc = -merr_errno(err);

	if (_IOC_DIR(cmd) & _IOC_READ) {
		struct mpioc_cmn *cmn = argp;

		cmn->mc_err = err;
		rc = 0;

		if (err)
			cmn->mc_err = merr_to_user(err, cmn->mc_merr_base);

		if (copy_to_user((void *)arg, argp, iosz))
			rc = ev(-EFAULT);
	}

	return rc;
}

/**
 * struct vcache -  very-large-buffer cache...
 */
struct vcache {
	spinlock_t  vc_lock;
	void       *vc_head;
	size_t      vc_size;
} ____cacheline_aligned;

static struct vcache mpc_physio_vcache;

static void *
mpc_vcache_alloc(struct vcache *vc, size_t sz)
{
	void *p;

	if (!vc || sz > vc->vc_size)
		return NULL;

	spin_lock(&vc->vc_lock);
	if ((p = vc->vc_head))
		vc->vc_head = *(void **)p;
	spin_unlock(&vc->vc_lock);

	return p;
}

static void
mpc_vcache_free(struct vcache *vc, void *p)
{
	if (!vc || !p)
		return;

	spin_lock(&vc->vc_lock);
	*(void **)p = vc->vc_head;
	vc->vc_head = p;
	spin_unlock(&vc->vc_lock);
}

static merr_t
mpc_vcache_init(struct vcache *vc, size_t sz, size_t n)
{
	if (!vc || sz < PAGE_SIZE || n < 1)
		return merr(EINVAL);

	spin_lock_init(&vc->vc_lock);
	vc->vc_head = NULL;
	vc->vc_size = sz;

	while (n-- > 0)
		mpc_vcache_free(vc, vmalloc(sz));

	return vc->vc_head ? 0 : merr(ENOMEM);
}

static void
mpc_vcache_fini(struct vcache *vc)
{
	void *p;

	while ((p = mpc_vcache_alloc(vc, PAGE_SIZE)))
	       vfree(p);
}

/**
 * mpc_physio() - Generic raw device mblock read/write routine.
 * @mpd:      mpool descriptor
 * @desc:     mblock or mlog descriptor
 * @uiov:     vector of iovecs that describe user-space segments
 * @uioc:     count of elements in uiov[]
 * @offset:   offset into the mblock at which to start reading
 * @objtype:  mblock or mlog
 * @rw:       READ or WRITE in regards to the media.
 * @stkbuf:   caller provided scratch space
 * @stkbufsz: size of stkbuf
 *
 * This function creates an array of iovec objects each of which
 * map a portion of the user request into kernel space so that
 * mpool can directly access the user data.  Note that this is
 * a zero-copy operation.
 *
 * Requires that each user-space segment be page aligned and of an
 * integral number of pages.
 *
 * See http://www.makelinux.net/ldd3/chp-15-sect-3 for more detail.
 */
static merr_t
mpc_physio(
	struct mpool_descriptor    *mpd,
	void                       *desc,
	struct iovec               *uiov,
	int                         uioc,
	off_t                       offset,
	enum mp_obj_type            objtype,
	int                         rw,
	void                       *stkbuf,
	size_t                      stkbufsz)
{
	struct iovec       *iov_base, *iov;
	struct iov_iter     iter;
	struct page       **pagesv;

	size_t  pagesvsz, pgbase, length;
	int     pagesc, niov, i;
	ssize_t cc;
	merr_t  err;

	iov = NULL;
	niov = 0;
	err = 0;

	length = iov_length(uiov, uioc);

	if (length < PAGE_SIZE || !IS_ALIGNED(length, PAGE_SIZE))
		return merr(EINVAL);

	if (length > (mpc_rwsz_max << 20))
		return merr(EINVAL);

	/* Allocate an array of page pointers for iov_iter_get_pages()
	 * and an array of iovecs for mblock_read() and mblock_write().
	 *
	 * Note: the only way we can calculate the number of required
	 * iovecs in advance is to assume that we need one per page.
	 */
	pagesc = length / PAGE_SIZE;
	pagesvsz = (sizeof(*pagesv) + sizeof(*iov)) * pagesc;

	/* pagesvsz may be big, and it will not be used as the iovec_list
	 * for the block stack - ecio will chunk it up to the underlying
	 * devices (with another iovec list per pd).
	 */
	if (pagesvsz > stkbufsz) {
		pagesv = NULL;

		if (pagesvsz <= PAGE_SIZE * 2)
			pagesv = kmalloc(pagesvsz, GFP_NOIO);

		while (!pagesv) {
			pagesv = mpc_vcache_alloc(&mpc_physio_vcache, pagesvsz);
			if (!pagesv)
				usleep_range(750, 1250);
		}
	} else {
		pagesv = stkbuf;
	}

	if (!pagesv)
		return merr(ENOMEM);

	iov_base = (struct iovec *)
		((char *)pagesv + (sizeof(*pagesv) * pagesc));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	iov_iter_init(&iter, rw, uiov, uioc, length);
#else
	iov_iter_init(&iter, uiov, uioc, length, 0);
#endif

	for (i = 0, cc = 0; i < pagesc; i += (cc / PAGE_SIZE)) {

		/* Get struct page vector for the user buffers.
		 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
		cc = iov_iter_get_pages(&iter, &pagesv[i],
					length - (i * PAGE_SIZE),
					pagesc - i, &pgbase);
#else
		int npages = ((ulong)iter.iov->iov_len - iter.iov_offset +
			PAGE_SIZE - 1) / PAGE_SIZE;

		pgbase = ((ulong)iter.iov->iov_base + iter.iov_offset) &
			(PAGE_SIZE - 1);

		/*
		 * The 3rd parameter "write" should be true if this is a
		 * write to memory (passed in first parameter).
		 * Note that this is the inverse of the I/O direction.
		 */
		cc = get_user_pages_fast(
			(ulong)iter.iov->iov_base + iter.iov_offset,
			npages, (rw != WRITE), &pagesv[i]);

		/* This works because we require I/Os to be page-aligned &
		 * page multiple
		 */
		if (cc > 0)
			cc = cc * PAGE_SIZE;
#endif

		if (cc < 0) {
			err = merr(cc);
			pagesc = i;
			goto errout;
		}

		/* pgbase is the offset into the 1st iovec - our alignment
		 * requirements force it to be 0
		 */
		if (cc < PAGE_SIZE || pgbase != 0) {
			err = merr(EINVAL);
			pagesc = i + 1;
			goto errout;
		}

		iov_iter_advance(&iter, cc);
	}

	/* Build an array of iovecs for mpool so that it can directly
	 * access the user data.
	 */
	for (i = 0, iov = iov_base; i < pagesc; ++i, ++iov, ++niov) {
		iov->iov_len = PAGE_SIZE;
		iov->iov_base = kmap(pagesv[i]);

		if (!iov->iov_base) {
			err = merr(EINVAL);
			pagesc = i + 1;
			goto errout;
		}
	}

	switch (objtype) {
	case MP_OBJ_MBLOCK:
		if (rw == WRITE) {
			err = mblock_write(mpd, desc, iov_base, niov);
			ev(err);
		} else {
			err = mblock_read(mpd, desc, iov_base, niov, offset);
			ev(err);
		}
		break;

	case MP_OBJ_MLOG:
		err = mlog_rw_raw(mpd, desc, iov_base, niov, offset, rw);
		ev(err);
		break;

	default:
		err = merr(EINVAL);
		goto errout;
	}

errout:
	for (i = 0, iov = iov_base; i < pagesc; ++i, ++iov) {
		if (i < niov)
			kunmap(pagesv[i]);
		put_page(pagesv[i]);
	}

	if (pagesvsz > stkbufsz) {
		if (pagesvsz > PAGE_SIZE * 2)
			mpc_vcache_free(&mpc_physio_vcache, pagesv);
		else
			kfree(pagesv);
	}

	return err;
}

static merr_t mpc_cf_journal(struct mpc_unit *unit)
{
	struct mpool_config     cfg = { };
	struct mpc_mpool       *mpool;
	merr_t                  err;

	mpool = unit->un_mpool;
	if (!mpool)
		return merr(EINVAL);

	down_write(&mpool->mp_lock);

	cfg.mc_uid = unit->un_uid;
	cfg.mc_gid = unit->un_gid;
	cfg.mc_mode = unit->un_mode;
	cfg.mc_oid1 = unit->un_ds_oidv[0];
	cfg.mc_oid2 = unit->un_ds_oidv[1];
	cfg.mc_mclassp = unit->un_ds_mclassp;
	cfg.mc_captgt = unit->un_mdc_captgt;
	cfg.mc_ra_pages_max = unit->un_ra_pages_max;
	memcpy(&cfg.mc_utype, &unit->un_utype, sizeof(cfg.mc_utype));
	strlcpy(cfg.mc_label, unit->un_label, sizeof(cfg.mc_label));

	err = mpool_config_store(mpool->mp_desc, &cfg);

	up_write(&mpool->mp_lock);

	return err;
}

/**
 * mpc_uevent() - Hook to intercept and modify uevents before they're posted
 *                to udev (see man 7 udev).
 * @dev:    mpc driver device
 * @env:
 */
static int mpc_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct mpc_unit    *unit = dev_get_drvdata(dev);

	if (unit) {
		add_uevent_var(env, "DEVMODE=%#o", unit->un_mode);
		add_uevent_var(env, "DEVUID=%u", unit->un_uid);
		add_uevent_var(env, "DEVGID=%u", unit->un_gid);
	}

	return 0;
}

void mpool_meminfo(ulong *freep, ulong *availp, uint shift)
{
	struct sysinfo si;

	si_meminfo(&si);

	if (freep)
		*freep = (si.freeram * si.mem_unit) >> shift;

	if (availp)
		*availp = (si_mem_available() * si.mem_unit) >> shift;
}

/**
 * mpc_init() - Load and initialize the mpool control module.
 *
 */
static __init int mpc_init(void)
{
	struct mpioc_cmn        cmn = { };
	struct mpool_config     cfg = { };
	struct mpc_softstate   *ss;
	struct mpc_unit        *unit;
	struct device          *device;
	const char             *errmsg;
	bool                    modinit;
	size_t                  sz;
	merr_t                  err;
	int                     rc, i;

	modinit = false;
	device = NULL;
	unit = NULL;
	ss = NULL;

	if (mpc_softstate)
		return -EBUSY; /* Do not call error_counter() */

	mpc_units_max = clamp_t(uint, mpc_units_max, 8, 8192);
	mpc_vma_max = clamp_t(uint, mpc_vma_max, 1024, 1u << 30);
	mpc_vma_size_max = clamp_t(ulong, mpc_vma_size_max, 27, 32);

	mpc_rwsz_max = clamp_t(ulong, mpc_rwsz_max, 1, 128);
	mpc_rwconc_max = clamp_t(ulong, mpc_rwconc_max, 1, 32);

	/* Must be same as mpc_physio() pagesvsz calculation.
	 */
	sz = (mpc_rwsz_max << 20) / PAGE_SIZE;
	sz *= (sizeof(void *) + sizeof(struct iovec));

	err = mpc_vcache_init(&mpc_physio_vcache, sz, mpc_rwconc_max);
	if (err) {
		errmsg = "vcache init failed";
		goto errout;
	}

	sz = sizeof(struct mpc_mbinfo) * 8;
	mpc_vma_cachesz[0] = sizeof(struct mpc_vma) + sz;

	mpc_vma_cache[0] = kmem_cache_create(
		"mpool_vma_0", mpc_vma_cachesz[0], 0,
		SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);
	if (!mpc_vma_cache[0]) {
		errmsg = "mpc vma meta cache 0 create failed";
		err = merr(ENOMEM);
		goto errout;
	}

	sz = sizeof(struct mpc_mbinfo) * 32;
	mpc_vma_cachesz[1] = sizeof(struct mpc_vma) + sz;

	mpc_vma_cache[1] = kmem_cache_create(
		"mpool_vma_1", mpc_vma_cachesz[1], 0,
		SLAB_HWCACHE_ALIGN | SLAB_POISON, NULL);
	if (!mpc_vma_cache[1]) {
		errmsg = "mpc vma meta cache 1 create failed";
		err = merr(ENOMEM);
		goto errout;
	}

	mpc_wq_trunc = alloc_workqueue("mpc_wq_trunc", WQ_UNBOUND, 16);
	if (!mpc_wq_trunc) {
		errmsg = "trunc workqueue alloc failed";
		err = merr(ENOMEM);
		goto errout;
	}

	err = mpc_reap_create(&mpc_reap);
	if (ev(err)) {
		errmsg = "reap create failed";
		goto errout;
	}

	for (i = 0; i < ARRAY_SIZE(mpc_wq_rav); ++i) {
		char name[16];

		snprintf(name, sizeof(name), "mpc_wa_ra%d", i);

		mpc_wq_rav[i] = alloc_workqueue(name, 0, 32);
		if (!mpc_wq_rav[i]) {
			errmsg = "mpctl ra workqueue alloc failed";
			err = merr(ENOMEM);
			goto errout;
		}
	}

	ss = kzalloc(sizeof(*ss) + sizeof(*ss->ss_unitv) * mpc_units_max,
		     GFP_KERNEL);
	if (!ss) {
		errmsg = "cannot allocate softstate";
		err = merr(ENOMEM);
		goto errout;
	}

	cdev_init(&ss->ss_cdev, &mpc_fops_default);
	ss->ss_cdev.owner = THIS_MODULE;

	ss->ss_units_max = mpc_units_max;
	mutex_init(&ss->ss_lock);
	ss->ss_class = NULL;
	ss->ss_devno = NODEV;
	sema_init(&ss->ss_op_sema, 1);

	modinit = true;
	rc = mpool_mod_init();
	if (rc) {
		errmsg = "mpool_mod_init() failed";
		err = merr(rc);
		goto errout;
	}

	rc = alloc_chrdev_region(&ss->ss_devno, 0, ss->ss_units_max, "mpool");
	if (rc) {
		errmsg = "cannot allocate control device major";
		ss->ss_devno = NODEV;
		err = merr(rc);
		goto errout;
	}

	ss->ss_class = class_create(THIS_MODULE, module_name(THIS_MODULE));
	if (IS_ERR(ss->ss_class)) {
		errmsg = "class_create() failed";
		rc = PTR_ERR(ss->ss_class);
		ss->ss_class = NULL;
		err = merr(rc);
		goto errout;
	}

	ss->ss_class->dev_uevent = mpc_uevent;

	rc = cdev_add(&ss->ss_cdev, ss->ss_devno, ss->ss_units_max);
	if (rc) {
		errmsg = "cdev_add() failed";
		ss->ss_cdev.ops = NULL;
		err = merr(rc);
		goto errout;
	}

	cfg.mc_uid = mpc_ctl_uid;
	cfg.mc_gid = mpc_ctl_gid;
	cfg.mc_mode = mpc_ctl_mode;

	err = mpc_unit_setup(ss, &mpc_uinfo_ctl, MPC_DEV_CTLNAME,
			     &cfg, NULL, &unit, &cmn);
	if (err) {
		errmsg = "cannot create control device";
		goto errout;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	rc = mpc_bdi_alloc();
	if (ev(rc)) {
		errmsg = "bdi alloc failed";
		goto errout;
	}
#endif

	dev_info(unit->un_device, "%s", mpool_version);

	mpc_softstate = ss;

	mpc_unit_put(unit);

	return 0;

errout:
	mp_pr_err("%s", err, errmsg);

	if (ss) {
		if (ss->ss_devno != NODEV) {
			if (ss->ss_class) {
				if (ss->ss_cdev.ops)
					cdev_del(&ss->ss_cdev);
				class_destroy(ss->ss_class);
			}
			unregister_chrdev_region(ss->ss_devno,
						 ss->ss_units_max);
		}
		if (modinit)
			mpool_mod_exit();
		kfree(ss);
	}

	for (i = 0; i < ARRAY_SIZE(mpc_wq_rav); ++i) {
		destroy_workqueue(mpc_wq_rav[i]);
		mpc_wq_rav[i] = NULL;
	}

	mpc_reap_destroy(mpc_reap);
	mpc_reap = NULL;

	destroy_workqueue(mpc_wq_trunc);
	mpc_wq_trunc = NULL;

	kmem_cache_destroy(mpc_vma_cache[1]);
	mpc_vma_cache[1] = NULL;

	kmem_cache_destroy(mpc_vma_cache[0]);
	mpc_vma_cache[0] = NULL;

	mpc_vcache_fini(&mpc_physio_vcache);

	return -merr_errno(err);
}

/**
 * mpc_exit() - Tear down and unload the mpool control module.
 *
 */
static __exit void mpc_exit(void)
{
	struct mpc_softstate   *ss;
	int                     i;

	ss = mpc_softstate;
	if (ss) {
		for (i = ss->ss_units_max - 1; i >= 0; --i)
			mpc_unit_put(ss->ss_unitv[i]);

		cdev_del(&ss->ss_cdev);
		class_destroy(ss->ss_class);
		unregister_chrdev_region(ss->ss_devno, ss->ss_units_max);
		mpool_mod_exit();
		kfree(ss);
	}

	for (i = 0; i < ARRAY_SIZE(mpc_wq_rav); ++i) {
		destroy_workqueue(mpc_wq_rav[i]);
		mpc_wq_rav[i] = NULL;
	}

	mpc_reap_destroy(mpc_reap);
	mpc_reap = NULL;

	destroy_workqueue(mpc_wq_trunc);
	mpc_wq_trunc = NULL;

	kmem_cache_destroy(mpc_vma_cache[1]);
	mpc_vma_cache[1] = NULL;

	kmem_cache_destroy(mpc_vma_cache[0]);
	mpc_vma_cache[0] = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	mpc_bdi_free();
#endif
}

static const struct file_operations mpc_fops_default = {
	.owner		= THIS_MODULE,
	.open		= mpc_open,
	.release	= mpc_release,
	.unlocked_ioctl	= mpc_ioctl,
	.mmap           = mpc_mmap,
};

static const struct vm_operations_struct mpc_vops_default = {
	.open           = mpc_vm_open,
	.close          = mpc_vm_close,
	.fault          = mpc_vm_fault,
};

static const struct address_space_operations mpc_aops_default = {
	.readpages      = mpc_readpages,
	.releasepage    = mpc_releasepage,
	.invalidatepage = mpc_invalidatepage,
	.migratepage    = mpc_migratepage,
};

module_init(mpc_init);
module_exit(mpc_exit);

MODULE_DESCRIPTION("Object Storage Media Pool (mpool)");
MODULE_AUTHOR("Micron Technology, Inc.");
MODULE_LICENSE("GPL v2");
