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
#include <linux/kref.h>

#include <linux/backing-dev.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/migrate.h>
#include <linux/delay.h>
#include <linux/ctype.h>
#include <linux/uio.h>
#include <linux/prefetch.h>

#include "mpool_printk.h"
#include "assert.h"

#include "mpool_ioctl.h"
#include "mpool_config.h"
#include "mblock.h"
#include "mlog.h"
#include "mp.h"
#include "mpctl.h"
#include "sysfs.h"
#include "reaper.h"
#include "init.h"


#define NODEV               MKDEV(0, 0)    /* Non-existent device */

/* mpc pseudo-driver instance data (i.e., all globals live here). */
struct mpc_softstate {
	struct mutex        ss_lock;        /* Protects ss_unitmap */
	struct idr          ss_unitmap;     /* minor-to-unit map */

	____cacheline_aligned
	struct semaphore    ss_op_sema;     /* Serialize mgmt. ops */
	dev_t               ss_devno;       /* Control device devno */
	struct cdev         ss_cdev;
	struct class       *ss_class;
	bool                ss_inited;
};

/* Unit-type specific information. */
struct mpc_uinfo {
	const char     *ui_typename;
	const char     *ui_subdirfmt;
};

/* One mpc_mpool object per mpool. */
struct mpc_mpool {
	struct kref                 mp_ref;
	struct rw_semaphore         mp_lock;
	struct mpool_descriptor    *mp_desc;
	struct mp_mdc              *mp_mdc;
	uint                        mp_dpathc;
	char                      **mp_dpathv;
	char                        mp_name[];
};

/* The following structures are initialized at the end of this file. */
static const struct file_operations mpc_fops_default;

static struct mpc_softstate mpc_softstate;

static struct backing_dev_info *mpc_bdi;

static unsigned int mpc_ctl_uid __read_mostly;
static unsigned int mpc_ctl_gid __read_mostly = 6;
static unsigned int mpc_ctl_mode __read_mostly = 0664;
static unsigned int mpc_default_uid __read_mostly;
static unsigned int mpc_default_gid __read_mostly = 6;
static unsigned int mpc_default_mode __read_mostly = 0660;

static const struct mpc_uinfo mpc_uinfo_ctl = {
	.ui_typename = "mpoolctl",
	.ui_subdirfmt = "%s",
};

static const struct mpc_uinfo mpc_uinfo_mpool = {
	.ui_typename = "mpool",
	.ui_subdirfmt = "mpool/%s",
};

static inline bool mpc_unit_isctldev(const struct mpc_unit *unit)
{
	return (unit->un_uinfo == &mpc_uinfo_ctl);
}

static inline bool mpc_unit_ismpooldev(const struct mpc_unit *unit)
{
	return (unit->un_uinfo == &mpc_uinfo_mpool);
}

static inline uid_t mpc_current_uid(void)
{
	return from_kuid(current_user_ns(), current_uid());
}

static inline gid_t mpc_current_gid(void)
{
	return from_kgid(current_user_ns(), current_gid());
}

#define MPC_MPOOL_PARAMS_CNT     7

static ssize_t mpc_uid_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", dev_to_unit(dev)->un_uid);
}

static ssize_t mpc_gid_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", dev_to_unit(dev)->un_gid);
}

static ssize_t mpc_mode_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0%o\n", dev_to_unit(dev)->un_mode);
}

static ssize_t mpc_ra_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", dev_to_unit(dev)->un_ra_pages_max);
}

static ssize_t mpc_label_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%s\n", dev_to_unit(dev)->un_label);
}

static ssize_t mpc_vma_show(struct device *dev, struct device_attribute *da, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", mpc_xvm_size_max);
}

static ssize_t mpc_type_show(struct device *dev, struct device_attribute *da, char *buf)
{
	struct mpool_uuid  uuid;
	char               uuid_str[MPOOL_UUID_STRING_LEN + 1] = { };

	memcpy(uuid.uuid, dev_to_unit(dev)->un_utype.b, MPOOL_UUID_SIZE);
	mpool_unparse_uuid(&uuid, uuid_str);

	return scnprintf(buf, PAGE_SIZE, "%s\n", uuid_str);
}

static void mpc_mpool_params_add(struct device_attribute *dattr)
{
	MPC_ATTR_RO(dattr++, uid);
	MPC_ATTR_RO(dattr++, gid);
	MPC_ATTR_RO(dattr++, mode);
	MPC_ATTR_RO(dattr++, ra);
	MPC_ATTR_RO(dattr++, label);
	MPC_ATTR_RO(dattr++, vma);
	MPC_ATTR_RO(dattr,   type);
}

static int mpc_params_register(struct mpc_unit *unit, int cnt)
{
	struct mpc_attr            *attr;
	struct device_attribute    *dattr;
	int                         rc;

	attr = mpc_attr_create(unit->un_device, "parameters", cnt);
	if (!attr)
		return -ENOMEM;

	dattr = attr->a_dattr;

	/* Per-mpool parameters */
	if (mpc_unit_ismpooldev(unit))
		mpc_mpool_params_add(dattr);

	/* Common parameters */
	if (mpc_unit_isctldev(unit))
		mpc_reap_params_add(dattr);

	rc = mpc_attr_group_create(attr);
	if (rc) {
		mpc_attr_destroy(attr);
		return rc;
	}

	unit->un_attr = attr;

	return 0;
}

static void mpc_params_unregister(struct mpc_unit *unit)
{
	mpc_attr_group_destroy(unit->un_attr);
	mpc_attr_destroy(unit->un_attr);
	unit->un_attr = NULL;
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

	if (params->mp_ra_pages_max == U32_MAX)
		params->mp_ra_pages_max = MPOOL_RA_PAGES_MAX;
	params->mp_ra_pages_max = clamp_t(u32, params->mp_ra_pages_max, 0, MPOOL_RA_PAGES_MAX);

	if (params->mp_mode != -1)
		params->mp_mode &= 0777;

	params->mp_vma_size_max = mpc_xvm_size_max;

	params->mp_rsvd0 = 0;
	params->mp_rsvd1 = 0;
	params->mp_rsvd2 = 0;
	params->mp_rsvd3 = 0;
	params->mp_rsvd4 = 0;

	if (!strcmp(params->mp_label, MPOOL_LABEL_INVALID))
		strcpy(params->mp_label, MPOOL_LABEL_DEFAULT);

	mpc_toascii(params->mp_label, sizeof(params->mp_label));
}

static void mpool_to_mpcore_params(struct mpool_params *params, struct mpcore_params *mpc_params)
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

static bool mpool_params_merge_config(struct mpool_params *params, struct mpool_config *cfg)
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
	    memcmp(&params->mp_utype, &cfg->mc_utype, sizeof(params->mp_utype))) {
		memcpy(&cfg->mc_utype, &params->mp_utype, sizeof(cfg->mc_utype));
		changed = true;
	}

	if (strcmp(params->mp_label, MPOOL_LABEL_DEFAULT) &&
	    strncmp(params->mp_label, cfg->mc_label, sizeof(params->mp_label))) {
		strlcpy(cfg->mc_label, params->mp_label, sizeof(cfg->mc_label));
		changed = true;
	}

	return changed;
}

/**
 * mpc_mpool_release() - release kref handler for mpc_mpool object
 * @refp:  kref pointer
 */
static void mpc_mpool_release(struct kref *refp)
{
	struct mpc_mpool *mpool = container_of(refp, struct mpc_mpool, mp_ref);
	int rc;

	if (mpool->mp_desc) {
		rc = mpool_deactivate(mpool->mp_desc);
		if (rc)
			mp_pr_err("mpool %s deactivate failed", rc, mpool->mp_name);
	}

	kfree(mpool->mp_dpathv);
	kfree(mpool);

	module_put(THIS_MODULE);
}

static void mpc_mpool_put(struct mpc_mpool *mpool)
{
	kref_put(&mpool->mp_ref, mpc_mpool_release);
}

/**
 * mpc_unit_create() - Create and install a unit object
 * @path:         device path under "/dev/" to create
 * @mpool:        mpool ptr
 * @unitp:        unit ptr
 *
 * Create a unit object and install a NULL ptr for it in the units map,
 * thereby reserving a minor number.  The unit cannot be found by any
 * of the lookup routines until the NULL ptr is replaced by the actual
 * ptr to the unit.
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
static int mpc_unit_create(const char *name, struct mpc_mpool *mpool, struct mpc_unit **unitp)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpc_unit        *unit;
	size_t                  unitsz;
	int                     minor;

	if (!ss || !name || !unitp)
		return -EINVAL;

	unitsz = sizeof(*unit) + strlen(name) + 1;

	unit = kzalloc(unitsz, GFP_KERNEL);
	if (!unit)
		return -ENOMEM;

	strcpy(unit->un_name, name);

	sema_init(&unit->un_open_lock, 1);
	unit->un_open_excl = false;
	unit->un_open_cnt = 0;
	unit->un_devno = NODEV;
	kref_init(&unit->un_ref);
	unit->un_mpool = mpool;

	mutex_init(&unit->un_rgnmap.rm_lock);
	idr_init(&unit->un_rgnmap.rm_root);
	atomic_set(&unit->un_rgnmap.rm_rgncnt, 0);

	mutex_lock(&ss->ss_lock);
	minor = idr_alloc(&ss->ss_unitmap, NULL, 0, -1, GFP_KERNEL);
	mutex_unlock(&ss->ss_lock);

	if (minor < 0) {
		kfree(unit);
		return minor;
	}

	kref_get(&unit->un_ref); /* acquire additional ref for the caller */

	unit->un_devno = MKDEV(MAJOR(ss->ss_cdev.dev), minor);
	*unitp = unit;

	return 0;
}

/**
 * mpc_unit_release() - Destroy a unit object created by mpc_unit_create().
 * @unit:
 */
static void mpc_unit_release(struct kref *refp)
{
	struct mpc_unit *unit = container_of(refp, struct mpc_unit, un_ref);
	struct mpc_softstate *ss = &mpc_softstate;

	mutex_lock(&ss->ss_lock);
	idr_remove(&ss->ss_unitmap, MINOR(unit->un_devno));
	mutex_unlock(&ss->ss_lock);

	if (unit->un_mpool)
		mpc_mpool_put(unit->un_mpool);

	if (unit->un_attr)
		mpc_params_unregister(unit);

	if (unit->un_device)
		device_destroy(ss->ss_class, unit->un_devno);

	idr_destroy(&unit->un_rgnmap.rm_root);

	kfree(unit);
}

static void mpc_unit_put(struct mpc_unit *unit)
{
	if (unit)
		kref_put(&unit->un_ref, mpc_unit_release);
}

/**
 * mpc_unit_lookup() - Look up a unit by minor number.
 * @minor:  minor number
 * @unitp:  unit ptr
 *
 * Returns a referenced ptr to the unit (via *unitp) if found,
 * otherwise it sets *unitp to NULL.
 */
static void mpc_unit_lookup(int minor, struct mpc_unit **unitp)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpc_unit        *unit;

	*unitp = NULL;

	mutex_lock(&ss->ss_lock);
	unit = idr_find(&ss->ss_unitmap, minor);
	if (unit) {
		kref_get(&unit->un_ref);
		*unitp = unit;
	}
	mutex_unlock(&ss->ss_lock);
}

/**
 * mpc_unit_lookup_by_name_itercb() - Test to see if unit matches arg.
 * @item:   unit ptr
 * @arg:    argument vector base ptr
 *
 * This iterator callback is called by mpc_unit_lookup_by_name()
 * for each unit in the units table.
 *
 * Return: If the unit matching the given name is found returns
 * the referenced unit pointer in argv[2], otherwise NULL.
 */
static int mpc_unit_lookup_by_name_itercb(int minor, void *item, void *arg)
{
	struct mpc_unit    *unit = item;
	void              **argv = arg;
	struct mpc_unit    *parent = argv[0];
	const char         *name = argv[1];

	if (!unit)
		return ITERCB_NEXT;

	if (mpc_unit_isctldev(parent) && !mpc_unit_ismpooldev(unit))
		return ITERCB_NEXT;

	if (parent->un_mpool && unit->un_mpool != parent->un_mpool)
		return ITERCB_NEXT;

	if (strcmp(unit->un_name, name) == 0) {
		kref_get(&unit->un_ref);
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
 */
static void
mpc_unit_lookup_by_name(struct mpc_unit *parent, const char *name, struct mpc_unit **unitp)
{
	struct mpc_softstate *ss = &mpc_softstate;
	void   *argv[] = { parent, (void *)name, NULL };

	mutex_lock(&ss->ss_lock);
	idr_for_each(&ss->ss_unitmap, mpc_unit_lookup_by_name_itercb, argv);
	mutex_unlock(&ss->ss_lock);

	*unitp = argv[2];
}

/**
 * mpc_unit_setup() - Create a device unit object and special file
 * @uinfo:
 * @name:
 * @cfg:
 * @mpool:
 * @unitp: unitp can be NULL. *unitp is updated only if unitp is not NULL
 *	and no error is returned.
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
static int
mpc_unit_setup(
	const struct mpc_uinfo     *uinfo,
	const char                 *name,
	const struct mpool_config  *cfg,
	struct mpc_mpool           *mpool,
	struct mpc_unit           **unitp)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpc_unit        *unit;
	struct device          *device;
	int rc;

	if (!ss || !uinfo || !name || !name[0] || !cfg || !unitp)
		return -EINVAL;

	if (cfg->mc_uid == -1 || cfg->mc_gid == -1 || cfg->mc_mode == -1)
		return -EINVAL;

	if (!capable(CAP_MKNOD))
		return -EPERM;

	if (cfg->mc_uid != mpc_current_uid() && !capable(CAP_CHOWN))
		return -EPERM;

	if (cfg->mc_gid != mpc_current_gid() && !capable(CAP_CHOWN))
		return -EPERM;

	if (mpool && strcmp(mpool->mp_name, name))
		return -EINVAL;

	*unitp = NULL;
	unit = NULL;

	/*
	 * Try to create a new unit object.  If successful, then all error
	 * handling beyond this point must route through the errout label
	 * to ensure the unit is fully destroyed.
	 */
	rc = mpc_unit_create(name, mpool, &unit);
	if (rc)
		return rc;

	unit->un_uid = cfg->mc_uid;
	unit->un_gid = cfg->mc_gid;
	unit->un_mode = cfg->mc_mode;

	unit->un_mdc_captgt = cfg->mc_captgt;
	memcpy(&unit->un_utype, &cfg->mc_utype, sizeof(unit->un_utype));
	strlcpy(unit->un_label, cfg->mc_label, sizeof(unit->un_label));
	unit->un_ds_oidv[0] = cfg->mc_oid1;
	unit->un_ds_oidv[1] = cfg->mc_oid2;
	unit->un_ra_pages_max = cfg->mc_ra_pages_max;

	device = device_create(ss->ss_class, NULL, unit->un_devno, unit, uinfo->ui_subdirfmt, name);
	if (IS_ERR(device)) {
		rc = PTR_ERR(device);
		mp_pr_err("device_create %s failed", rc, name);
		goto errout;
	}

	unit->un_device = device;
	unit->un_uinfo = uinfo;

	dev_info(unit->un_device, "minor %u, uid %u, gid %u, mode 0%02o",
		 MINOR(unit->un_devno), cfg->mc_uid, cfg->mc_gid, cfg->mc_mode);

	*unitp = unit;

errout:
	if (rc) {
		/*
		 * Acquire an additional reference on mpool so that it is not
		 * errantly destroyed along with the unit, then release both
		 * the unit's birth and caller's references which should
		 * destroy the unit.
		 */
		kref_get(&mpool->mp_ref);
		mpc_unit_put(unit);
		mpc_unit_put(unit);
	}

	return rc;
}


static int mpc_cf_journal(struct mpc_unit *unit)
{
	struct mpool_config     cfg = { };
	struct mpc_mpool       *mpool;
	int rc;

	mpool = unit->un_mpool;
	if (!mpool)
		return -EINVAL;

	down_write(&mpool->mp_lock);

	cfg.mc_uid = unit->un_uid;
	cfg.mc_gid = unit->un_gid;
	cfg.mc_mode = unit->un_mode;
	cfg.mc_oid1 = unit->un_ds_oidv[0];
	cfg.mc_oid2 = unit->un_ds_oidv[1];
	cfg.mc_captgt = unit->un_mdc_captgt;
	cfg.mc_ra_pages_max = unit->un_ra_pages_max;
	cfg.mc_vma_size_max = mpc_xvm_size_max;
	memcpy(&cfg.mc_utype, &unit->un_utype, sizeof(cfg.mc_utype));
	strlcpy(cfg.mc_label, unit->un_label, sizeof(cfg.mc_label));

	rc = mpool_config_store(mpool->mp_desc, &cfg);

	up_write(&mpool->mp_lock);

	return rc;
}

/**
 * mpc_uevent() - Hook to intercept and modify uevents before they're posted to udev
 * @dev:    mpc driver device
 * @env:
 *
 * See man 7 udev for more info.
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

/**
 * mpc_mp_chown() - Change ownership of an mpool.
 * @unit: mpool unit ptr
 * @mps:
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpc_mp_chown(struct mpc_unit *unit, struct mpool_params *params)
{
	uid_t  uid;
	gid_t  gid;
	mode_t mode;
	int    rc = 0;

	if (!mpc_unit_ismpooldev(unit))
		return -EINVAL;

	uid  = params->mp_uid;
	gid  = params->mp_gid;
	mode = params->mp_mode;

	if (mode != -1)
		mode &= 0777;

	if (uid != -1 && uid != unit->un_uid && !capable(CAP_CHOWN))
		return -EPERM;

	if (gid != -1 && gid != unit->un_gid && !capable(CAP_CHOWN))
		return -EPERM;

	if (mode != -1 && mode != unit->un_mode && !capable(CAP_FOWNER))
		return -EPERM;

	if (-1 != uid)
		unit->un_uid = uid;
	if (-1 != gid)
		unit->un_gid = gid;
	if (-1 != mode)
		unit->un_mode = mode;

	if (uid != -1 || gid != -1 || mode != -1)
		rc = kobject_uevent(&unit->un_device->kobj, KOBJ_CHANGE);

	return rc;
}

/**
 * mpioc_params_get() - get parameters of an activated mpool
 * @unit:   mpool device unit ptr
 * @get:    mpool params
 *
 * MPIOC_PARAMS_GET ioctl handler to get mpool parameters
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_params_get(struct mpc_unit *unit, struct mpioc_params *get)
{
	struct mpc_softstate       *ss = &mpc_softstate;
	struct mpool_descriptor    *desc;
	struct mpool_params        *params;
	struct mpool_xprops         xprops = { };
	u8                          mclass;

	if (!mpc_unit_ismpooldev(unit))
		return -EINVAL;

	desc = unit->un_mpool->mp_desc;

	mutex_lock(&ss->ss_lock);

	params = &get->mps_params;
	memset(params, 0, sizeof(*params));
	params->mp_uid = unit->un_uid;
	params->mp_gid = unit->un_gid;
	params->mp_mode = unit->un_mode;
	params->mp_mdc_captgt = MPOOL_ROOT_LOG_CAP;
	params->mp_oidv[0] = unit->un_ds_oidv[0];
	params->mp_oidv[1] = unit->un_ds_oidv[1];
	params->mp_ra_pages_max = unit->un_ra_pages_max;
	params->mp_vma_size_max = mpc_xvm_size_max;
	memcpy(&params->mp_utype, &unit->un_utype, sizeof(params->mp_utype));
	strlcpy(params->mp_label, unit->un_label, sizeof(params->mp_label));
	strlcpy(params->mp_name, unit->un_name, sizeof(params->mp_name));

	/* Get mpool properties.. */
	mpool_get_xprops(desc, &xprops);

	for (mclass = 0; mclass < MP_MED_NUMBER; mclass++)
		params->mp_mblocksz[mclass] = xprops.ppx_params.mp_mblocksz[mclass];

	params->mp_spare_cap = xprops.ppx_drive_spares[MP_MED_CAPACITY];
	params->mp_spare_stg = xprops.ppx_drive_spares[MP_MED_STAGING];

	memcpy(params->mp_poolid.b, xprops.ppx_params.mp_poolid.b, MPOOL_UUID_SIZE);

	mutex_unlock(&ss->ss_lock);

	return 0;
}

/**
 * mpioc_params_set() - set parameters of an activated mpool
 * @unit:   control device unit ptr
 * @set:    mpool params
 *
 * MPIOC_PARAMS_SET ioctl handler to set mpool parameters
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_params_set(struct mpc_unit *unit, struct mpioc_params *set)
{
	struct mpc_softstate       *ss = &mpc_softstate;
	struct mpool_descriptor    *mp;
	struct mpool_params        *params;

	uuid_le uuidnull = { };
	int rerr = 0, err = 0;
	bool journal = false;

	if (!mpc_unit_ismpooldev(unit))
		return -EINVAL;

	params = &set->mps_params;

	params->mp_vma_size_max = mpc_xvm_size_max;

	mutex_lock(&ss->ss_lock);
	if (params->mp_uid != -1 || params->mp_gid != -1 || params->mp_mode != -1) {
		err = mpc_mp_chown(unit, params);
		if (err) {
			mutex_unlock(&ss->ss_lock);
			return err;
		}
		journal = true;
	}

	if (params->mp_label[0]) {
		mpc_toascii(params->mp_label, sizeof(params->mp_label));
		strlcpy(unit->un_label, params->mp_label, sizeof(unit->un_label));
		journal = true;
	}

	if (memcmp(&uuidnull, &params->mp_utype, sizeof(uuidnull))) {
		memcpy(&unit->un_utype, &params->mp_utype, sizeof(unit->un_utype));
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

	if (err) {
		mp_pr_err("%s: params commit failed", err, unit->un_name);
		return err;
	}

	mp = unit->un_mpool->mp_desc;

	if (params->mp_spare_cap != MPOOL_SPARES_INVALID) {
		err = mpool_drive_spares(mp, MP_MED_CAPACITY, params->mp_spare_cap);
		if (err && err != -ENOENT)
			rerr = err;
	}

	if (params->mp_spare_stg != MPOOL_SPARES_INVALID) {
		err = mpool_drive_spares(mp, MP_MED_STAGING, params->mp_spare_stg);
		if (err && err != -ENOENT)
			rerr = err;
	}

	return rerr;
}

/**
 * mpioc_mp_mclass_get() - get information regarding an mpool's mclasses
 * @unit:   control device unit ptr
 * @mcl:    mclass info struct
 *
 * MPIOC_MP_MCLASS_GET ioctl handler to get mclass information
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_mp_mclass_get(struct mpc_unit *unit, struct mpioc_mclass *mcl)
{
	struct mpool_descriptor   *desc = unit->un_mpool->mp_desc;
	struct mpool_mclass_xprops mcxv[MP_MED_NUMBER];
	uint32_t                   mcxc = ARRAY_SIZE(mcxv);
	int                        rc;

	if (!mcl || !desc)
		return -EINVAL;

	if (!mcl->mcl_xprops) {
		mpool_mclass_get_cnt(desc, &mcl->mcl_cnt);
		return 0;
	}

	memset(mcxv, 0, sizeof(mcxv));

	rc = mpool_mclass_get(desc, &mcxc, mcxv);
	if (rc)
		return rc;

	if (mcxc > mcl->mcl_cnt)
		mcxc = mcl->mcl_cnt;
	mcl->mcl_cnt = mcxc;

	rc = copy_to_user(mcl->mcl_xprops, mcxv, sizeof(mcxv[0]) * mcxc);

	return rc ? -EFAULT : 0;
}

/**
 * mpioc_devprops_get() - Get device properties
 * @unit:   mpool unit ptr
 *
 * MPIOC_PROP_GET ioctl handler to retrieve properties for the specified device.
 */
static int mpioc_devprops_get(struct mpc_unit *unit, struct mpioc_devprops *devprops)
{
	int rc = 0;

	if (unit->un_mpool) {
		struct mpool_descriptor *mp = unit->un_mpool->mp_desc;

		rc = mpool_get_devprops_by_name(mp, devprops->dpr_pdname, &devprops->dpr_devprops);
	}

	return rc;
}

/**
 * mpioc_prop_get() - Get mpool properties.
 * @unit:   mpool unit ptr
 *
 * MPIOC_PROP_GET ioctl handler to retrieve properties for the specified device.
 */
static void mpioc_prop_get(struct mpc_unit *unit, struct mpioc_prop *kprop)
{
	struct mpool_descriptor    *desc = unit->un_mpool->mp_desc;
	struct mpool_params        *params;
	struct mpool_xprops        *xprops;

	memset(kprop, 0, sizeof(*kprop));

	/* Get unit properties.. */
	params = &kprop->pr_xprops.ppx_params;
	params->mp_uid = unit->un_uid;
	params->mp_gid = unit->un_gid;
	params->mp_mode = unit->un_mode;
	params->mp_mdc_captgt = unit->un_mdc_captgt;
	params->mp_oidv[0] = unit->un_ds_oidv[0];
	params->mp_oidv[1] = unit->un_ds_oidv[1];
	params->mp_ra_pages_max = unit->un_ra_pages_max;
	params->mp_vma_size_max = mpc_xvm_size_max;
	memcpy(&params->mp_utype, &unit->un_utype, sizeof(params->mp_utype));
	strlcpy(params->mp_label, unit->un_label, sizeof(params->mp_label));
	strlcpy(params->mp_name, unit->un_name, sizeof(params->mp_name));

	/* Get mpool properties.. */
	xprops = &kprop->pr_xprops;
	mpool_get_xprops(desc, xprops);
	mpool_get_usage(desc, MP_MED_ALL, &kprop->pr_usage);

	params->mp_spare_cap = xprops->ppx_drive_spares[MP_MED_CAPACITY];
	params->mp_spare_stg = xprops->ppx_drive_spares[MP_MED_STAGING];

	kprop->pr_mcxc = ARRAY_SIZE(kprop->pr_mcxv);
	mpool_mclass_get(desc, &kprop->pr_mcxc, kprop->pr_mcxv);
}

/**
 * mpioc_proplist_get_itercb() - Get properties iterator callback.
 * @item:   unit ptr
 * @arg:    argument list
 *
 * Return: Returns properties for each unit matching the input criteria.
 */
static int mpioc_proplist_get_itercb(int minor, void *item, void *arg)
{
	struct mpc_unit             *unit = item;
	struct mpioc_prop __user    *uprop;
	struct mpioc_prop            kprop;
	struct mpc_unit             *match;
	struct mpioc_list           *ls;
	void                       **argv = arg;
	int                         *cntp, rc;
	int                         *errp;

	if (!unit)
		return ITERCB_NEXT;

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

	mpioc_prop_get(unit, &kprop);

	uprop = (struct mpioc_prop __user *)ls->ls_listv + *cntp;

	rc = copy_to_user(uprop, &kprop, sizeof(*uprop));
	if (rc) {
		*errp = -EFAULT;
		return ITERCB_DONE;
	}

	return (++(*cntp) >= ls->ls_listc) ? ITERCB_DONE : ITERCB_NEXT;
}

/**
 * mpioc_proplist_get() - Get mpool or dataset properties.
 * @unit:   mpool or dataset unit ptr
 * @ls:     properties parameter block
 *
 * MPIOC_PROP_GET ioctl handler to retrieve properties for one
 * or more mpools.
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_proplist_get(struct mpc_unit *unit, struct mpioc_list *ls)
{
	struct mpc_softstate *ss = &mpc_softstate;
	int err = 0;
	int cnt = 0;
	void *argv[] = { unit, ls, &cnt, &err };

	if (!ls || ls->ls_listc < 1 || ls->ls_cmd == MPIOC_LIST_CMD_INVALID)
		return -EINVAL;

	mutex_lock(&ss->ss_lock);
	idr_for_each(&ss->ss_unitmap, mpioc_proplist_get_itercb, argv);
	mutex_unlock(&ss->ss_lock);

	ls->ls_listc = cnt;

	return err;
}

/**
 * mpc_mpool_open() - Open the mpool specified by the given drive paths,
 *                    and then create an mpool object to track the
 *                    underlying mpool.
 * @dpathc: drive count
 * @dpathv: drive path name vector
 * @mpoolp: mpool ptr. Set only if success.
 * @pd_prop: PDs properties
 *
 * Return:  Returns 0 if successful and sets *mpoolp.
 *          Returns -errno on error.
 */
static int mpc_mpool_open(uint dpathc, char **dpathv, struct mpc_mpool **mpoolp,
			  struct pd_prop *pd_prop, struct mpool_params *params, u32 flags)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpcore_params    mpc_params;
	struct mpc_mpool       *mpool;
	size_t mpoolsz, len;
	int rc;

	if (!ss || !dpathv || !mpoolp || !params)
		return -EINVAL;

	len = mpc_toascii(params->mp_name, sizeof(params->mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return (len < 1) ? -EINVAL : -ENAMETOOLONG;

	mpoolsz = sizeof(*mpool) + len + 1;

	mpool = kzalloc(mpoolsz, GFP_KERNEL);
	if (!mpool)
		return -ENOMEM;

	if (!try_module_get(THIS_MODULE)) {
		kfree(mpool);
		return -EBUSY;
	}

	mpool_to_mpcore_params(params, &mpc_params);

	rc = mpool_activate(dpathc, dpathv, pd_prop, MPOOL_ROOT_LOG_CAP,
			    &mpc_params, flags, &mpool->mp_desc);
	if (rc) {
		mp_pr_err("Activating %s failed", rc, params->mp_name);
		module_put(THIS_MODULE);
		kfree(mpool);
		return rc;
	}

	kref_init(&mpool->mp_ref);
	init_rwsem(&mpool->mp_lock);
	mpool->mp_dpathc = dpathc;
	mpool->mp_dpathv = dpathv;
	strcpy(mpool->mp_name, params->mp_name);

	*mpoolp = mpool;

	return 0;
}

/**
 * mpioc_mp_create() - create an mpool.
 * @mp:      mpool parameter block
 * @pd_prop:
 * @dpathv:
 *
 * MPIOC_MP_CREATE ioctl handler to create an mpool.
 *
 * Return:  Returns 0 if the mpool is created, -errno otherwise...
 */
static int mpioc_mp_create(struct mpc_unit *ctl, struct mpioc_mpool *mp,
			   struct pd_prop *pd_prop, char ***dpathv)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpool_config     cfg = { };
	struct mpcore_params    mpc_params;
	struct mpc_unit        *unit = NULL;
	struct mpc_mpool       *mpool = NULL;
	size_t                  len;
	mode_t                  mode;
	uid_t                   uid;
	gid_t                   gid;
	int rc;

	if (!ctl || !mp || !pd_prop || !dpathv)
		return -EINVAL;

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return (len < 1) ? -EINVAL : -ENAMETOOLONG;

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
		rc = -EPERM;
		mp_pr_err("chown permission denied, uid %d", rc, uid);
		return rc;
	}

	if (gid != mpc_current_gid() && !capable(CAP_CHOWN)) {
		rc = -EPERM;
		mp_pr_err("chown permission denied, gid %d", rc, gid);
		return rc;
	}

	if (!capable(CAP_SYS_ADMIN)) {
		rc = -EPERM;
		mp_pr_err("chmod/activate permission denied", rc);
		return rc;
	}

	mpool_to_mpcore_params(&mp->mp_params, &mpc_params);

	rc = mpool_create(mp->mp_params.mp_name, mp->mp_flags, *dpathv,
			  pd_prop, &mpc_params, MPOOL_ROOT_LOG_CAP);
	if (rc) {
		mp_pr_err("%s: create failed", rc, mp->mp_params.mp_name);
		return rc;
	}

	/*
	 * Create an mpc_mpool object through which we can (re)open and manage
	 * the mpool.  If successful, mpc_mpool_open() adopts dpathv.
	 */
	mpool_params_merge_defaults(&mp->mp_params);

	rc = mpc_mpool_open(mp->mp_dpathc, *dpathv, &mpool, pd_prop, &mp->mp_params, mp->mp_flags);
	if (rc) {
		mp_pr_err("%s: mpc_mpool_open failed", rc, mp->mp_params.mp_name);
		mpool_destroy(mp->mp_dpathc, *dpathv, pd_prop, mp->mp_flags);
		return rc;
	}

	*dpathv = NULL;

	mlog_lookup_rootids(&cfg.mc_oid1, &cfg.mc_oid2);
	cfg.mc_uid = uid;
	cfg.mc_gid = gid;
	cfg.mc_mode = mode;
	cfg.mc_rsvd0 = mp->mp_params.mp_rsvd0;
	cfg.mc_captgt = MPOOL_ROOT_LOG_CAP;
	cfg.mc_ra_pages_max = mp->mp_params.mp_ra_pages_max;
	cfg.mc_vma_size_max = mp->mp_params.mp_vma_size_max;
	cfg.mc_rsvd1 = mp->mp_params.mp_rsvd1;
	cfg.mc_rsvd2 = mp->mp_params.mp_rsvd2;
	cfg.mc_rsvd3 = mp->mp_params.mp_rsvd3;
	cfg.mc_rsvd4 = mp->mp_params.mp_rsvd4;
	memcpy(&cfg.mc_utype, &mp->mp_params.mp_utype, sizeof(cfg.mc_utype));
	strlcpy(cfg.mc_label, mp->mp_params.mp_label, sizeof(cfg.mc_label));

	rc = mpool_config_store(mpool->mp_desc, &cfg);
	if (rc) {
		mp_pr_err("%s: config store failed", rc, mp->mp_params.mp_name);
		goto errout;
	}

	/* A unit is born with two references:  A birth reference, and one for the caller. */
	rc = mpc_unit_setup(&mpc_uinfo_mpool, mp->mp_params.mp_name,
			    &cfg, mpool, &unit);
	if (rc) {
		mp_pr_err("%s: unit setup failed", rc, mp->mp_params.mp_name);
		goto errout;
	}

	/* Return resolved params to caller. */
	mp->mp_params.mp_uid = uid;
	mp->mp_params.mp_gid = gid;
	mp->mp_params.mp_mode = mode;
	mp->mp_params.mp_mdc_captgt = cfg.mc_captgt;
	mp->mp_params.mp_oidv[0] = cfg.mc_oid1;
	mp->mp_params.mp_oidv[1] = cfg.mc_oid2;

	rc = mpc_params_register(unit, MPC_MPOOL_PARAMS_CNT);
	if (rc) {
		mpc_unit_put(unit); /* drop birth ref */
		goto errout;
	}

	mutex_lock(&ss->ss_lock);
	idr_replace(&ss->ss_unitmap, unit, MINOR(unit->un_devno));
	mutex_unlock(&ss->ss_lock);

	mpool = NULL;

errout:
	if (mpool) {
		mpool_deactivate(mpool->mp_desc);
		mpool->mp_desc = NULL;
		mpool_destroy(mp->mp_dpathc, mpool->mp_dpathv, pd_prop, mp->mp_flags);
	}

	/*
	 * For failures after mpc_unit_setup() (i.e., mpool != NULL)
	 * dropping the final unit ref will release the mpool ref.
	 */
	if (unit)
		mpc_unit_put(unit); /* Drop caller's ref */
	else if (mpool)
		mpc_mpool_put(mpool);

	return rc;
}

/**
 * mpioc_mp_activate() - activate an mpool.
 * @mp:      mpool parameter block
 * @pd_prop:
 * @dpathv:
 *
 * MPIOC_MP_ACTIVATE ioctl handler to activate an mpool.
 *
 * Return:  Returns 0 if the mpool is activated, -errno otherwise...
 */
static int mpioc_mp_activate(struct mpc_unit *ctl, struct mpioc_mpool *mp,
			     struct pd_prop *pd_prop, char ***dpathv)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpool_config     cfg;
	struct mpc_mpool       *mpool = NULL;
	struct mpc_unit        *unit = NULL;
	size_t                  len;
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!ctl || !mp || !pd_prop || !dpathv)
		return -EINVAL;

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return (len < 1) ? -EINVAL : -ENAMETOOLONG;

	mpool_params_merge_defaults(&mp->mp_params);

	/*
	 * Create an mpc_mpool object through which we can (re)open and manage
	 * the mpool.  If successful, mpc_mpool_open() adopts dpathv.
	 */
	rc = mpc_mpool_open(mp->mp_dpathc, *dpathv, &mpool, pd_prop, &mp->mp_params, mp->mp_flags);
	if (rc) {
		mp_pr_err("%s: mpc_mpool_open failed", rc, mp->mp_params.mp_name);
		return rc;
	}

	*dpathv = NULL; /* Was adopted by successful mpc_mpool_open() */

	rc = mpool_config_fetch(mpool->mp_desc, &cfg);
	if (rc) {
		mp_pr_err("%s config fetch failed", rc, mp->mp_params.mp_name);
		goto errout;
	}

	if (mpool_params_merge_config(&mp->mp_params, &cfg))
		mpool_config_store(mpool->mp_desc, &cfg);

	/* A unit is born with two references:  A birth reference, and one for the caller. */
	rc = mpc_unit_setup(&mpc_uinfo_mpool, mp->mp_params.mp_name,
			    &cfg, mpool, &unit);
	if (rc) {
		mp_pr_err("%s unit setup failed", rc, mp->mp_params.mp_name);
		goto errout;
	}

	/* Return resolved params to caller. */
	mp->mp_params.mp_uid = cfg.mc_uid;
	mp->mp_params.mp_gid = cfg.mc_gid;
	mp->mp_params.mp_mode = cfg.mc_mode;
	mp->mp_params.mp_mdc_captgt = cfg.mc_captgt;
	mp->mp_params.mp_oidv[0] = cfg.mc_oid1;
	mp->mp_params.mp_oidv[1] = cfg.mc_oid2;
	mp->mp_params.mp_ra_pages_max = cfg.mc_ra_pages_max;
	mp->mp_params.mp_vma_size_max = cfg.mc_vma_size_max;
	memcpy(&mp->mp_params.mp_utype, &cfg.mc_utype, sizeof(mp->mp_params.mp_utype));
	strlcpy(mp->mp_params.mp_label, cfg.mc_label, sizeof(mp->mp_params.mp_label));

	rc = mpc_params_register(unit, MPC_MPOOL_PARAMS_CNT);
	if (rc) {
		mpc_unit_put(unit); /* drop birth ref */
		goto errout;
	}

	mutex_lock(&ss->ss_lock);
	idr_replace(&ss->ss_unitmap, unit, MINOR(unit->un_devno));
	mutex_unlock(&ss->ss_lock);

	mpool = NULL;

errout:
	/*
	 * For failures after mpc_unit_setup() (i.e., mpool != NULL)
	 * dropping the final unit ref will release the mpool ref.
	 */
	if (unit)
		mpc_unit_put(unit); /* drop caller's ref */
	else if (mpool)
		mpc_mpool_put(mpool);

	return rc;
}

/**
 * mpioc_mp_deactivate_impl() - deactivate an mpool.
 * @unit:   control device unit ptr
 * @mp:     mpool parameter block
 *
 * MPIOC_MP_DEACTIVATE ioctl handler to deactivate an mpool.
 */
static int mp_deactivate_impl(struct mpc_unit *ctl, struct mpioc_mpool *mp, bool locked)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpc_unit        *unit = NULL;
	size_t len;
	int rc;

	if (!ctl || !mp)
		return -EINVAL;

	if (!mpc_unit_isctldev(ctl))
		return -ENOTTY;

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return (len < 1) ? -EINVAL : -ENAMETOOLONG;

	if (!locked) {
		rc = down_interruptible(&ss->ss_op_sema);
		if (rc)
			return rc;
	}

	mpc_unit_lookup_by_name(ctl, mp->mp_params.mp_name, &unit);
	if (!unit) {
		rc = -ENXIO;
		goto errout;
	}

	/*
	 * In order to be determined idle, a unit shall not be open
	 * and shall have a ref count of exactly two (the birth ref
	 * and the lookup ref from above).
	 */
	mutex_lock(&ss->ss_lock);
	if (unit->un_open_cnt > 0 || kref_read(&unit->un_ref) != 2) {
		rc = -EBUSY;
		mp_pr_err("%s: busy, cannot deactivate", rc, unit->un_name);
	} else {
		idr_replace(&ss->ss_unitmap, NULL, MINOR(unit->un_devno));
		rc = 0;
	}
	mutex_unlock(&ss->ss_lock);

	if (!rc)
		mpc_unit_put(unit); /* drop birth ref */

	mpc_unit_put(unit); /* drop lookup ref */

errout:
	if (!locked)
		up(&ss->ss_op_sema);

	return rc;
}

static int mpioc_mp_deactivate(struct mpc_unit *ctl, struct mpioc_mpool *mp)
{
	return mp_deactivate_impl(ctl, mp, false);
}

static int mpioc_mp_cmd(struct mpc_unit *ctl, uint cmd, struct mpioc_mpool *mp)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpc_unit        *unit = NULL;
	struct pd_prop         *pd_prop = NULL;
	char                  **dpathv = NULL;
	size_t                  dpathvsz;
	char                   *dpaths;
	int                     rc, i;
	size_t                  pd_prop_sz;
	const char             *action;
	size_t                  len;

	if (!ctl || !mp)
		return -EINVAL;

	if (!mpc_unit_isctldev(ctl))
		return -EOPNOTSUPP;

	if (mp->mp_dpathc < 1 || mp->mp_dpathc > MPOOL_DRIVES_MAX)
		return -EDOM;

	len = mpc_toascii(mp->mp_params.mp_name, sizeof(mp->mp_params.mp_name));
	if (len < 1 || len >= MPOOL_NAMESZ_MAX)
		return (len < 1) ? -EINVAL : -ENAMETOOLONG;

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
		return -EINVAL;
	}

	if (!mp->mp_pd_prop || !mp->mp_dpaths) {
		rc = -EINVAL;
		mp_pr_err("%s: %s, (%d drives), drives names %p or PD props %p invalid",
			  rc, mp->mp_params.mp_name, action, mp->mp_dpathc,
			  mp->mp_dpaths, mp->mp_pd_prop);

		return rc;
	}

	if (mp->mp_dpathssz > (mp->mp_dpathc + 1) * PATH_MAX)
		return -EINVAL;

	rc = down_interruptible(&ss->ss_op_sema);
	if (rc)
		return rc;

	/*
	 * If mpc_unit_lookup_by_name() succeeds it will have acquired
	 * a reference on unit.  We release that reference at the
	 * end of this function.
	 */
	mpc_unit_lookup_by_name(ctl, mp->mp_params.mp_name, &unit);

	if (unit && cmd != MPIOC_MP_DESTROY) {
		if (cmd == MPIOC_MP_ACTIVATE)
			goto errout;
		rc = -EEXIST;
		mp_pr_err("%s: mpool already activated", rc, mp->mp_params.mp_name);
		goto errout;
	}

	/*
	 * The device path names are in one long string separated by
	 * newlines.  Here we allocate one chunk of memory to hold
	 * all the device paths and a vector of ptrs to them.
	 */
	dpathvsz = mp->mp_dpathc * sizeof(*dpathv) + mp->mp_dpathssz;
	if (dpathvsz > MPOOL_DRIVES_MAX * (PATH_MAX + sizeof(*dpathv))) {
		rc = -E2BIG;
		mp_pr_err("%s: %s, too many member drives %zu",
			  rc, mp->mp_params.mp_name, action, dpathvsz);
		goto errout;
	}

	dpathv = kmalloc(dpathvsz, GFP_KERNEL);
	if (!dpathv) {
		rc = -ENOMEM;
		goto errout;
	}

	dpaths = (char *)dpathv + mp->mp_dpathc * sizeof(*dpathv);

	rc = copy_from_user(dpaths, mp->mp_dpaths, mp->mp_dpathssz);
	if (rc) {
		rc = -EFAULT;
		goto errout;
	}

	for (i = 0; i < mp->mp_dpathc; ++i) {
		dpathv[i] = strsep(&dpaths, "\n");
		if (!dpathv[i]) {
			rc = -EINVAL;
			goto errout;
		}
	}

	/* Get the PDs properties from user space buffer. */
	pd_prop_sz = mp->mp_dpathc * sizeof(*pd_prop);
	pd_prop = kmalloc(pd_prop_sz, GFP_KERNEL);
	if (!pd_prop) {
		rc = -ENOMEM;
		mp_pr_err("%s: %s, alloc pd prop %zu failed",
			  rc, mp->mp_params.mp_name, action, pd_prop_sz);
		goto errout;
	}

	rc = copy_from_user(pd_prop, mp->mp_pd_prop, pd_prop_sz);
	if (rc) {
		rc = -EFAULT;
		mp_pr_err("%s: %s, copyin pd prop %zu failed",
			  rc, mp->mp_params.mp_name, action, pd_prop_sz);
		goto errout;
	}

	switch (cmd) {
	case MPIOC_MP_CREATE:
		rc = mpioc_mp_create(ctl, mp, pd_prop, &dpathv);
		break;

	case MPIOC_MP_ACTIVATE:
		rc = mpioc_mp_activate(ctl, mp, pd_prop, &dpathv);
		break;

	case MPIOC_MP_DESTROY:
		if (unit) {
			mpc_unit_put(unit);
			unit = NULL;

			rc = mp_deactivate_impl(ctl, mp, true);
			if (rc) {
				action = "deactivate";
				break;
			}
		}
		rc = mpool_destroy(mp->mp_dpathc, dpathv, pd_prop, mp->mp_flags);
		break;

	case MPIOC_MP_RENAME:
		rc = mpool_rename(mp->mp_dpathc, dpathv, pd_prop, mp->mp_flags,
				   mp->mp_params.mp_name);
		break;
	}

	if (rc)
		mp_pr_err("%s: %s failed", rc, mp->mp_params.mp_name, action);

errout:
	mpc_unit_put(unit);
	up(&ss->ss_op_sema);

	kfree(pd_prop);
	kfree(dpathv);

	return rc;
}

/**
 * mpioc_mp_add() - add a device to an existing mpool
 * @unit:   control device unit ptr
 * @drv:    mpool device parameter block
 *
 * MPIOC_MP_ADD ioctl handler to add a drive to a activated mpool
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_mp_add(struct mpc_unit *unit, struct mpioc_drive *drv)
{
	struct mpool_descriptor    *desc = unit->un_mpool->mp_desc;
	struct pd_prop             *pd_prop;

	size_t  pd_prop_sz;
	size_t  dpathvsz;
	char  **dpathv;
	char   *dpaths;
	int     rc, i;

	/*
	 * The device path names are in one long string separated by
	 * newlines.  Here we allocate one chunk of memory to hold
	 * all the device paths and a vector of ptrs to them.
	 */
	dpathvsz = drv->drv_dpathc * sizeof(*dpathv) + drv->drv_dpathssz;
	if (drv->drv_dpathc > MPOOL_DRIVES_MAX ||
	    dpathvsz > MPOOL_DRIVES_MAX * (PATH_MAX + sizeof(*dpathv))) {
		rc = -E2BIG;
		mp_pr_err("%s: invalid pathc %u, pathsz %zu",
			  rc, unit->un_name, drv->drv_dpathc, dpathvsz);
		return rc;
	}

	dpathv = kmalloc(dpathvsz, GFP_KERNEL);
	if (!dpathv) {
		rc = -ENOMEM;
		mp_pr_err("%s: alloc dpathv %zu failed", rc, unit->un_name, dpathvsz);
		return rc;
	}

	dpaths = (char *)dpathv + drv->drv_dpathc * sizeof(*dpathv);
	rc = copy_from_user(dpaths, drv->drv_dpaths, drv->drv_dpathssz);
	if (rc) {
		rc = -EFAULT;
		mp_pr_err("%s: copyin dpaths %u failed", rc, unit->un_name, drv->drv_dpathssz);
		kfree(dpathv);
		return rc;
	}

	for (i = 0; i < drv->drv_dpathc; ++i) {
		dpathv[i] = strsep(&dpaths, "\n");
		if (!dpathv[i] || (strlen(dpathv[i]) > PATH_MAX - 1)) {
			rc = -EINVAL;
			mp_pr_err("%s: ill-formed dpathv list ", rc, unit->un_name);
			kfree(dpathv);
			return rc;
		}
	}

	/* Get the PDs properties from user space buffer. */
	pd_prop_sz = drv->drv_dpathc * sizeof(*pd_prop);

	pd_prop = kmalloc(pd_prop_sz, GFP_KERNEL);
	if (!pd_prop) {
		rc = -ENOMEM;
		mp_pr_err("%s: alloc pd prop %zu failed", rc, unit->un_name, pd_prop_sz);
		kfree(dpathv);
		return rc;
	}

	rc = copy_from_user(pd_prop, drv->drv_pd_prop, pd_prop_sz);
	if (rc) {
		rc = -EFAULT;
		mp_pr_err("%s: copyin pd prop %zu failed", rc, unit->un_name, pd_prop_sz);
		kfree(pd_prop);
		kfree(dpathv);
		return rc;
	}

	for (i = 0; i < drv->drv_dpathc; ++i) {
		rc = mpool_drive_add(desc, dpathv[i], &pd_prop[i]);
		if (rc)
			break;
	}

	kfree(pd_prop);
	kfree(dpathv);

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

static void *mpc_vcache_alloc(struct vcache *vc, size_t sz)
{
	void *p;

	if (!vc || sz > vc->vc_size)
		return NULL;

	spin_lock(&vc->vc_lock);
	p = vc->vc_head;
	if (p)
		vc->vc_head = *(void **)p;
	spin_unlock(&vc->vc_lock);

	return p;
}

static void mpc_vcache_free(struct vcache *vc, void *p)
{
	if (!vc || !p)
		return;

	spin_lock(&vc->vc_lock);
	*(void **)p = vc->vc_head;
	vc->vc_head = p;
	spin_unlock(&vc->vc_lock);
}

static int mpc_vcache_init(struct vcache *vc, size_t sz, size_t n)
{
	if (!vc || sz < PAGE_SIZE || n < 1)
		return -EINVAL;

	spin_lock_init(&vc->vc_lock);
	vc->vc_head = NULL;
	vc->vc_size = sz;

	while (n-- > 0)
		mpc_vcache_free(vc, vmalloc(sz));

	return vc->vc_head ? 0 : -ENOMEM;
}

static void mpc_vcache_fini(struct vcache *vc)
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
static int
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
	struct kvec        *iov_base, *iov;
	struct iov_iter     iter;
	struct page       **pagesv;

	size_t  pagesvsz, pgbase, length;
	int     pagesc, niov, rc, i;
	ssize_t cc;

	iov = NULL;
	niov = 0;
	rc = 0;

	length = iov_length(uiov, uioc);

	if (length < PAGE_SIZE || !IS_ALIGNED(length, PAGE_SIZE))
		return -EINVAL;

	if (length > (mpc_rwsz_max << 20))
		return -EINVAL;

	/*
	 * Allocate an array of page pointers for iov_iter_get_pages()
	 * and an array of iovecs for mblock_read() and mblock_write().
	 *
	 * Note: the only way we can calculate the number of required
	 * iovecs in advance is to assume that we need one per page.
	 */
	pagesc = length / PAGE_SIZE;
	pagesvsz = (sizeof(*pagesv) + sizeof(*iov)) * pagesc;

	/*
	 * pagesvsz may be big, and it will not be used as the iovec_list
	 * for the block stack - pd will chunk it up to the underlying
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
		return -ENOMEM;

	iov_base = (struct kvec *)((char *)pagesv + (sizeof(*pagesv) * pagesc));

#if HAVE_IOV_ITER_INIT_DIRECTION
	iov_iter_init(&iter, rw, uiov, uioc, length);
#else
	iov_iter_init(&iter, uiov, uioc, length, 0);
#endif

	for (i = 0, cc = 0; i < pagesc; i += (cc / PAGE_SIZE)) {

		/* Get struct page vector for the user buffers. */
#if HAVE_IOV_ITER_GET_PAGES
		cc = iov_iter_get_pages(&iter, &pagesv[i], length - (i * PAGE_SIZE),
					pagesc - i, &pgbase);
#else
		int npages = ((ulong)iter.iov->iov_len - iter.iov_offset + PAGE_SIZE - 1) /
			PAGE_SIZE;

		pgbase = ((ulong)iter.iov->iov_base + iter.iov_offset) & (PAGE_SIZE - 1);

		/*
		 * The 3rd parameter "write" should be true if this is a
		 * write to memory (passed in first parameter).
		 * Note that this is the inverse of the I/O direction.
		 */
		cc = get_user_pages_fast((ulong)iter.iov->iov_base + iter.iov_offset,
					 npages, (rw != WRITE), &pagesv[i]);

		/* This works because we require I/Os to be page-aligned & page multiple */
		if (cc > 0)
			cc = cc * PAGE_SIZE;
#endif

		if (cc < 0) {
			rc = cc;
			pagesc = i;
			goto errout;
		}

		/*
		 * pgbase is the offset into the 1st iovec - our alignment
		 * requirements force it to be 0
		 */
		if (cc < PAGE_SIZE || pgbase != 0) {
			rc = -EINVAL;
			pagesc = i + 1;
			goto errout;
		}

		iov_iter_advance(&iter, cc);
	}

	/* Build an array of iovecs for mpool so that it can directly access the user data. */
	for (i = 0, iov = iov_base; i < pagesc; ++i, ++iov, ++niov) {
		iov->iov_len = PAGE_SIZE;
		iov->iov_base = kmap(pagesv[i]);

		if (!iov->iov_base) {
			rc = -EINVAL;
			pagesc = i + 1;
			goto errout;
		}
	}

	switch (objtype) {
	case MP_OBJ_MBLOCK:
		if (rw == WRITE) {
			rc = mblock_write(mpd, desc, iov_base, niov, pagesc << PAGE_SHIFT);
		} else {
			rc = mblock_read(mpd, desc, iov_base, niov, offset, pagesc << PAGE_SHIFT);
		}
		break;

	case MP_OBJ_MLOG:
		rc = mlog_rw_raw(mpd, desc, iov_base, niov, offset, rw);
		break;

	default:
		rc = -EINVAL;
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

	return rc;
}

/**
 * mpioc_mb_alloc() - Allocate an mblock object.
 * @unit:   mpool or dataset unit ptr
 * @mb:     mblock parameter block
 *
 * MPIOC_MB_ALLOC ioctl handler to allocate a single mblock.
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_mb_alloc(struct mpc_unit *unit, struct mpioc_mblock *mb)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;
	struct mblock_props         props;
	int rc;

	if (!unit || !mb || !unit->un_mpool)
		return -EINVAL;

	mpool = unit->un_mpool->mp_desc;

	rc = mblock_alloc(mpool, mb->mb_mclassp, mb->mb_spare, &mblock, &props);
	if (rc)
		return rc;

	mblock_get_props_ex(mpool, mblock, &mb->mb_props);
	mblock_put(mblock);

	mb->mb_objid  = props.mpr_objid;
	mb->mb_offset = -1;

	return 0;
}

/**
 * mpioc_mb_find() - Find an mblock object by its objid
 * @unit:   mpool or dataset unit ptr
 * @mb:     mblock parameter block
 *
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_mb_find(struct mpc_unit *unit, struct mpioc_mblock *mb)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;
	int rc;

	if (!unit || !mb || !unit->un_mpool)
		return -EINVAL;

	if (!mblock_objid(mb->mb_objid))
		return -EINVAL;

	mpool = unit->un_mpool->mp_desc;

	rc = mblock_find_get(mpool, mb->mb_objid, 0, NULL, &mblock);
	if (rc)
		return rc;

	(void)mblock_get_props_ex(mpool, mblock, &mb->mb_props);

	mblock_put(mblock);

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
 * Return:  Returns 0 if successful, -errno otherwise...
 */
static int mpioc_mb_abcomdel(struct mpc_unit *unit, uint cmd, struct mpioc_mblock_id *mi)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;

	int which, rc;
	bool drop;

	if (!unit || !mi || !unit->un_mpool)
		return -EINVAL;

	if (!mblock_objid(mi->mi_objid))
		return -EINVAL;

	which = (cmd == MPIOC_MB_DELETE) ? 1 : -1;
	mpool = unit->un_mpool->mp_desc;
	drop = true;

	rc = mblock_find_get(mpool, mi->mi_objid, which, NULL, &mblock);
	if (rc)
		return rc;

	switch (cmd) {
	case MPIOC_MB_COMMIT:
		rc = mblock_commit(mpool, mblock);
		break;

	case MPIOC_MB_ABORT:
		rc = mblock_abort(mpool, mblock);
		drop = !!rc;
		break;

	case MPIOC_MB_DELETE:
		rc = mblock_delete(mpool, mblock);
		drop = !!rc;
		break;

	default:
		rc = -ENOTTY;
		break;
	}

	if (drop)
		mblock_put(mblock);

	return rc;
}

/**
 * mpioc_mb_rw() - read/write mblock ioctl handler
 * @unit:   dataset unit ptr
 * @cmd:    MPIOC_MB_READ or MPIOC_MB_WRITE
 * @mbiov:  mblock parameter block
 */
static int mpioc_mb_rw(struct mpc_unit *unit, uint cmd, struct mpioc_mblock_rw *mbrw,
		       void *stkbuf, size_t stkbufsz)
{
	struct mblock_descriptor   *mblock;
	struct mpool_descriptor    *mpool;
	struct iovec               *kiov;

	bool    xfree = false;
	int     which, rc;
	size_t  kiovsz;

	if (!unit || !mbrw || !unit->un_mpool)
		return -EINVAL;

	if (!mblock_objid(mbrw->mb_objid))
		return -EINVAL;

	/*
	 * For small iovec counts we simply copyin the array of iovecs
	 * to local storage (stkbuf).  Otherwise, we must kmalloc a
	 * buffer into which to perform the copyin.
	 */
	if (mbrw->mb_iov_cnt > MPIOC_KIOV_MAX)
		return -EINVAL;

	kiovsz = mbrw->mb_iov_cnt * sizeof(*kiov);

	if (kiovsz > stkbufsz) {
		kiov = kmalloc(kiovsz, GFP_KERNEL);
		if (!kiov)
			return -ENOMEM;

		xfree = true;
	} else {
		kiov = stkbuf;
		stkbuf += kiovsz;
		stkbufsz -= kiovsz;
	}

	which = (cmd == MPIOC_MB_READ) ? 1 : -1;
	mpool = unit->un_mpool->mp_desc;

	rc = mblock_find_get(mpool, mbrw->mb_objid, which, NULL, &mblock);
	if (rc)
		goto errout;

	if (copy_from_user(kiov, mbrw->mb_iov, kiovsz)) {
		rc = -EFAULT;
	} else {
		rc = mpc_physio(mpool, mblock, kiov, mbrw->mb_iov_cnt, mbrw->mb_offset,
				MP_OBJ_MBLOCK, (cmd == MPIOC_MB_READ) ? READ : WRITE,
				stkbuf, stkbufsz);
	}

	mblock_put(mblock);

errout:
	if (xfree)
		kfree(kiov);

	return rc;
}

/*
 * Mpctl mlog ioctl handlers
 */
static int mpioc_mlog_alloc(struct mpc_unit *unit, struct mpioc_mlog *ml)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct mlog_props           props;
	int rc;

	if (!unit || !unit->un_mpool || !ml)
		return -EINVAL;

	mpool = unit->un_mpool->mp_desc;

	rc = mlog_alloc(mpool, &ml->ml_cap, ml->ml_mclassp, &props, &mlog);
	if (rc)
		return rc;

	mlog_get_props_ex(mpool, mlog, &ml->ml_props);
	mlog_put(mlog);

	ml->ml_objid = props.lpr_objid;

	return 0;
}

static int mpioc_mlog_find(struct mpc_unit *unit, struct mpioc_mlog *ml)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	int rc;

	if (!unit || !unit->un_mpool || !ml || !mlog_objid(ml->ml_objid))
		return -EINVAL;

	mpool = unit->un_mpool->mp_desc;

	rc = mlog_find_get(mpool, ml->ml_objid, 0, NULL, &mlog);
	if (!rc) {
		rc = mlog_get_props_ex(mpool, mlog, &ml->ml_props);
		mlog_put(mlog);
	}

	return rc;
}

static int mpioc_mlog_abcomdel(struct mpc_unit *unit, uint cmd, struct mpioc_mlog_id *mi)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct mlog_props_ex        props;
	int                         which, rc;
	bool                        drop;

	if (!unit || !unit->un_mpool || !mi || !mlog_objid(mi->mi_objid))
		return -EINVAL;

	which = (cmd == MPIOC_MLOG_DELETE) ? 1 : -1;
	mpool = unit->un_mpool->mp_desc;
	drop = true;

	rc = mlog_find_get(mpool, mi->mi_objid, which, NULL, &mlog);
	if (rc)
		return rc;

	switch (cmd) {
	case MPIOC_MLOG_COMMIT:
		rc = mlog_commit(mpool, mlog);
		if (!rc) {
			mlog_get_props_ex(mpool, mlog, &props);
			mi->mi_gen   = props.lpx_props.lpr_gen;
			mi->mi_state = props.lpx_state;
		}
		break;

	case MPIOC_MLOG_ABORT:
		rc = mlog_abort(mpool, mlog);
		drop = !!rc;
		break;

	case MPIOC_MLOG_DELETE:
		rc = mlog_delete(mpool, mlog);
		drop = !!rc;
		break;

	default:
		rc = -ENOTTY;
		break;
	}

	if (drop)
		mlog_put(mlog);

	return rc;
}

static int mpioc_mlog_rw(struct mpc_unit *unit, struct mpioc_mlog_io *mi,
			 void *stkbuf, size_t stkbufsz)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct iovec               *kiov;

	bool    xfree = false;
	size_t  kiovsz;
	int     rc;

	if (!unit || !unit->un_mpool || !mi || !mlog_objid(mi->mi_objid))
		return -EINVAL;

	/*
	 * For small iovec counts we simply copyin the array of iovecs
	 * to the stack (kiov_buf). Otherwise, we must kmalloc a
	 * buffer into which to perform the copyin.
	 */
	if (mi->mi_iovc > MPIOC_KIOV_MAX)
		return -EINVAL;

	kiovsz = mi->mi_iovc * sizeof(*kiov);

	if (kiovsz > stkbufsz) {
		kiov = kmalloc(kiovsz, GFP_KERNEL);
		if (!kiov)
			return -ENOMEM;

		xfree = true;
	} else {
		kiov = stkbuf;
		stkbuf += kiovsz;
		stkbufsz -= kiovsz;
	}

	mpool = unit->un_mpool->mp_desc;

	rc = mlog_find_get(mpool, mi->mi_objid, 1, NULL, &mlog);
	if (rc)
		goto errout;

	if (copy_from_user(kiov, mi->mi_iov, kiovsz)) {
		rc = -EFAULT;
	} else {
		rc = mpc_physio(mpool, mlog, kiov, mi->mi_iovc, mi->mi_off, MP_OBJ_MLOG,
				(mi->mi_op == MPOOL_OP_READ) ? READ : WRITE, stkbuf, stkbufsz);
	}

	mlog_put(mlog);

errout:
	if (xfree)
		kfree(kiov);

	return rc;
}

static int mpioc_mlog_erase(struct mpc_unit *unit, struct mpioc_mlog_id *mi)
{
	struct mpool_descriptor    *mpool;
	struct mlog_descriptor     *mlog;
	struct mlog_props_ex        props;
	int rc;

	if (!unit || !unit->un_mpool || !mi || !mlog_objid(mi->mi_objid))
		return -EINVAL;

	mpool = unit->un_mpool->mp_desc;

	rc = mlog_find_get(mpool, mi->mi_objid, 0, NULL, &mlog);
	if (rc)
		return rc;

	rc = mlog_erase(mpool, mlog, mi->mi_gen);
	if (!rc) {
		mlog_get_props_ex(mpool, mlog, &props);
		mi->mi_gen   = props.lpx_props.lpr_gen;
		mi->mi_state = props.lpx_state;
	}

	mlog_put(mlog);

	return rc;
}

static struct mpc_softstate *mpc_cdev2ss(struct cdev *cdev)
{
	if (!cdev || cdev->owner != THIS_MODULE) {
		mp_pr_crit("module dissociated", -EINVAL);
		return NULL;
	}

	return container_of(cdev, struct mpc_softstate, ss_cdev);
}

static int mpc_bdi_alloc(void)
{
#if HAVE_BDI_INIT
	mpc_bdi = kzalloc(sizeof(*mpc_bdi), GFP_KERNEL);
	if (mpc_bdi) {
		int    rc;

		rc = bdi_init(mpc_bdi);
		if (rc) {
			kfree(mpc_bdi);
			return rc;
		}
	}
#elif HAVE_BDI_ALLOC_NODE
	mpc_bdi = bdi_alloc_node(GFP_KERNEL, NUMA_NO_NODE);
#else
	mpc_bdi = bdi_alloc(NUMA_NO_NODE);
#endif
	if (!mpc_bdi)
		return -ENOMEM;

	return 0;
}

static void mpc_bdi_save(struct mpc_unit *unit, struct inode *ip, struct file *fp)
{
#if HAVE_ADDRESS_SPACE_BDI
	unit->un_saved_bdi = fp->f_mapping->backing_dev_info;
	fp->f_mapping->backing_dev_info = mpc_bdi;
#else
	unit->un_saved_bdi = ip->i_sb->s_bdi;
#if HAVE_BDI_INIT
	ip->i_sb->s_bdi = mpc_bdi;
#else
	ip->i_sb->s_bdi = bdi_get(mpc_bdi);
#endif /* HAVE_BDI_INIT */
#endif /* HAVE_ADDRESS_SPACE_BDI */
}

static void mpc_bdi_restore(struct mpc_unit *unit, struct inode *ip, struct file *fp)
{
#if HAVE_ADDRESS_SPACE_BDI
	fp->f_mapping->backing_dev_info = unit->un_saved_bdi;
#else
	ip->i_sb->s_bdi = unit->un_saved_bdi;
#if !HAVE_BDI_INIT
	bdi_put(mpc_bdi);
#endif /* !HAVE_BDI_INIT */
#endif /* HAVE_ADDRESS_SPACE_BDI */
}

static int mpc_bdi_setup(void)
{
	int    rc;

	rc = mpc_bdi_alloc();
	if (rc)
		return rc;

#if HAVE_BDI_NAME
	mpc_bdi->name = "mpoolctl";
#endif
	mpc_bdi->capabilities = BDI_CAP_NO_ACCT_AND_WRITEBACK;
	mpc_bdi->ra_pages = MPOOL_RA_PAGES_MAX;

	return 0;
}

static void mpc_bdi_teardown(void)
{
#if HAVE_BDI_INIT
	bdi_destroy(mpc_bdi);
	kfree(mpc_bdi);
#else
	bdi_put(mpc_bdi);
#endif
}

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
	struct mpc_softstate   *ss;
	struct mpc_unit        *unit;

	bool    firstopen;
	int     rc = 0;

	ss = mpc_cdev2ss(ip->i_cdev);
	if (!ss || ss != &mpc_softstate)
		return -EBADFD;

	/* Acquire a reference on the unit object.  We'll release it in mpc_release(). */
	mpc_unit_lookup(iminor(fp->f_inode), &unit);
	if (!unit)
		return -ENODEV;

	if (down_trylock(&unit->un_open_lock)) {
		rc = (fp->f_flags & O_NONBLOCK) ? -EWOULDBLOCK :
			down_interruptible(&unit->un_open_lock);

		if (rc)
			goto errout;
	}

	firstopen = (unit->un_open_cnt == 0);

	if (!firstopen) {
		if (fp->f_mapping != unit->un_mapping)
			rc = -EBUSY;
		else if (unit->un_open_excl || (fp->f_flags & O_EXCL))
			rc = -EBUSY;
		goto unlock;
	}

	if (!mpc_unit_ismpooldev(unit)) {
		unit->un_open_excl = !!(fp->f_flags & O_EXCL);
		goto unlock; /* control device */
	}

	/* First open of an mpool unit (not the control device). */
	if (!fp->f_mapping || fp->f_mapping != ip->i_mapping) {
		rc = -EINVAL;
		goto unlock;
	}

	fp->f_op = &mpc_fops_default;
	fp->f_mapping->a_ops = &mpc_aops_default;

	mpc_bdi_save(unit, ip, fp);

	unit->un_mapping = fp->f_mapping;
	unit->un_ds_reap = mpc_reap;

	inode_lock(ip);
	i_size_write(ip, 1ul << 63);
	inode_unlock(ip);

	unit->un_open_excl = !!(fp->f_flags & O_EXCL);

unlock:
	if (!rc) {
		fp->private_data = unit;
		nonseekable_open(ip, fp);
		++unit->un_open_cnt;
	}
	up(&unit->un_open_lock);

errout:
	if (rc) {
		if (rc != -EBUSY)
			mp_pr_err("open %s failed", rc, unit->un_name);
		mpc_unit_put(unit);
	}

	return rc;
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
		mpc_rgnmap_flush(&unit->un_rgnmap);

		unit->un_ds_reap = NULL;
		unit->un_mapping = NULL;

		mpc_bdi_restore(unit, ip, fp);
	}

	unit->un_open_excl = false;

errout:
	up(&unit->un_open_lock);

	mpc_unit_put(unit);

	return 0;
}

/**
 * mpc_ioctl() - mpc driver ioctl entry point
 * @fp:     file pointer
 * @cmd:    an mpool ioctl command (i.e.,  MPIOC_*)
 * @arg:    varies..
 *
 * Perform the specified mpool ioctl command.
 *
 * Return:  Returns 0 on success, -errno otherwise...
 */
static long mpc_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	char argbuf[256] __aligned(16);
	struct mpc_unit *unit;

	size_t  argbufsz, stkbufsz;
	void   *argp, *stkbuf;
	ulong   iosz;
	int     rc;

	if (_IOC_TYPE(cmd) != MPIOC_MAGIC)
		return -ENOTTY;

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
			break;

		default:
			return -EINVAL;
		}
	}

	unit = fp->private_data;
	argbufsz = sizeof(argbuf);
	iosz = _IOC_SIZE(cmd);
	argp = (void *)arg;

	if (!unit || (iosz > sizeof(union mpioc_union)))
		return -EINVAL;

	/* Set up argp/argbuf for read/write requests. */
	if (_IOC_DIR(cmd) & (_IOC_READ | _IOC_WRITE)) {
		argp = argbuf;
		if (iosz > argbufsz) {
			argbufsz = roundup_pow_of_two(iosz);

			argp = kzalloc(argbufsz, GFP_KERNEL);
			if (!argp)
				return -ENOMEM;
		}

		if (_IOC_DIR(cmd) & _IOC_WRITE) {
			if (copy_from_user(argp, (const void __user *)arg, iosz)) {
				if (argp != argbuf)
					kfree(argp);
				return -EFAULT;
			}
		}
	}

	switch (cmd) {
	case MPIOC_MP_CREATE:
	case MPIOC_MP_ACTIVATE:
	case MPIOC_MP_DESTROY:
	case MPIOC_MP_RENAME:
		rc = mpioc_mp_cmd(unit, cmd, argp);
		break;

	case MPIOC_MP_DEACTIVATE:
		rc = mpioc_mp_deactivate(unit, argp);
		break;

	case MPIOC_DRV_ADD:
		rc = mpioc_mp_add(unit, argp);
		break;

	case MPIOC_PARAMS_SET:
		rc = mpioc_params_set(unit, argp);
		break;

	case MPIOC_PARAMS_GET:
		rc = mpioc_params_get(unit, argp);
		break;

	case MPIOC_MP_MCLASS_GET:
		rc = mpioc_mp_mclass_get(unit, argp);
		break;

	case MPIOC_PROP_GET:
		rc = mpioc_proplist_get(unit, argp);
		break;

	case MPIOC_DEVPROPS_GET:
		rc = mpioc_devprops_get(unit, argp);
		break;

	case MPIOC_MB_ALLOC:
		rc = mpioc_mb_alloc(unit, argp);
		break;

	case MPIOC_MB_FIND:
		rc = mpioc_mb_find(unit, argp);
		break;

	case MPIOC_MB_COMMIT:
	case MPIOC_MB_DELETE:
	case MPIOC_MB_ABORT:
		rc = mpioc_mb_abcomdel(unit, cmd, argp);
		break;

	case MPIOC_MB_READ:
	case MPIOC_MB_WRITE:
		ASSERT(roundup(iosz, 16) < argbufsz);

		stkbufsz = argbufsz - roundup(iosz, 16);
		stkbuf = argbuf + roundup(iosz, 16);

		rc = mpioc_mb_rw(unit, cmd, argp, stkbuf, stkbufsz);
		break;

	case MPIOC_MLOG_ALLOC:
		rc = mpioc_mlog_alloc(unit, argp);
		break;

	case MPIOC_MLOG_FIND:
	case MPIOC_MLOG_PROPS:
		rc = mpioc_mlog_find(unit, argp);
		break;

	case MPIOC_MLOG_ABORT:
	case MPIOC_MLOG_COMMIT:
	case MPIOC_MLOG_DELETE:
		rc = mpioc_mlog_abcomdel(unit, cmd, argp);
		break;

	case MPIOC_MLOG_READ:
	case MPIOC_MLOG_WRITE:
		ASSERT(roundup(iosz, 16) < argbufsz);

		stkbufsz = argbufsz - roundup(iosz, 16);
		stkbuf = argbuf + roundup(iosz, 16);

		rc = mpioc_mlog_rw(unit, argp, stkbuf, stkbufsz);
		break;

	case MPIOC_MLOG_ERASE:
		rc = mpioc_mlog_erase(unit, argp);
		break;

	case MPIOC_VMA_CREATE:
		rc = mpioc_xvm_create(unit, unit->un_mpool->mp_desc, argp);
		break;

	case MPIOC_VMA_DESTROY:
		rc = mpioc_xvm_destroy(unit, argp);
		break;

	case MPIOC_VMA_PURGE:
		rc = mpioc_xvm_purge(unit, argp);
		break;

	case MPIOC_VMA_VRSS:
		rc = mpioc_xvm_vrss(unit, argp);
		break;

	default:
		rc = -ENOTTY;
		mp_pr_rl("invalid command %x: dir=%u type=%c nr=%u size=%u",
			 rc, cmd, _IOC_DIR(cmd), _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
		break;
	}

	if (!rc && _IOC_DIR(cmd) & _IOC_READ) {
		if (copy_to_user((void __user *)arg, argp, iosz))
			rc = -EFAULT;
	}

	if (argp != argbuf)
		kfree(argp);

	return rc;
}

static const struct file_operations mpc_fops_default = {
	.owner		= THIS_MODULE,
	.open		= mpc_open,
	.release	= mpc_release,
	.unlocked_ioctl	= mpc_ioctl,
	.mmap           = mpc_mmap,
};

static int mpc_exit_unit(int minor, void *item, void *arg)
{
	mpc_unit_put(item);

	return ITERCB_NEXT;
}

/**
 * mpctl_exit() - Tear down and unload the mpool control module.
 */
void mpctl_exit(void)
{
	struct mpc_softstate   *ss = &mpc_softstate;

	if (ss->ss_inited) {
		idr_for_each(&ss->ss_unitmap, mpc_exit_unit, NULL);
		idr_destroy(&ss->ss_unitmap);

		if (ss->ss_devno != NODEV) {
			if (ss->ss_class) {
				if (ss->ss_cdev.ops)
					cdev_del(&ss->ss_cdev);
				class_destroy(ss->ss_class);
			}
			unregister_chrdev_region(ss->ss_devno, mpc_maxunits);
		}

		ss->ss_inited = false;
	}

	mpc_vcache_fini(&mpc_physio_vcache);

	mpc_bdi_teardown();
}

/**
 * mpctl_init() - Load and initialize the mpool control module.
 */
int mpctl_init(void)
{
	struct mpc_softstate   *ss = &mpc_softstate;
	struct mpool_config    *cfg = NULL;
	struct mpc_unit        *ctlunit;
	const char             *errmsg = NULL;
	size_t                  sz;
	int                     rc;

	if (ss->ss_inited)
		return -EBUSY;

	ctlunit = NULL;

	mpc_maxunits = clamp_t(uint, mpc_maxunits, 8, 8192);

	mpc_rwsz_max = clamp_t(ulong, mpc_rwsz_max, 1, 128);
	mpc_rwconc_max = clamp_t(ulong, mpc_rwconc_max, 1, 32);

	/* Must be same as mpc_physio() pagesvsz calculation. */
	sz = (mpc_rwsz_max << 20) / PAGE_SIZE;
	sz *= (sizeof(void *) + sizeof(struct iovec));

	rc = mpc_vcache_init(&mpc_physio_vcache, sz, mpc_rwconc_max);
	if (rc) {
		errmsg = "vcache init failed";
		goto errout;
	}

	cdev_init(&ss->ss_cdev, &mpc_fops_default);
	ss->ss_cdev.owner = THIS_MODULE;

	mutex_init(&ss->ss_lock);
	idr_init(&ss->ss_unitmap);
	ss->ss_class = NULL;
	ss->ss_devno = NODEV;
	sema_init(&ss->ss_op_sema, 1);
	ss->ss_inited = true;

	rc = alloc_chrdev_region(&ss->ss_devno, 0, mpc_maxunits, "mpool");
	if (rc) {
		errmsg = "cannot allocate control device major";
		ss->ss_devno = NODEV;
		goto errout;
	}

	ss->ss_class = class_create(THIS_MODULE, module_name(THIS_MODULE));
	if (IS_ERR(ss->ss_class)) {
		errmsg = "class_create() failed";
		rc = PTR_ERR(ss->ss_class);
		ss->ss_class = NULL;
		goto errout;
	}

	ss->ss_class->dev_uevent = mpc_uevent;

	rc = cdev_add(&ss->ss_cdev, ss->ss_devno, mpc_maxunits);
	if (rc) {
		errmsg = "cdev_add() failed";
		ss->ss_cdev.ops = NULL;
		goto errout;
	}

	rc = mpc_bdi_setup();
	if (rc) {
		errmsg = "mpc bdi setup failed";
		goto errout;
	}

	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (!cfg) {
		errmsg = "cfg alloc failed";
		rc = -ENOMEM;
		goto errout;
	}

	cfg->mc_uid = mpc_ctl_uid;
	cfg->mc_gid = mpc_ctl_gid;
	cfg->mc_mode = mpc_ctl_mode;

	rc = mpc_unit_setup(&mpc_uinfo_ctl, MPC_DEV_CTLNAME, cfg, NULL, &ctlunit);
	if (rc) {
		errmsg = "cannot create control device";
		goto errout;
	}

	/* The reaper component has already been initialized before mpctl. */
	ctlunit->un_ds_reap = mpc_reap;
	rc = mpc_params_register(ctlunit, MPC_REAP_PARAMS_CNT);
	if (rc) {
		errmsg = "cannot register common parameters";
		goto errout;
	}

	mutex_lock(&ss->ss_lock);
	idr_replace(&ss->ss_unitmap, ctlunit, MINOR(ctlunit->un_devno));
	mutex_unlock(&ss->ss_lock);

	dev_info(ctlunit->un_device, "version %s", MPOOL_VERSION);

	mpc_unit_put(ctlunit);

errout:
	if (rc) {
		mp_pr_err("%s", rc, errmsg);
		mpctl_exit();
	}

	kfree(cfg);

	return rc;
}
