// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Space map module.
 *
 * Implements space maps for managing free space on drives.
 */

#include <linux/log2.h>
#include <linux/delay.h>

#include "mpcore_defs.h"

static merr_t smap_drive_sballoc(struct mpool_descriptor *mp, u16 pdh);

/*
 * smap API functions
 */

static struct smap_zone *smap_zone_find(struct rb_root *root, u64 key)
{
	struct rb_node *node = root->rb_node;
	struct smap_zone *elem;

	while (node) {
		elem = rb_entry(node, typeof(*elem), smz_node);

		if (key < elem->smz_key)
			node = node->rb_left;
		else if (key > elem->smz_key)
			node = node->rb_right;
		else
			return elem;
	}

	return NULL;
}

static int smap_zone_insert(struct rb_root *root, struct smap_zone *item)
{
	struct rb_node **pos = &root->rb_node, *parent = NULL;
	struct smap_zone *this;

	/* Figure out where to put new node */
	while (*pos) {
		this = rb_entry(*pos, typeof(*this), smz_node);
		parent = *pos;

		if (item->smz_key < this->smz_key)
			pos = &(*pos)->rb_left;
		else if (item->smz_key > this->smz_key)
			pos = &(*pos)->rb_right;
		else
			return false;
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&item->smz_node, parent, pos);
	rb_insert_color(&item->smz_node, root);

	return true;
}

/**
 * See smap.h.
 */
merr_t smap_mpool_init(struct mpool_descriptor *mp)
{
	merr_t                 err = 0;
	u64                    pdh = 0;
	struct mpool_dev_info *pd  = NULL;
	struct media_class    *mc;

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++) {
		struct mc_smap_parms   mcsp;

		pd = &mp->pds_pdv[pdh];
		mc = &mp->pds_mc[pd->pdi_mclass];
		err = mc_smap_parms_get(mp, mc->mc_parms.mcp_classp, &mcsp);
		if (ev(err))
			break;

		err = smap_drive_init(mp, &mcsp, pdh);
		if (err) {
			mp_pr_err("smap(%s, %s): drive init failed",
				  err, mp->pds_name, pd->pdi_name);
			break;
		}
	}

	if (err)
		smap_mpool_free(mp);

	return err;
}

/**
 * See smap.h.
 */
void smap_mpool_free(struct mpool_descriptor *mp)
{
	u64 pdh = 0;

	for (pdh = 0; pdh < mp->pds_pdvcnt; pdh++)
		smap_drive_free(mp, pdh);
}

/**
 * See smap.h.
 */
void smap_mpool_usage(struct mpool_descriptor *mp, u8 mclass, struct mp_usage *usage)
{
	if (mclass == MP_MED_ALL) {
		u32 i;

		for (i = 0; i < MP_MED_NUMBER; i++)
			smap_mclass_usage(mp, i, usage);
	} else {
		smap_mclass_usage(mp, mclass, usage);
	}
}

merr_t smap_drive_spares(struct mpool_descriptor *mp, enum mp_media_classp mclassp, u8 spzone)
{
	struct mpool_dev_info *pd = NULL;
	struct media_class    *mc;
	merr_t                 err;
	u8                     i;

	if (!mclass_isvalid(mclassp) || spzone > 100) {
		err = merr(EINVAL);
		mp_pr_err("smap mpool %s: smap drive spares failed mclassp %d spzone %u",
			  err, mp->pds_name, mclassp, spzone);
		return err;
	}

	/* Loop on all classes matching mclassp. */
	for (i = 0; i < MP_MED_NUMBER; i++) {
		mc = &mp->pds_mc[i];
		if (mc->mc_parms.mcp_classp != mclassp || mc->mc_pdmc < 0)
			continue;

		pd = &mp->pds_pdv[mc->mc_pdmc];

		spin_lock(&pd->pdi_ds.sda_dalock);
		/*
		 * adjust utgt but not uact; possible for uact > utgt
		 * due to spzone change
		 */
		pd->pdi_ds.sda_utgt =
			(pd->pdi_ds.sda_zoneeff * (100 - spzone)) / 100;
		/*
		 * adjust stgt and sact maintaining invariant that
		 * sact <= stgt
		 */
		pd->pdi_ds.sda_stgt =
			pd->pdi_ds.sda_zoneeff - pd->pdi_ds.sda_utgt;
		if (pd->pdi_ds.sda_sact > pd->pdi_ds.sda_stgt) {
			pd->pdi_ds.sda_uact +=
				(pd->pdi_ds.sda_sact - pd->pdi_ds.sda_stgt);
			pd->pdi_ds.sda_sact = pd->pdi_ds.sda_stgt;
		}
		spin_unlock(&pd->pdi_ds.sda_dalock);

	}
	return 0;
}

/*
 * Compute zone stats for drive pd per comments in smap_dev_alloc.
 */
static void smap_calc_znstats(struct mpool_dev_info *pd, struct smap_dev_znstats *zones)
{
	zones->sdv_total = pd->pdi_parm.dpr_zonetot;
	zones->sdv_avail = pd->pdi_ds.sda_zoneeff;
	zones->sdv_usable = pd->pdi_ds.sda_utgt;

	if (pd->pdi_ds.sda_utgt > pd->pdi_ds.sda_uact)
		zones->sdv_fusable = pd->pdi_ds.sda_utgt -
				    pd->pdi_ds.sda_uact;
	else
		zones->sdv_fusable = 0;

	zones->sdv_spare = pd->pdi_ds.sda_stgt;
	zones->sdv_fspare = pd->pdi_ds.sda_stgt - pd->pdi_ds.sda_sact;
	zones->sdv_used = pd->pdi_ds.sda_uact;
}

/**
 * See smap.h.
 */
merr_t smap_drive_usage(struct mpool_descriptor *mp, u16 pdh, struct mp_devprops *dprop)
{
	struct smap_dev_znstats zones;
	struct mpool_dev_info   *pd = &mp->pds_pdv[pdh];
	u32                      zonepg = 0;

	zonepg = pd->pdi_parm.dpr_zonepg;

	spin_lock(&pd->pdi_ds.sda_dalock);
	smap_calc_znstats(pd, &zones);
	spin_unlock(&pd->pdi_ds.sda_dalock);

	dprop->pdp_total = (zones.sdv_total * zonepg) << PAGE_SHIFT;
	dprop->pdp_avail = (zones.sdv_avail * zonepg) << PAGE_SHIFT;
	dprop->pdp_spare = (zones.sdv_spare * zonepg) << PAGE_SHIFT;
	dprop->pdp_fspare = (zones.sdv_fspare * zonepg) << PAGE_SHIFT;
	dprop->pdp_usable = (zones.sdv_usable * zonepg) << PAGE_SHIFT;
	dprop->pdp_fusable = (zones.sdv_fusable * zonepg) << PAGE_SHIFT;
	dprop->pdp_used = (zones.sdv_used * zonepg) << PAGE_SHIFT;

	return 0;
}

/**
 * See smap.h.
 */
merr_t smap_drive_init(struct mpool_descriptor *mp, struct mc_smap_parms *mcsp, u16 pdh)
{
	struct mpool_dev_info *pd __maybe_unused;
	merr_t                 err;

	pd = &mp->pds_pdv[pdh];

	if ((mcsp->mcsp_spzone > 100) || !(mcsp->mcsp_rgnc > 0)) {
		err = merr(EINVAL);
		mp_pr_err("smap(%s, %s): drive init failed, spzone %u rcnt %lu", err, mp->pds_name,
			  pd->pdi_name, mcsp->mcsp_spzone, (ulong)mcsp->mcsp_rgnc);
		return merr(EINVAL);
	}

	err = smap_drive_alloc(mp, mcsp, pdh);
	if (!err) {
		err = smap_drive_sballoc(mp, pdh);
		if (err)
			mp_pr_err("smap(%s, %s): sb alloc failed", err, mp->pds_name, pd->pdi_name);
	} else {
		mp_pr_err("smap(%s, %s): drive alloc failed", err, mp->pds_name, pd->pdi_name);
	}

	if (err)
		smap_drive_free(mp, pdh);

	return err;
}

/**
 * See smap.h.
 */
void smap_drive_free(struct mpool_descriptor *mp, u16 pdh)
{
	struct mpool_dev_info *pd = &mp->pds_pdv[pdh];
	u8                     rgn = 0;

	if (pd->pdi_rmbktv) {
		struct media_class     *mc;
		struct mc_smap_parms    mcsp;

		mc = &mp->pds_mc[pd->pdi_mclass];
		(void)mc_smap_parms_get(mp, mc->mc_parms.mcp_classp, &mcsp);

		for (rgn = 0; rgn < mcsp.mcsp_rgnc; rgn++) {
			struct smap_zone   *zone, *tmp;
			struct rb_root     *root;

			root = &pd->pdi_rmbktv[rgn].pdi_rmroot;

			rbtree_postorder_for_each_entry_safe(
				zone, tmp, root, smz_node) {

				kmem_cache_free(smap_zone_cache, zone);
			}
		}

		kfree(pd->pdi_rmbktv);
		pd->pdi_rmbktv = NULL;
	}

	pd->pdi_ds.sda_rgnsz = 0;
	pd->pdi_ds.sda_rgnladdr = 0;
	pd->pdi_ds.sda_rgnalloc = 0;
	pd->pdi_ds.sda_zoneeff = 0;
	pd->pdi_ds.sda_utgt = 0;
	pd->pdi_ds.sda_uact = 0;
}

static bool smap_alloccheck(struct mpool_dev_info *pd, u64 zonecnt, enum smap_space_type sapolicy)
{
	struct smap_dev_alloc *ds;

	u64   zoneextra;
	bool  alloced = false;

	ds = &pd->pdi_ds;

	spin_lock(&ds->sda_dalock);

	switch (sapolicy) {

	case SMAP_SPC_USABLE_ONLY:
		if ((ds->sda_uact + zonecnt) > ds->sda_utgt)
			break;

		ds->sda_uact = ds->sda_uact + zonecnt;
		alloced = true;
		break;

	case SMAP_SPC_SPARE_ONLY:
		if ((ds->sda_sact + zonecnt) > ds->sda_stgt)
			break;

		ds->sda_sact = ds->sda_sact + zonecnt;
		alloced = true;
		break;

	case SMAP_SPC_USABLE_2_SPARE:
		if ((ds->sda_uact + ds->sda_sact + zonecnt) > ds->sda_zoneeff)
			break;

		if ((ds->sda_uact + zonecnt) <= ds->sda_utgt) {
			ds->sda_uact = ds->sda_uact + zonecnt;
		} else {
			zoneextra = (ds->sda_uact + zonecnt) - ds->sda_utgt;
			ds->sda_uact = ds->sda_utgt;
			ds->sda_sact = ds->sda_sact + zoneextra;
		}
		alloced = true;
		break;

	case SMAP_SPC_SPARE_2_USABLE:
		if ((ds->sda_sact + ds->sda_uact + zonecnt) > ds->sda_zoneeff)
			break;

		if ((ds->sda_sact + zonecnt) <= ds->sda_stgt) {
			ds->sda_sact = ds->sda_sact + zonecnt;
		} else {
			zoneextra = (ds->sda_sact + zonecnt) - ds->sda_stgt;
			ds->sda_sact = ds->sda_stgt;
			ds->sda_uact = ds->sda_uact + zoneextra;
		}
		alloced = true;
		break;

	default:
		break;
	}

	spin_unlock(&ds->sda_dalock);

	return alloced;
}

/**
 * See smap.h.
 */
merr_t
smap_alloc(
	struct mpool_descriptor *mp,
	u16                      pdh,
	u64                      zonecnt,
	enum smap_space_type     sapolicy,
	u64                     *zoneaddr,
	u64                      align)
{
	struct mpool_dev_info *pd;
	struct smap_dev_alloc *ds;
	struct mutex          *rmlock = NULL;
	struct rb_root        *rmap = NULL;
	struct smap_zone  *elem = NULL;
	struct media_class    *mc;
	struct mc_smap_parms   mcsp;
	merr_t err;
	u64    fsoff = 0;
	u64    fslen = 0;
	u64    ualen = 0;
	s8     rgnleft;
	bool   res;
	u8     rgn  = 0;
	u8     rgnc;

	*zoneaddr = 0;
	pd = &mp->pds_pdv[pdh];

	if (ev(!zonecnt || !saptype_valid(sapolicy)))
		return merr(EINVAL);

	assert(is_power_of_2(align));

	ds = &pd->pdi_ds;
	mc = &mp->pds_mc[pd->pdi_mclass];
	err = mc_smap_parms_get(mp, mc->mc_parms.mcp_classp, &mcsp);
	if (ev(err))
		return err;
	rgnc = mcsp.mcsp_rgnc;

	/*
	 * We do not update the last rgn alloced beyond this point as it
	 * would incur search penalty if all the regions except one are highly
	 * fragmented, i.e., the last alloc rgn would never change in
	 * this case.
	 */
	spin_lock(&ds->sda_dalock);
	ds->sda_rgnalloc = (ds->sda_rgnalloc + 1) % rgnc;
	rgn = ds->sda_rgnalloc;
	spin_unlock(&ds->sda_dalock);

	rgnleft = rgnc;

	/* Search per-rgn space maps for contiguous region. */
	while (rgnleft--) {
		struct rb_node        *node;

		rmlock = &pd->pdi_rmbktv[rgn].pdi_rmlock;
		rmap = &pd->pdi_rmbktv[rgn].pdi_rmroot;

		mutex_lock(rmlock);

		for (node = rb_first(rmap); node; node = rb_next(node)) {
			elem  = rb_entry(node, struct smap_zone, smz_node);
			fsoff = elem->smz_key;
			fslen = elem->smz_value;

			if (zonecnt > fslen)
				continue;

			if (IS_ALIGNED(fsoff, align)) {
				ualen = 0;
				break;
			}

			ualen = ALIGN(fsoff, align) - fsoff;
			if (ualen + zonecnt > fslen)
				continue;

			break;
		}

		if (node)
			break;

		mutex_unlock(rmlock);

		rgn = (rgn + 1) % rgnc;
	}

	if (rgnleft < 0)
		return merr(ENOSPC);

	/* Alloc from this free space if permitted. First fit. */
	res = smap_alloccheck(pd, zonecnt, sapolicy);
	if (!res) {
		mutex_unlock(rmlock);
		return merr(ENOSPC);
	}

	fsoff = fsoff + ualen;
	fslen = fslen - ualen;

	*zoneaddr = fsoff;
	rb_erase(&elem->smz_node, rmap);

	if (zonecnt < fslen) {
		/* Re-use elem */
		elem->smz_key   = fsoff + zonecnt;
		elem->smz_value = fslen - zonecnt;
		smap_zone_insert(rmap, elem);
		elem = NULL;
	}

	if (ualen) {
		if (!elem) {
			elem = kmem_cache_alloc(smap_zone_cache,
						GFP_ATOMIC);
			if (ev(!elem)) {
				mutex_unlock(rmlock);
				return merr(ENOMEM);
			}
		}

		elem->smz_key   = fsoff - ualen;
		elem->smz_value = ualen;
		smap_zone_insert(rmap, elem);
		elem = NULL;
	}

	mutex_unlock(rmlock);

	if (elem)
		kmem_cache_free(smap_zone_cache, elem);

	return 0;
}

/**
 * See smap.h.
 */
/*
 * smap internal functions
 */

/*
 * Init empty space map for drive pdh with a % spare zones of spzone.
 * Returns: 0 if successful, merr_t otherwise
 */
merr_t smap_drive_alloc(struct mpool_descriptor *mp, struct mc_smap_parms *mcsp, u16 pdh)
{
	struct mpool_dev_info *pd = &mp->pds_pdv[pdh];
	u8                     rgn = 0;
	u8                     rgn2 = 0;
	struct smap_zone  *urb_elem = NULL;
	struct smap_zone  *found_ue = NULL;
	u32                    rgnsz = 0;
	merr_t                 err;
	u8                     rgnc;

	rgnc  = mcsp->mcsp_rgnc;
	rgnsz = pd->pdi_parm.dpr_zonetot / rgnc;
	if (!rgnsz) {
		err = merr(EINVAL);
		mp_pr_err("smap(%s, %s): drive alloc failed, invalid rgn size",
			  err, mp->pds_name, pd->pdi_name);
		return err;
	}

	/* allocate and init per channel space maps and associated locks */
	pd->pdi_rmbktv = kcalloc(rgnc, sizeof(*pd->pdi_rmbktv), GFP_KERNEL);
	if (!pd->pdi_rmbktv) {
		err = merr(ENOMEM);
		mp_pr_err("smap(%s, %s): rmbktv alloc failed", err, mp->pds_name, pd->pdi_name);
		return err;
	}

	/* define all space on all channels as being free (drive empty) */
	for (rgn = 0; rgn < rgnc; rgn++) {
		mutex_init(&pd->pdi_rmbktv[rgn].pdi_rmlock);

		urb_elem = kmem_cache_alloc(smap_zone_cache, GFP_KERNEL);
		if (!urb_elem) {
			struct rb_root *rmroot;

			for (rgn2 = 0; rgn2 < rgn; rgn2++) {
				rmroot = &pd->pdi_rmbktv[rgn2].pdi_rmroot;

				found_ue = smap_zone_find(rmroot, 0);
				if (found_ue) {
					rb_erase(&found_ue->smz_node, rmroot);
					kmem_cache_free(smap_zone_cache,
							found_ue);
				}
			}

			kfree(pd->pdi_rmbktv);
			pd->pdi_rmbktv = NULL;

			err = merr(ENOMEM);
			mp_pr_err("smap(%s, %s): rb node alloc failed, rgn %u",
				  err, mp->pds_name, pd->pdi_name, rgn);
			return err;
		}

		urb_elem->smz_key = rgn * rgnsz;
		if (rgn < rgnc - 1)
			urb_elem->smz_value = rgnsz;
		else
			urb_elem->smz_value = pd->pdi_parm.dpr_zonetot -
					      (rgn * rgnsz);
		smap_zone_insert(&pd->pdi_rmbktv[rgn].pdi_rmroot, urb_elem);
	}

	spin_lock_init(&pd->pdi_ds.sda_dalock);
	pd->pdi_ds.sda_rgnalloc = 0;
	pd->pdi_ds.sda_rgnsz = rgnsz;
	pd->pdi_ds.sda_rgnladdr = (rgnc - 1) * rgnsz;
	pd->pdi_ds.sda_zoneeff = pd->pdi_parm.dpr_zonetot;
	pd->pdi_ds.sda_utgt = (pd->pdi_ds.sda_zoneeff *
			       (100 - mcsp->mcsp_spzone)) / 100;
	pd->pdi_ds.sda_uact = 0;
	pd->pdi_ds.sda_stgt = pd->pdi_ds.sda_zoneeff - pd->pdi_ds.sda_utgt;
	pd->pdi_ds.sda_sact = 0;

	return 0;
}

/*
 * Add entry to space map covering superblocks on drive pdh.
 * Returns: 0 if successful, merr_t otherwise
 */
static merr_t smap_drive_sballoc(struct mpool_descriptor *mp, u16 pdh)
{
	struct mpool_dev_info *pd = &mp->pds_pdv[pdh];
	merr_t err;
	u32    cnt;

	cnt = sb_zones_for_sbs(&(pd->pdi_prop));
	if (cnt < 1) {
		err = merr(ESPIPE);
		mp_pr_err("smap(%s, %s): identifying sb failed", err, mp->pds_name, pd->pdi_name);
		return err;
	}

	err = smap_insert(mp, pdh, 0, cnt);
	if (err) {
		mp_pr_err("smap(%s, %s): insert failed, cnt %u",
			  err, mp->pds_name, pd->pdi_name, cnt);
		return err;
	}

	return err;
}

void smap_mclass_usage(struct mpool_descriptor *mp, u8 mclass, struct mp_usage *usage)
{
	struct media_class         *mc;
	struct smap_dev_znstats     zones;
	struct mpool_dev_info      *pd;
	u32                         zonepg = 0;

	mc = &mp->pds_mc[mclass];
	if (mc->mc_pdmc < 0)
		return;

	pd = &mp->pds_pdv[mc->mc_pdmc];
	zonepg = pd->pdi_zonepg;

	spin_lock(&pd->pdi_ds.sda_dalock);
	smap_calc_znstats(pd, &zones);
	spin_unlock(&pd->pdi_ds.sda_dalock);

	usage->mpu_total  += ((zones.sdv_total * zonepg) << PAGE_SHIFT);
	usage->mpu_usable += ((zones.sdv_usable * zonepg) << PAGE_SHIFT);
	usage->mpu_used   += ((zones.sdv_used * zonepg) << PAGE_SHIFT);
	usage->mpu_spare  += ((zones.sdv_spare * zonepg) << PAGE_SHIFT);
	usage->mpu_fspare += ((zones.sdv_fspare * zonepg) << PAGE_SHIFT);
	usage->mpu_fusable += ((zones.sdv_fusable * zonepg) << PAGE_SHIFT);
}

static u32 smap_addr2rgn(struct mpool_descriptor *mp, struct mpool_dev_info *pd, u64 zoneaddr)
{
	struct mc_smap_parms   mcsp;

	mc_smap_parms_get(mp, pd->pdi_mclass, &mcsp);

	if (zoneaddr >= pd->pdi_ds.sda_rgnladdr)
		return mcsp.mcsp_rgnc - 1;

	return zoneaddr / pd->pdi_ds.sda_rgnsz;
}

/*
 * Add entry to space map in rgn starting at virtual erase block zoneaddr
 * and continuing for zonecnt blocks.
 *
 *   Returns: 0 if successful, merr_t otherwise
 */
merr_t smap_insert_byrgn(struct mpool_dev_info *pd, u32 rgn, u64 zoneaddr, u16 zonecnt)
{
	const char             *msg __maybe_unused;
	struct smap_zone   *elem = NULL;
	struct rb_root         *rmap;
	struct rb_node         *node;
	merr_t                  err;
	u64                     fsoff;
	u64                     fslen;

	fsoff = fslen = 0;
	err = 0;
	msg = NULL;

	mutex_lock(&pd->pdi_rmbktv[rgn].pdi_rmlock);
	rmap = &pd->pdi_rmbktv[rgn].pdi_rmroot;

	node = rmap->rb_node;
	if (!node) {
		msg = "invalid rgn map";
		err = merr(EINVAL);
		goto errout;
	}

	/* Use binary search to find the insertion point in the tree.
	 */
	while (node) {
		elem = rb_entry(node, struct smap_zone, smz_node);

		if (zoneaddr < elem->smz_key)
			node = node->rb_left;
		else if (zoneaddr > elem->smz_key + elem->smz_value)
			node = node->rb_right;
		else
			break;
	}

	fsoff = elem->smz_key;
	fslen = elem->smz_value;

	/* Bail out if we're past zoneaddr in space map w/o finding
	 * the required chunk.
	 */
	if (zoneaddr < fsoff) {
		elem = NULL;
		msg = "requested range not free";
		err = merr(EINVAL);
		goto errout;
	}

	/* The allocation must fit entirely within this chunk or it fails.
	 */
	if (zoneaddr + zonecnt > fsoff + fslen) {
		elem = NULL;
		msg = "requested range does not fit";
		err = merr(EINVAL);
		goto errout;
	}

	rb_erase(&elem->smz_node, rmap);

	if (zoneaddr > fsoff) {
		elem->smz_key = fsoff;
		elem->smz_value = zoneaddr - fsoff;
		smap_zone_insert(rmap, elem);
		elem = NULL;
	}
	if (zoneaddr + zonecnt < fsoff + fslen) {
		if (!elem)
			elem = kmem_cache_alloc(
				smap_zone_cache, GFP_KERNEL);
		if (!elem) {
			msg = "chunk alloc failed";
			err = merr(ENOMEM);
			goto errout;
		}

		elem->smz_key = zoneaddr + zonecnt;
		elem->smz_value = (fsoff + fslen) - (zoneaddr + zonecnt);
		smap_zone_insert(rmap, elem);
		elem = NULL;
	}

	/* Insert consumes usable only; possible for uact > utgt.
	 */
	spin_lock(&pd->pdi_ds.sda_dalock);
	pd->pdi_ds.sda_uact = pd->pdi_ds.sda_uact + zonecnt;
	spin_unlock(&pd->pdi_ds.sda_dalock);

errout:
	mutex_unlock(&pd->pdi_rmbktv[rgn].pdi_rmlock);

	if (elem != NULL) {
		/* Was an exact match */
		assert((zoneaddr == fsoff) && (zonecnt == fslen));
		kmem_cache_free(smap_zone_cache, elem);
	}

	if (err)
		mp_pr_err("smap pd %s: %s, zoneaddr %lu zonecnt %u fsoff %lu fslen %lu",
			  err, pd->pdi_name, msg ? msg : "(no detail)",
			  (ulong)zoneaddr, zonecnt, (ulong)fsoff, (ulong)fslen);

	return err;
}

/**
 * See smap.h.
 */
merr_t smap_insert(struct mpool_descriptor *mp, u16 pdh, u64 zoneaddr, u32 zonecnt)
{
	merr_t                 err = 0;
	struct mpool_dev_info *pd = &mp->pds_pdv[pdh];
	u32                    rstart = 0;
	u32                    rend = 0;
	u64                    zoneadded = 0; /* can this be u32 */
	int                    rgn = 0;
	u64                    raddr = 0;
	u64                    rcnt = 0;

	if (zoneaddr >= pd->pdi_parm.dpr_zonetot ||
	    (zoneaddr + zonecnt) > pd->pdi_parm.dpr_zonetot) {
		err = merr(EINVAL);
		mp_pr_err("smap(%s, %s): insert failed, zoneaddr %lu zonecnt %u zonetot %u",
			  err, mp->pds_name, pd->pdi_name, (ulong)zoneaddr,
			  zonecnt, pd->pdi_parm.dpr_zonetot);
		return err;
	}

	/*
	 * smap_alloc() never crosses regions. however a previous instantiation
	 * of this mpool might have used a different value of rgn count
	 * so must handle inserts that cross regions.
	 */
	rstart = smap_addr2rgn(mp, pd, zoneaddr);
	rend = smap_addr2rgn(mp, pd, zoneaddr + zonecnt - 1);
	zoneadded = 0;

	for (rgn = rstart; rgn < rend + 1; rgn++) {
		/* compute zone address and count for this rgn */
		if (rgn == rstart)
			raddr = zoneaddr;
		else
			raddr = (u64)rgn * pd->pdi_ds.sda_rgnsz;

		if (rgn < rend)
			rcnt = ((rgn + 1) * pd->pdi_ds.sda_rgnsz) - raddr;
		else
			rcnt = zonecnt - zoneadded;

		err = smap_insert_byrgn(pd, rgn, raddr, rcnt);
		if (err) {
			mp_pr_err("smap(%s, %s): insert byrgn failed, rgn %d raddr %lu rcnt %lu",
				  err, mp->pds_name, pd->pdi_name, rgn, (ulong)raddr, (ulong)rcnt);
			break;
		}
		zoneadded = zoneadded + rcnt;
	}

	return err;
}


/**
 * smap_free_byrgn() - free the specified range of zones
 * @pd:         physical device object
 * @rgn:       allocation rgn specifier
 * @zoneaddr:    offset into the space map
 * @zonecnt:     length of range to be freed
 *
 * Free the given range of zone (i.e., [%zoneaddr, %zoneaddr + %zonecnt])
 * back to the indicated space map.  Always coalesces ranges in the space
 * map that abut the range to be freed so as to minimize fragmentation.
 *
 * Return: 0 if successful, merr_t otherwise
 */
static merr_t smap_free_byrgn(struct mpool_dev_info *pd, u32 rgn, u64 zoneaddr, u32 zonecnt)
{
	const char             *msg __maybe_unused;
	struct smap_zone   *left, *right;
	struct smap_zone   *new, *old;
	struct rb_root         *rmap;
	struct rb_node         *node;

	u32     orig_zonecnt = zonecnt;
	merr_t  err = 0;

	new = old = left = right = NULL;
	msg = NULL;

	mutex_lock(&pd->pdi_rmbktv[rgn].pdi_rmlock);
	rmap = &pd->pdi_rmbktv[rgn].pdi_rmroot;

	node = rmap->rb_node;

	/* Use binary search to find chunks to the left and/or right
	 * of the range being freed.
	 */
	while (node) {
		struct smap_zone *this;

		this = rb_entry(node, struct smap_zone, smz_node);

		if (zoneaddr + zonecnt <= this->smz_key) {
			right = this;
			node = node->rb_left;
		} else if (zoneaddr >= this->smz_key + this->smz_value) {
			left = this;
			node = node->rb_right;
		} else {
			msg = "chunk overlapping";
			err = merr(ev(EINVAL));
			goto unlock;
		}
	}

	/* If the request abuts the chunk to the right then coalesce them.
	 */
	if (right) {
		if (zoneaddr + zonecnt == right->smz_key) {
			zonecnt += right->smz_value;
			rb_erase(&right->smz_node, rmap);

			new = right;  /* re-use right node */
		}
	}

	/* If the request abuts the chunk to the left then coalesce them.
	 */
	if (left) {
		if (left->smz_key + left->smz_value == zoneaddr) {
			zoneaddr = left->smz_key;
			zonecnt += left->smz_value;
			rb_erase(&left->smz_node, rmap);

			old = new;  /* free new/left outside the critsec */
			new = left; /* re-use left node */
		}
	}

	/* If the request did not abut either the current or the previous
	 * chunk (i.e., new == NULL) then we must create a new chunk node
	 * and insert it into the smap.  Otherwise, we'll re-use one of
	 * the abutting chunk nodes (i.e., left or right).
	 *
	 * Note: If we have to call kmalloc and it fails (unlikely) then
	 * this chunk will be lost only for the current session.  It will
	 * be recovered once the mpool is closed and re-opened.
	 */
	if (!new) {
		new = kmem_cache_alloc(smap_zone_cache, GFP_ATOMIC);
		if (!new) {
			msg = "chunk alloc failed";
			err = merr(ENOMEM);
			goto unlock;
		}
	}

	new->smz_key = zoneaddr;
	new->smz_value = zonecnt;

	if (!smap_zone_insert(rmap, new)) {
		kmem_cache_free(smap_zone_cache, new);
		msg = "chunk insert failed";
		err = merr(EBUG);
		goto unlock;
	}

	/* Freed space goes to spare first then usable.
	 */
	zonecnt = orig_zonecnt;

	spin_lock(&pd->pdi_ds.sda_dalock);
	if (pd->pdi_ds.sda_sact > 0) {
		if (pd->pdi_ds.sda_sact > zonecnt) {
			pd->pdi_ds.sda_sact -= zonecnt;
			zonecnt = 0;
		} else {
			zonecnt -= pd->pdi_ds.sda_sact;
			pd->pdi_ds.sda_sact = 0;
		}
	}

	pd->pdi_ds.sda_uact -= zonecnt;
	spin_unlock(&pd->pdi_ds.sda_dalock);

unlock:
	mutex_unlock(&pd->pdi_rmbktv[rgn].pdi_rmlock);

	if (old)
		kmem_cache_free(smap_zone_cache, old);

	if (err)
		mp_pr_err("smap pd %s: %s, free byrgn failed, rgn %u zoneaddr %lu zonecnt %u",
			 err, pd->pdi_name, msg ? msg : "(no detail)",
			 rgn, (ulong)zoneaddr, zonecnt);

	return err;
}

merr_t smap_free(struct mpool_descriptor *mp, u16 pdh, u64 zoneaddr, u16 zonecnt)
{
	merr_t                 err      = 0;
	struct mpool_dev_info *pd       = NULL;
	u32                    rstart   = 0;
	u32                    rend     = 0;
	u32                    rgn     = 0;
	u64                    zonefreed = 0;
	u32                    raddr    = 0;
	u64                    rcnt     = 0;

	pd = &mp->pds_pdv[pdh];

	if (zoneaddr >= pd->pdi_parm.dpr_zonetot ||
	    zoneaddr + zonecnt > pd->pdi_parm.dpr_zonetot) {
		err = merr(EINVAL);
		mp_pr_err("smap(%s, %s): free failed, zoneaddr %lu zonecnt %u zonetot: %u",
			  err, mp->pds_name, pd->pdi_name, (ulong)zoneaddr,
			  zonecnt, pd->pdi_parm.dpr_zonetot);
		return err;
	}

	if (!zonecnt)
		/* Nothing to be returned */
		return 0;

	/*
	 * smap_alloc() never crosses regions. however a previous instantiation
	 * of this mpool might have used a different value of rgn count
	 * so must handle frees that cross regions.
	 */

	rstart = smap_addr2rgn(mp, pd, zoneaddr);
	rend = smap_addr2rgn(mp, pd, zoneaddr + zonecnt - 1);

	for (rgn = rstart; rgn < rend + 1; rgn++) {
		/* compute zone address and count for this rgn */
		if (rgn == rstart)
			raddr = zoneaddr;
		else
			raddr = rgn * pd->pdi_ds.sda_rgnsz;

		if (rgn < rend)
			rcnt = ((u64)(rgn + 1) * pd->pdi_ds.sda_rgnsz) -
			       raddr;
		else
			rcnt = zonecnt - zonefreed;

		err = smap_free_byrgn(pd, rgn, raddr, rcnt);
		if (err) {
			mp_pr_err("smap(%s, %s): free byrgn failed, rgn %d raddr %lu, rcnt %lu",
				  err, mp->pds_name, pd->pdi_name, rgn, (ulong)raddr, (ulong)rcnt);
			break;
		}
		zonefreed = zonefreed + rcnt;
	}

	return err;
}

void smap_wait_usage_done(struct mpool_descriptor *mp)
{
	struct smap_usage_work *usagew = &mp->pds_smap_usage_work;

	cancel_delayed_work_sync(&usagew->smapu_wstruct);
}

#define SMAP_FREEPCT_DELTA 5
#define SMAP_FREEPCT_LOG_THLD   50

void smap_log_mpool_usage(struct work_struct *ws)
{
	struct smap_usage_work     *smapu;
	struct mpool_descriptor    *mp;
	int                         last, cur, delta;
	struct mp_usage             usage;

	smapu = container_of(ws, struct smap_usage_work, smapu_wstruct.work);
	mp = smapu->smapu_mp;

	/* Get the current mpool space usage stats */
	smap_mpool_usage(mp, MP_MED_ALL, &usage);

	if (usage.mpu_usable == 0) {
		merr_t err = merr(EINVAL);

		mp_pr_err("smap mpool %s: zero usable space", err, mp->pds_name);
		return;
	}
	/*
	 * Calculate the delta of free usable space/total usable space,
	 * since last time a message was logged
	 */
	last = smapu->smapu_freepct;
	cur = usage.mpu_fusable * 100 / usage.mpu_usable;
	delta = cur - last;

	/*
	 * Log a message if delta >= 5% && free usable space % < 50%
	 */
	if ((abs(delta) >= SMAP_FREEPCT_DELTA) &&
			(cur < SMAP_FREEPCT_LOG_THLD)) {

		smapu->smapu_freepct = cur;
		if (last == 0)
			mp_pr_info("smap mpool %s, free space %d%%",
				   mp->pds_name, smapu->smapu_freepct);

		else
			mp_pr_info("smap mpool %s, free space %s from %d%% to %d%%",
				   mp->pds_name, (delta > 0) ? "increases" : "decreases",
				   last, smapu->smapu_freepct);
	}

	/* Schedule the next run of smap_log_mpool_usage() */
	queue_delayed_work(mp->pds_workq, &smapu->smapu_wstruct,
		   msecs_to_jiffies(mp->pds_params.mp_mpusageperiod));
}
