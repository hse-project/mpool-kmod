/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PMD_UTILS_H
#define MPOOL_PMD_UTILS_H

#include <linux/sort.h>

struct mpool_descriptor;
struct pmd_layout;

struct pmd_layout *pmd_layout_find(struct rb_root *root, u64 key);

struct pmd_layout *pmd_layout_insert(struct rb_root *root, struct pmd_layout *item);

void pmd_layout_unprovision(struct mpool_descriptor *mp, struct pmd_layout *layout);

void
pmd_layout_calculate(
	struct mpool_descriptor   *mp,
	struct pmd_obj_capacity   *ocap,
	struct media_class        *mc,
	u64                       *zcnt,
	enum obj_type_omf          otype);

merr_t
pmd_layout_provision(
	struct mpool_descriptor    *mp,
	struct pmd_obj_capacity    *ocap,
	struct pmd_layout          *layout,
	struct media_class         *mc,
	u64                         zcnt);

merr_t pmd_smap_insert(struct mpool_descriptor *mp, struct pmd_layout *layout);

void
pmd_update_mdc_stats(
	struct mpool_descriptor    *mp,
	struct pmd_layout          *layout,
	struct pmd_mdc_info        *cinfo,
	enum pmd_obj_op             op);

merr_t pmd_mdc_append(struct mpool_descriptor *mp, u8 cslot, struct omf_mdcrec_data *cdr, int sync);

bool pmd_mdc_needed(struct mpool_descriptor *mp);

bool pmd_need_compact(struct mpool_descriptor *mp, u8 cslot, char *msgbuf, size_t msgsz);

merr_t
pmd_alloc_argcheck(
	struct mpool_descriptor    *mp,
	u64                         objid,
	enum obj_type_omf           otype,
	struct pmd_obj_capacity    *ocap,
	enum mp_media_classp        mclassp);

/* Committed object tree operations... */
#define pmd_co_foreach(_cinfo, _node) \
	for ((_node) = rb_first(&(_cinfo)->mmi_co_root); (_node); (_node) = rb_next((_node)))

static inline void pmd_co_rlock(struct pmd_mdc_info *cinfo, u8 slot)
{
	down_read_nested(&cinfo->mmi_co_lock, slot > 0 ? PMD_MDC_NORMAL : PMD_MDC_ZERO);
}

static inline void pmd_co_runlock(struct pmd_mdc_info *cinfo)
{
	up_read(&cinfo->mmi_co_lock);
}

static inline void pmd_co_wlock(struct pmd_mdc_info *cinfo, u8 slot)
{
	down_write_nested(&cinfo->mmi_co_lock, slot > 0 ? PMD_MDC_NORMAL : PMD_MDC_ZERO);
}

static inline void pmd_co_wunlock(struct pmd_mdc_info *cinfo)
{
	up_write(&cinfo->mmi_co_lock);
}

static inline struct pmd_layout *pmd_co_find(struct pmd_mdc_info *cinfo, u64 objid)
{
	return pmd_layout_find(&cinfo->mmi_co_root, objid);
}

static inline struct pmd_layout *
pmd_co_insert(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	return pmd_layout_insert(&cinfo->mmi_co_root, layout);
}

static inline struct pmd_layout *
pmd_co_remove(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	struct pmd_layout *found;

	found = pmd_co_find(cinfo, layout->eld_objid);
	if (found)
		rb_erase(&found->eld_nodemdc, &cinfo->mmi_co_root);

	return found;
}

/* Uncommitted object tree operations... */
static inline void pmd_uc_lock(struct pmd_mdc_info *cinfo, u8 slot)
{
	mutex_lock_nested(&cinfo->mmi_uc_lock, slot > 0 ? PMD_MDC_NORMAL : PMD_MDC_ZERO);
}

static inline void pmd_uc_unlock(struct pmd_mdc_info *cinfo)
{
	mutex_unlock(&cinfo->mmi_uc_lock);
}

static inline struct pmd_layout *pmd_uc_find(struct pmd_mdc_info *cinfo, u64 objid)
{
	return pmd_layout_find(&cinfo->mmi_uc_root, objid);
}

static inline struct pmd_layout *
pmd_uc_insert(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	return pmd_layout_insert(&cinfo->mmi_uc_root, layout);
}

static inline struct pmd_layout *
pmd_uc_remove(struct pmd_mdc_info *cinfo, struct pmd_layout *layout)
{
	struct pmd_layout *found;

	found = pmd_uc_find(cinfo, layout->eld_objid);
	if (found)
		rb_erase(&found->eld_nodemdc, &cinfo->mmi_uc_root);

	return found;
}

#endif /* MPOOL_PMD_UTILS_H */
