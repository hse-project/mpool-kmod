// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Pool on-drive format (omf) module.
 *
 * Defines:
 * + on-drive format for mpool superblocks
 * + on-drive formats for mlogs, mblocks, and metadata containers (mdc)
 * + utility functions for working with these on-drive formats
 *
 * All mpool metadata is versioned and stored on media in little-endian format.
 */

#include <crypto/hash.h>

#include "mpool_config.h"
#include "mpcore_defs.h"

#define _STR(x) #x
#define STR(x)  _STR(x)
static const char mpool_sbver[] = "MPOOL_SBVER_" STR(OMF_SB_DESC_VER_LAST);

enum unpack_only {
	UNPACKONLY    = 0,
	UNPACKCONVERT = 1,
};

/*
 * Forward declarations.
 */
static merr_t omf_layout_unpack_letoh_v1(void *out, const char *inbuf);
static merr_t omf_dparm_unpack_letoh_v1(void *out, const char *inbuf);
static merr_t omf_mdcrec_mcspare_unpack_letoh_v1(void *out, const char *inbuf);
static merr_t omf_sb_unpack_letoh_v1(void *out, const char *inbuf);
static merr_t omf_pmd_layout_unpack_letoh_v1(void *out, const char *inbuf);

/*
 * layout_descriptor_table: track changes in OMF and in-memory layout descriptor
 */
struct upgrade_history layout_descriptor_table[] = {
	{
		sizeof(struct omf_layout_descriptor),
		omf_layout_unpack_letoh_v1,
		NULL,
		OMF_SB_DESC_V1,
		{ {1, 0, 0, 0} }
	},
};

/*
 * devparm_descriptor_table: track changes in dev parm descriptor
 */
struct upgrade_history devparm_descriptor_table[] = {
	{
		sizeof(struct omf_devparm_descriptor),
		omf_dparm_unpack_letoh_v1,
		NULL,
		OMF_SB_DESC_V1,
		{ {1, 0, 0, 0} }
	},
};

/*
 * mdcrec_data_mcspare_table: track changes in spare % record.
 */
struct upgrade_history mdcrec_data_mcspare_table[]
	= {
	{
		sizeof(struct omf_mdcrec_data),
		omf_mdcrec_mcspare_unpack_letoh_v1,
		NULL,
		OMF_SB_DESC_UNDEF,
		{ {1, 0, 0, 0} },
	},
};

/*
 * sb_descriptor_table: track changes in mpool superblock descriptor
 */
struct upgrade_history sb_descriptor_table[] = {
	{
		sizeof(struct omf_sb_descriptor),
		omf_sb_unpack_letoh_v1,
		NULL,
		OMF_SB_DESC_V1,
		{ {1, 0, 0, 0} }
	},
};

/*
 * mdcrec_data_ocreate_table: track changes in OCREATE mdc record.
 */
struct upgrade_history mdcrec_data_ocreate_table[]
	= {
	{
		sizeof(struct omf_mdcrec_data),
		omf_pmd_layout_unpack_letoh_v1,
		NULL,
		OMF_SB_DESC_UNDEF,
		{ {1, 0, 0, 0} }
	},
};


/*
 * Generic routines
 */

/**
 * omf_find_upgrade_hist() -
 *
 * @uhtab:
 * @tabsz:   NELEM of upgrade_table
 * @sbver:   superblock version
 * @mdcver:  mdc version
 *
 * Given a superblock version or a mpool MDC content version, find the
 * corresponding upgrade history entry which matches the given sb or mdc
 * version.  That is the entry with the highest version such as
 * entry version <= the version passed in.
 *
 * Note that caller of this routine can pass in either a valid superblock
 * version or a valid mdc verison. If a valid superblock version is passed in,
 * mdcver need to be set to NULL. If a mdc version is passed in, sbver
 * need to set to 0.
 *
 * For example,
 * We update a structure "struct abc" three times, which is part of mpool
 * superblock or MDC. when superblock version is  1, 3 and 5 respectively.
 * Each time we add an entry in the upgrade table for this structure.
 * The upgrade history table looks like:
 *
 * struct upgrade_history abc_hist[] =
 * {{sizeof(struct abc_v1), abc_unpack_v1, NULL, OMF_SB_DESC_V1, NULL},
 *  {sizeof(struct abc_v2), abc_unpack_v2, NULL, OMF_SB_DESC_V3, NULL},
 *  {sizeof(struct abc_v3), abc_unpack_v3, NULL, OMF_SB_DESC_V5, NULL}}
 *
 * if caller needs to find the upgrade history entry matches
 * sb version 3(OMF_SB_DESC_V3), this routine finds the exact match and
 * returns &abc_hist[1].
 *
 * if caller needs to find the upgrade history entry which matches
 * sb version 4 (OMF_SB_DESC_V4), since we don't update this structure
 * in sb version 4, this routine finds the prior entry which matches
 * the sb version 3, return &abc_hist[1]
 *
 */
struct upgrade_history *
omf_find_upgrade_hist(
	struct upgrade_history     *uhtab,
	size_t                      tabsz,
	enum sb_descriptor_ver_omf  sbver,
	struct omf_mdcver          *mdcver)
{
	struct upgrade_history *cur = NULL;

	int    beg = 0;
	int    end = tabsz;
	int    mid;

	while (beg < end) {
		mid = (beg + end) / 2;
		cur = &uhtab[mid];
		if (mdcver) {
			assert(sbver == 0);
			if (omfu_mdcver_cmp(mdcver, "==", &cur->uh_mdcver))
				return cur;
			else if (omfu_mdcver_cmp(mdcver, ">", &cur->uh_mdcver))
				beg = mid + 1;
			else
				end = mid;
		} else {
			assert(sbver <= OMF_SB_DESC_VER_LAST);
			if (sbver == cur->uh_sbver)
				return cur;
			else if (sbver > cur->uh_sbver)
				beg = mid + 1;
			else
				end = mid;
		}
	}

	if (end == 0)
		return NULL; /* not found */

	return &uhtab[end - 1];
}

/**
 * omf_upgrade_convert_only()-
 *
 * @out:   v2 in-memory metadata structure
 * @outsz: size of v2 in-memory metadata structure
 * @in:    v1 in-memory metadata structure
 * @uhtab: upgrade history table for this structure
 * @tabsz: NELEM(uhtab)
 * @sbv1:  superblock version converting from
 * @sbv2:  superblock version converting to
 * @mdcv1: mdc version converting from
 * @mdcv2: mdc version converting to
 *
 * Convert a nested metadata structure in mpool superblock or
 * MDC from v1 to v2 (v1 <= v2)
 *
 * Note that callers can pass in either mdc beg/end ver (mdcv1/mdcv2),
 * or superblock beg/end versions (sbv1/sbv2). Set both mdcv1 and
 * mdcv2 to NULL, if caller wants to use superblock versions
 */
merr_t
omf_upgrade_convert_only(
	void                       *out,
	size_t                      outsz,
	const void                 *in,
	struct upgrade_history     *uhtab,
	size_t                      tabsz,
	enum sb_descriptor_ver_omf  sbv1,
	enum sb_descriptor_ver_omf  sbv2,
	struct omf_mdcver          *mdcv1,
	struct omf_mdcver          *mdcv2)
{
	struct upgrade_history *v1, *v2, *cur;

	void   *new, *old;
	size_t newsz;

	v1 = omf_find_upgrade_hist(uhtab, tabsz, sbv1, mdcv1);
	assert(v1);

	v2 = omf_find_upgrade_hist(uhtab, tabsz, sbv2, mdcv2);
	assert(v2);
	assert(v1 <= v2);

	if (v1 == v2)
		/* No need to do conversion */
		return 0;

	if (v2 == v1 + 1) {
		/*
		 * Single step conversion, Don't need to allocate/free
		 * buffers for intermediate conversion states
		 */
		if (v2->uh_conv != NULL)
			v2->uh_conv(in, out);
		return 0;
	}

	/*
	 * Make a local copy of input buffer, we won't free it
	 * in the for loop below
	 */
	old = kmalloc(v1->uh_size, GFP_KERNEL);
	if (!old)
		return merr(ENOMEM);
	memcpy(old, in, v1->uh_size);

	new = old;
	newsz = v1->uh_size;

	for (cur = v1 + 1; cur <= v2; cur++) {
		if (!cur->uh_conv)
			continue;
		new = kzalloc(cur->uh_size, GFP_KERNEL);
		if (!new) {
			kfree(old);
			return merr(ENOMEM);
		}
		newsz = cur->uh_size;
		cur->uh_conv(old, new);
		kfree(old);
		old = new;
	}

	memcpy(out, new, newsz);
	kfree(new);

	return 0;
}

/**
 * omf_upgrade_unpack_only() - unpack OMF meta data
 * @out:     output buffer for in-memory structure
 * @outsz:   size of output buffer
 * @inbuf:   OMF structure
 * @uhtab:   upgrade history table
 * @tabsz:   NELEM of uhtab
 * @sbver:   superblock version
 * @mdcver: mpool MDC content version
 */
merr_t
omf_upgrade_unpack_only(
	void                       *out,
	size_t                      outsz,
	const char                 *inbuf,
	struct upgrade_history     *uhtab,
	size_t                      tabsz,
	enum sb_descriptor_ver_omf  sbver,
	struct omf_mdcver          *mdcver)
{
	struct upgrade_history *res;

	merr_t err;

	res = omf_find_upgrade_hist(uhtab, tabsz, sbver, mdcver);

	err = res->uh_unpack(out, inbuf);

	return ev(err);
}

/**
 * omf_unpack_letoh_and_convert() -
 *
 * Unpack OMF meta data and convert it to the latest version.
 *
 * @out:    in-memory structure
 * @outsz:  size of in-memory structure
 * @inbuf:  OMF structure
 * @uhtab:  upgrade history table
 * @tabsz:  number of elements in uhtab
 * @sbver:  superblock version
 * @mdcver: mdc version. if set to NULL, use sbver to find the corresponding
 *          nested structure upgrade table
 */
merr_t
omf_unpack_letoh_and_convert(
	void                       *out,
	size_t                      outsz,
	const char                 *inbuf,
	struct upgrade_history     *uhtab,
	size_t                      tabsz,
	enum sb_descriptor_ver_omf  sbver,
	struct omf_mdcver          *mdcver)
{
	struct upgrade_history *cur, *omf;

	void   *old, *new;
	size_t  newsz;
	merr_t  err;

	omf = omf_find_upgrade_hist(uhtab, tabsz, sbver, mdcver);
	assert(omf);
	if (omf == &uhtab[tabsz - 1]) {
		/*
		 * Current version is the latest version.
		 * Don't need to do any conversion
		 */
		err = omf->uh_unpack(out, inbuf);
		return ev(err);
	}

	old = kzalloc(omf->uh_size, GFP_KERNEL);
	if (!old)
		return merr(ENOMEM);

	err = omf->uh_unpack(old, inbuf);
	if (ev(err)) {
		kfree(old);
		return err;
	}

	new = old;
	newsz = omf->uh_size;

	for (cur = omf + 1; cur <= &uhtab[tabsz - 1]; cur++) {
		if (!cur->uh_conv)
			continue;
		new = kzalloc(cur->uh_size, GFP_KERNEL);
		if (!new) {
			kfree(old);
			return merr(ENOMEM);
		}
		newsz = cur->uh_size;
		cur->uh_conv(old, new);
		kfree(old);
		old = new;
	}

	assert(newsz == outsz);
	memcpy(out, new, newsz);
	kfree(new);

	return 0;
}


/*
 * devparm_descriptor
 */
void omf_dparm_pack_htole(struct omf_devparm_descriptor *dp, char *outbuf)
{
	struct devparm_descriptor_omf  *dp_omf;

	dp_omf = (struct devparm_descriptor_omf *)outbuf;
	assert(MPOOL_UUID_SIZE == OMF_UUID_PACKLEN);
	omf_set_podp_devid(dp_omf, dp->odp_devid.uuid, MPOOL_UUID_SIZE);
	omf_set_podp_devsz(dp_omf, dp->odp_devsz);
	omf_set_podp_zonetot(dp_omf, dp->odp_zonetot);
	omf_set_podp_zonepg(dp_omf, dp->odp_zonepg);
	omf_set_podp_mclassp(dp_omf, dp->odp_mclassp);
	/* Translate pd_devtype into devtype_omf */
	omf_set_podp_devtype(dp_omf, dp->odp_devtype);
	omf_set_podp_sectorsz(dp_omf, dp->odp_sectorsz);
	omf_set_podp_features(dp_omf, dp->odp_features);
}

/**
 * omf_dparm_unpack_letoh()- unpack version 1 omf devparm descriptor into
 *                            in-memory format
 * @out: in-memory format
 * @inbuf: omf format
 */
static merr_t omf_dparm_unpack_letoh_v1(void *out, const char *inbuf)
{
	struct devparm_descriptor_omf  *dp_omf;
	struct omf_devparm_descriptor  *dp;

	dp_omf = (struct devparm_descriptor_omf *)inbuf;
	dp = (struct omf_devparm_descriptor *)out;

	assert(MPOOL_UUID_SIZE == OMF_UUID_PACKLEN);
	omf_podp_devid(dp_omf, dp->odp_devid.uuid, MPOOL_UUID_SIZE);
	dp->odp_devsz     = omf_podp_devsz(dp_omf);
	dp->odp_zonetot    = omf_podp_zonetot(dp_omf);
	dp->odp_zonepg = omf_podp_zonepg(dp_omf);
	dp->odp_mclassp   = omf_podp_mclassp(dp_omf);
	/* Translate devtype_omf into mp_devtype */
	dp->odp_devtype	  = omf_podp_devtype(dp_omf);
	dp->odp_sectorsz  = omf_podp_sectorsz(dp_omf);
	dp->odp_features  = omf_podp_features(dp_omf);

	return 0;
}

merr_t
omf_dparm_unpack_letoh(
	struct omf_devparm_descriptor  *dp,
	const char                     *inbuf,
	enum sb_descriptor_ver_omf      sbver,
	struct omf_mdcver              *mdcver,
	enum unpack_only                unpackonly)
{
	merr_t err;

	if (unpackonly == UNPACKONLY)
		err = omf_upgrade_unpack_only(dp, sizeof(*dp), inbuf,
			devparm_descriptor_table,
			ARRAY_SIZE(devparm_descriptor_table), sbver, mdcver);
	else
		err = omf_unpack_letoh_and_convert(dp, sizeof(*dp), inbuf,
			devparm_descriptor_table,
			ARRAY_SIZE(devparm_descriptor_table), sbver, mdcver);

	return ev(err);
}


/*
 * layout_descriptor
 */
void omf_layout_pack_htole(const struct omf_layout_descriptor *ld, char *outbuf)
{
	struct layout_descriptor_omf   *ld_omf;

	ld_omf = (struct layout_descriptor_omf *)outbuf;
	omf_set_pol_zcnt(ld_omf, ld->ol_zcnt);
	omf_set_pol_zaddr(ld_omf, ld->ol_zaddr);
}

/**
 * omf_layout_unpack_letoh_v1: unpack omf layout descriptor version 1
 * @out: in-memory layout descriptor
 * @in: on-media layout descriptor
 */
merr_t omf_layout_unpack_letoh_v1(void *out, const char *inbuf)
{
	struct omf_layout_descriptor   *ld;
	struct layout_descriptor_omf   *ld_omf;

	ld = (struct omf_layout_descriptor *)out;
	ld_omf = (struct layout_descriptor_omf *)inbuf;

	ld->ol_zcnt = omf_pol_zcnt(ld_omf);
	ld->ol_zaddr = omf_pol_zaddr(ld_omf);

	return 0;
}

merr_t
omf_layout_unpack_letoh(
	struct omf_layout_descriptor   *ld,
	const char                     *inbuf,
	enum sb_descriptor_ver_omf      sbver,
	struct omf_mdcver              *mdcver,
	enum unpack_only                unpackonly)
{
	merr_t err;

	if (unpackonly == UNPACKONLY)
		err = omf_upgrade_unpack_only(ld, sizeof(*ld), inbuf,
			layout_descriptor_table,
			ARRAY_SIZE(layout_descriptor_table), sbver, mdcver);
	else
		err = omf_unpack_letoh_and_convert(ld, sizeof(*ld), inbuf,
			layout_descriptor_table,
			ARRAY_SIZE(layout_descriptor_table), sbver, mdcver);

	return ev(err);
}

/*
 * pmd_layout
 */
int
omf_pmd_layout_pack_htole(
	const struct mpool_descriptor  *mp,
	u8                              rtype,
	struct pmd_layout              *ecl,
	char                           *outbuf)
{
	struct mdcrec_data_ocreate_omf *ocre_omf;

	int data_rec_sz;

	if (rtype != OMF_MDR_OCREATE && rtype != OMF_MDR_OUPDATE) {
		mp_pr_warn("mpool %s, wrong rec type %u packing layout",
			   mp->pds_name, rtype);
		return -EINVAL;
	}

	data_rec_sz = sizeof(*ocre_omf);

	ocre_omf = (struct mdcrec_data_ocreate_omf *)outbuf;
	omf_set_pdrc_rtype(ocre_omf, rtype);
	omf_set_pdrc_mclass(ocre_omf,
			    mp->pds_pdv[ecl->eld_ld.ol_pdh].pdi_mclass);
	omf_set_pdrc_objid(ocre_omf, ecl->eld_objid);
	omf_set_pdrc_gen(ocre_omf, ecl->eld_gen);
	omf_set_pdrc_mblen(ocre_omf, ecl->eld_mblen);

	if (objid_type(ecl->eld_objid) == OMF_OBJ_MLOG) {
		memcpy(ocre_omf->pdrc_uuid, ecl->eld_uuid.uuid,
		       OMF_UUID_PACKLEN);
		data_rec_sz += OMF_UUID_PACKLEN;
	}

	omf_layout_pack_htole(&(ecl->eld_ld), (char *)&(ocre_omf->pdrc_ld));

	return data_rec_sz;
}

/**
 * omf_pmd_layout_unpack_letoh_v1() - Unpack little-endian mdc obj record and
 *	optional obj layout from inbuf.
 * For version 1 of OMF_MDR_OCREATE record (strut layout_descriptor_omf)
 * @out:
 * @inbuf:
 *
 * Return:
 *   0 if successful
 *   merr_t with one of the following errno values upon failure:
 *   EINVAL if invalid record type or format
 *   ENOMEM if cannot alloc memory for metadata conversion
 */
static merr_t omf_pmd_layout_unpack_letoh_v1(void *out, const char *inbuf)
{
	struct mdcrec_data_ocreate_omf *ocre_omf;
	struct omf_mdcrec_data         *cdr = out;

	merr_t err;

	ocre_omf = (struct mdcrec_data_ocreate_omf *)inbuf;

	cdr->omd_rtype = omf_pdrc_rtype(ocre_omf);
	if (cdr->omd_rtype != OMF_MDR_OCREATE &&
		cdr->omd_rtype == OMF_MDR_OUPDATE) {
		err = merr(EINVAL);
		mp_pr_err("Unpacking layout failed, wrong record type %d",
			  err, cdr->omd_rtype);
		return err;
	}

	cdr->u.obj.omd_mclass = omf_pdrc_mclass(ocre_omf);
	cdr->u.obj.omd_objid = omf_pdrc_objid(ocre_omf);
	cdr->u.obj.omd_gen   = omf_pdrc_gen(ocre_omf);
	cdr->u.obj.omd_mblen = omf_pdrc_mblen(ocre_omf);

	if (objid_type(cdr->u.obj.omd_objid) == OMF_OBJ_MLOG)
		memcpy(cdr->u.obj.omd_uuid.uuid, ocre_omf->pdrc_uuid,
		       OMF_UUID_PACKLEN);

	err = omf_layout_unpack_letoh(&cdr->u.obj.omd_old,
				      (char *)&(ocre_omf->pdrc_ld),
				      OMF_SB_DESC_V1, NULL, UNPACKONLY);
	if (ev(err))
		return err;

	return 0;
}


/**
 * omf_pmd_layout_unpack_letoh() - Unpack little-endian mdc obj record and
 *	optional obj layout from inbuf.
 *	Allocate object layout.
 * For version 1 of OMF_MDR_OCREATE record (strut layout_descriptor_omf)
 * @mp:
 * @mdcver: version of the mpool MDC content being unpacked.
 * @rtype:
 * @cdr: output
 * @inbuf:
 *
 * Return:
 *   0 if successful
 *   merr_t with one of the following errno values upon failure:
 *   EINVAL if invalid record type or format
 *   ENOMEM if cannot alloc memory to return an object layout
 *   ENOENT if cannot convert a devid to a device handle (pdh)
 */
static merr_t
omf_pmd_layout_unpack_letoh(
	struct mpool_descriptor    *mp,
	struct omf_mdcver          *mdcver,
	enum mdcrec_type_omf        rtype,
	struct omf_mdcrec_data     *cdr,
	const char                 *inbuf)
{
	struct pmd_layout *ecl;

	merr_t err;
	int    i;

	err = omf_unpack_letoh_and_convert(cdr, sizeof(*cdr), inbuf,
					mdcrec_data_ocreate_table,
					ARRAY_SIZE(mdcrec_data_ocreate_table),
					OMF_SB_DESC_UNDEF, mdcver);
	if (ev(err)) {
		char buf[MAX_MDCVERSTR];

		omfu_mdcver_to_str(mdcver, buf, sizeof(buf));
		mp_pr_err("mpool %s, unpacking layout failed for mdc content version %s",
			  err, mp->pds_name, buf);
		return err;
	}

	ecl = pmd_layout_alloc(mp, &cdr->u.obj.omd_uuid,
			       cdr->u.obj.omd_objid, cdr->u.obj.omd_gen,
			       cdr->u.obj.omd_mblen,
			       cdr->u.obj.omd_old.ol_zcnt);
	if (!ecl) {
		err = merr(ENOMEM);
		mp_pr_err("mpool %s, unpacking layout failed, could not allocate layout structure",
			  err, mp->pds_name);
		return err;
	}

	ecl->eld_ld.ol_zaddr = cdr->u.obj.omd_old.ol_zaddr;

	for (i = 0; i < mp->pds_pdvcnt; i++) {
		if (mp->pds_pdv[i].pdi_mclass == cdr->u.obj.omd_mclass) {
			ecl->eld_ld.ol_pdh = i;
			break;
		}
	}

	if (i >= mp->pds_pdvcnt) {
		pmd_obj_put(mp, ecl);

		err = merr(ENOENT);
		mp_pr_err("mpool %s, unpacking layout failed, mclass %u not in mpool",
			  err, mp->pds_name, cdr->u.obj.omd_mclass);
		return err;
	}

	cdr->u.obj.omd_layout = ecl;

	return err;
}


/*
 * sb_descriptor
 */

/*
 * omf_cksum_crc32c_le() -
 *
 * Compute 4-byte checksum of type CRC32C for data buffer dbuf with length dlen
 * and store in obuf little-endian; CRC32C is the only crypto algorithm we
 * currently support
 *
 * @dbuf: data buf
 * @dlen: data length
 * @obuf: output buf
 *
 * Return: 0 if successful, merr_t(EINVAL) otherwise
 */
merr_t omf_cksum_crc32c_le(const char *dbuf, u64 dlen, u8 *obuf)
{
	SHASH_DESC_ON_STACK(desc, mpool_tfm);

	int rc;

	memset(obuf, 0, 4);

	desc->tfm = mpool_tfm;

#if HAVE_SHASH_DESC_FLAGS
	desc->flags = 0;
#endif

	rc = crypto_shash_digest(desc, (u8 *)dbuf, dlen, obuf);

	return merr(rc);
}

struct omf_mdcver *omf_sbver_to_mdcver(enum sb_descriptor_ver_omf sbver)
{
	struct upgrade_history *uhtab;

	uhtab = omf_find_upgrade_hist(sb_descriptor_table,
				      ARRAY_SIZE(sb_descriptor_table),
				      sbver, NULL);
	if (uhtab) {
		assert(uhtab->uh_sbver == sbver);
		return &uhtab->uh_mdcver;
	}

	return NULL;
}

merr_t omf_sb_pack_htole(struct omf_sb_descriptor *sb, char *outbuf)
{
	struct sb_descriptor_omf   *sb_omf;

	merr_t err;
	u8     cksum[4];

	if (sb->osb_vers != OMF_SB_DESC_VER_LAST) {
		/* not a valid header version */
		return merr(EINVAL);
	}

	sb_omf = (struct sb_descriptor_omf *)outbuf;

	/* pack drive-specific info */
	omf_set_psb_magic(sb_omf, sb->osb_magic);
	assert(OMF_MPOOL_NAME_LEN == MPOOL_NAME_LEN_MAX);
	omf_set_psb_name(sb_omf, sb->osb_name, MPOOL_NAME_LEN_MAX);
	assert(MPOOL_UUID_SIZE == OMF_UUID_PACKLEN);
	omf_set_psb_poolid(sb_omf, sb->osb_poolid.uuid, MPOOL_UUID_SIZE);
	omf_set_psb_vers(sb_omf, sb->osb_vers);
	omf_set_psb_gen(sb_omf, sb->osb_gen);

	omf_dparm_pack_htole(&(sb->osb_parm), (char *)&(sb_omf->psb_parm));

	omf_set_psb_mdc01gen(sb_omf, sb->osb_mdc01gen);
	omf_set_psb_mdc01uuid(sb_omf, sb->osb_mdc01uuid.uuid, MPOOL_UUID_SIZE);
	omf_layout_pack_htole(&(sb->osb_mdc01desc),
		(char *)&(sb_omf->psb_mdc01desc));
	omf_set_psb_mdc01devid(sb_omf, sb->osb_mdc01devid.uuid,
			       MPOOL_UUID_SIZE);

	omf_set_psb_mdc02gen(sb_omf, sb->osb_mdc02gen);
	omf_set_psb_mdc02uuid(sb_omf, sb->osb_mdc02uuid.uuid, MPOOL_UUID_SIZE);
	omf_layout_pack_htole(&(sb->osb_mdc02desc),
		(char *)&(sb_omf->psb_mdc02desc));
	omf_set_psb_mdc02devid(sb_omf, sb->osb_mdc02devid.uuid,
			       MPOOL_UUID_SIZE);

	outbuf = (char *)&sb_omf->psb_mdc0dev;
	omf_dparm_pack_htole(&sb->osb_mdc0dev, outbuf);

	/* Add CKSUM1 */
	err = omf_cksum_crc32c_le((char *) sb_omf,
				offsetof(struct sb_descriptor_omf, psb_cksum1),
				cksum);
	if (err)
		return merr(EINVAL);

	omf_set_psb_cksum1(sb_omf, cksum, 4);

	/* Add CKSUM2 */
	err = omf_cksum_crc32c_le((char *) &(sb_omf->psb_parm),
				sizeof(sb_omf->psb_parm),
				cksum);
	if (err)
		return merr(EINVAL);

	omf_set_psb_cksum2(sb_omf, cksum, 4);

	return 0;
}


/**
 * omf_sb_unpack_letoh_v1()- unpack version 1 omf sb descriptor into
 *                            in-memory format
 * @out: in-memory format
 * @inbuf: omf format
 */
merr_t omf_sb_unpack_letoh_v1(void *out, const char *inbuf)
{
	struct sb_descriptor_omf   *sb_omf;
	struct omf_sb_descriptor   *sb;

	merr_t err;
	u8     cksum[4];
	u8     omf_cksum[4];

	sb_omf = (struct sb_descriptor_omf *)inbuf;
	sb = (struct omf_sb_descriptor *)out;

	/* verify CKSUM2 */
	err = omf_cksum_crc32c_le((char *) &(sb_omf->psb_parm),
				  sizeof(sb_omf->psb_parm), cksum);
	omf_psb_cksum2(sb_omf, omf_cksum, 4);

	if (err || memcmp(cksum, omf_cksum, 4))
		return merr(EINVAL);


	sb->osb_magic = omf_psb_magic(sb_omf);

	assert(OMF_MPOOL_NAME_LEN == MPOOL_NAME_LEN_MAX);
	omf_psb_name(sb_omf, sb->osb_name, MPOOL_NAME_LEN_MAX);

	sb->osb_vers = omf_psb_vers(sb_omf);
	assert(sb->osb_vers == OMF_SB_DESC_V1);

	assert(MPOOL_UUID_SIZE == OMF_UUID_PACKLEN);
	omf_psb_poolid(sb_omf, sb->osb_poolid.uuid, MPOOL_UUID_SIZE);

	sb->osb_gen = omf_psb_gen(sb_omf);
	omf_dparm_unpack_letoh(&(sb->osb_parm), (char *)&(sb_omf->psb_parm),
		OMF_SB_DESC_V1, NULL, UNPACKONLY);

	sb->osb_mdc01gen  = omf_psb_mdc01gen(sb_omf);
	omf_psb_mdc01uuid(sb_omf, sb->osb_mdc01uuid.uuid, MPOOL_UUID_SIZE);
	omf_layout_unpack_letoh(&(sb->osb_mdc01desc),
		(char *)&(sb_omf->psb_mdc01desc), OMF_SB_DESC_V1, NULL,
		UNPACKONLY);
	omf_psb_mdc01devid(sb_omf, sb->osb_mdc01devid.uuid, MPOOL_UUID_SIZE);

	sb->osb_mdc02gen = omf_psb_mdc02gen(sb_omf);
	omf_psb_mdc02uuid(sb_omf, sb->osb_mdc02uuid.uuid, MPOOL_UUID_SIZE);
	omf_layout_unpack_letoh(&(sb->osb_mdc02desc),
		(char *)&(sb_omf->psb_mdc02desc), OMF_SB_DESC_V1, NULL,
		UNPACKONLY);
	omf_psb_mdc02devid(sb_omf, sb->osb_mdc02devid.uuid, MPOOL_UUID_SIZE);

	inbuf = (char *)&sb_omf->psb_mdc0dev;
	omf_dparm_unpack_letoh(&sb->osb_mdc0dev, inbuf,
			       OMF_SB_DESC_V1, NULL, UNPACKONLY);

	return 0;
}

merr_t
omf_sb_unpack_letoh(
	struct omf_sb_descriptor   *sb,
	const char                 *inbuf,
	u16                        *omf_ver,
	struct mpool_devrpt        *devrpt)
{
	struct sb_descriptor_omf   *sb_omf;

	merr_t err;
	u64    magic = 0;
	u8     cksum[4];
	u8     omf_cksum[4];

	sb_omf = (struct sb_descriptor_omf *)inbuf;

	magic = omf_psb_magic(sb_omf);

	*omf_ver = OMF_SB_DESC_UNDEF;

	if (magic != OMF_SB_MAGIC)
		return merr(EBADF);

	/* verify CKSUM1 */
	err = omf_cksum_crc32c_le(inbuf,
		offsetof(struct sb_descriptor_omf, psb_cksum1), cksum);
	omf_psb_cksum1(sb_omf, omf_cksum, 4);
	if (err || memcmp(cksum, omf_cksum, 4))
		return merr(EINVAL);

	*omf_ver = omf_psb_vers(sb_omf);

	if (*omf_ver > OMF_SB_DESC_VER_LAST) {
		mpool_devrpt(devrpt, MPOOL_RC_ERRMSG, -1,
			     "superblock version %d not supported",
			     *omf_ver);
		return merr(EPROTONOSUPPORT);
	}

	err = omf_unpack_letoh_and_convert(sb, sizeof(*sb), inbuf,
		sb_descriptor_table, ARRAY_SIZE(sb_descriptor_table),
		*omf_ver, NULL);
	if (ev(err))
		mp_pr_err("Unpacking superblock failed for version %u",
			  err, *omf_ver);

	return err;
}

bool omf_sb_has_magic_le(const char *inbuf)
{
	struct sb_descriptor_omf   *sb_omf;

	u64    magic;

	sb_omf = (struct sb_descriptor_omf *)inbuf;
	magic  = omf_psb_magic(sb_omf);

	return magic == OMF_SB_MAGIC;
}


/*
 * mdcrec_objcmn
 */

/**
 * omf_mdcrec_objcmn_pack_htole() - pack mdc obj record
 * @mp:
 * @cdr:
 * @outbuf:
 *
 * Pack mdc obj record and optional obj layout into outbuf little-endian.
 *
 * Return: bytes packed if successful, -EINVAL otherwise
 */
static u64
omf_mdcrec_objcmn_pack_htole(
	struct mpool_descriptor    *mp,
	struct omf_mdcrec_data     *cdr,
	char                       *outbuf)
{
	struct pmd_layout *layout = cdr->u.obj.omd_layout;
	struct mdcrec_data_odelete_omf *odel_omf;
	struct mdcrec_data_oerase_omf  *oera_omf;

	s64    bytes = 0;

	switch (cdr->omd_rtype) {
	case OMF_MDR_ODELETE:
	case OMF_MDR_OIDCKPT:
		odel_omf = (struct mdcrec_data_odelete_omf *)outbuf;
		omf_set_pdro_rtype(odel_omf, cdr->omd_rtype);
		omf_set_pdro_objid(odel_omf, cdr->u.obj.omd_objid);
		return sizeof(*odel_omf);

	case OMF_MDR_OERASE:
		oera_omf = (struct mdcrec_data_oerase_omf *)outbuf;
		omf_set_pdrt_rtype(oera_omf, cdr->omd_rtype);
		omf_set_pdrt_objid(oera_omf, cdr->u.obj.omd_objid);
		omf_set_pdrt_gen(oera_omf, cdr->u.obj.omd_gen);
		return sizeof(*oera_omf);

	default:
		break;
	}

	if (cdr->omd_rtype != OMF_MDR_OCREATE &&
	    cdr->omd_rtype != OMF_MDR_OUPDATE) {
		/* unknown rtype */
		mp_pr_warn("mpool %s, packing object, unknown rec type %d",
			   mp->pds_name, cdr->omd_rtype);
		return -EINVAL;
	}

	/* OCREATE or OUPDATE: pack object in provided layout descriptor */
	if (!layout) {
		mp_pr_warn("mpool %s, invalid layout", mp->pds_name);
		return ev(-EINVAL);
	}

	bytes = omf_pmd_layout_pack_htole(mp, cdr->omd_rtype, layout, outbuf);
	if (bytes < 0)
		return ev(-EINVAL);

	return bytes;
}

/**
 * omf_mdcrec_objcmn_unpack_letoh() - Unpack little-endian mdc object-related
 *	record and optional obj layout from inbuf.
 * @mp:
 * @mdcver:
 * @cdr:
 * @inbuf:
 *
 * Return:
 *   0 if successful
 *   merr_t with one of the following errno values upon failure:
 *   EINVAL if invalid record type or format
 *   ENOMEM if cannot alloc memory to return an object layout
 *   ENOENT if cannot convert a devid to a device handle (pdh)
 */
static merr_t
omf_mdcrec_objcmn_unpack_letoh(
	struct mpool_descriptor    *mp,
	struct omf_mdcver          *mdcver,
	struct omf_mdcrec_data     *cdr,
	const char                 *inbuf)
{
	struct mdcrec_data_odelete_omf *odel_omf;
	struct mdcrec_data_oerase_omf  *oera_omf;
	enum mdcrec_type_omf            rtype;

	merr_t err = 0;

	/*
	 * The data record type is always the first field of all the
	 * data records.
	 */
	rtype = omf_pdro_rtype((struct mdcrec_data_odelete_omf *)inbuf);

	switch (rtype) {
	case OMF_MDR_ODELETE:
	case OMF_MDR_OIDCKPT:
		odel_omf = (struct mdcrec_data_odelete_omf *)inbuf;
		cdr->omd_rtype = omf_pdro_rtype(odel_omf);
		cdr->u.obj.omd_objid = omf_pdro_objid(odel_omf);
		break;

	case OMF_MDR_OERASE:
		oera_omf = (struct mdcrec_data_oerase_omf *)inbuf;
		cdr->omd_rtype = omf_pdrt_rtype(oera_omf);
		cdr->u.obj.omd_objid = omf_pdrt_objid(oera_omf);
		cdr->u.obj.omd_gen = omf_pdrt_gen(oera_omf);
		break;

	case OMF_MDR_OCREATE:
	case OMF_MDR_OUPDATE:
		err = omf_pmd_layout_unpack_letoh(mp, mdcver, rtype,
						  cdr, inbuf);
		ev(err);
		break;

	default:
		/* unknown rtype */
		mp_pr_warn("mpool %s, invalid rtype %d", mp->pds_name, rtype);
		return merr(EINVAL);
	}


	return err;
}


/*
 * mdcrec_mcconfig
 */

/**
 * omf_mdcrec_mcconfig_pack_htole() - Pack mdc mclass config record into outbuf
 *	little-endian.
 * @cdr:
 * @outbuf:
 *
 * Return: bytes packed.
 */
static u64
omf_mdcrec_mcconfig_pack_htole(struct omf_mdcrec_data *cdr, char *outbuf)
{
	struct mdcrec_data_mcconfig_omf    *mc_omf;

	mc_omf = (struct mdcrec_data_mcconfig_omf *)outbuf;
	omf_set_pdrs_rtype(mc_omf, cdr->omd_rtype);
	omf_dparm_pack_htole(&(cdr->u.dev.omd_parm),
		(char *)&(mc_omf->pdrs_parm));

	return sizeof(*mc_omf);
}

/**
 * omf_mdcrec_mcconfig_unpack_letoh() - Unpack little-endian mdc mcconfig
 *	record from inbuf.
 * @cdr:
 * @inbuf:
 */
static merr_t
omf_mdcrec_mcconfig_unpack_letoh(
	struct omf_mdcver      *mdcver,
	struct omf_mdcrec_data *cdr,
	const char             *inbuf)
{
	struct mdcrec_data_mcconfig_omf    *mc_omf;
	merr_t                              err;

	mc_omf = (struct mdcrec_data_mcconfig_omf *)inbuf;

	cdr->omd_rtype = omf_pdrs_rtype(mc_omf);
	err = omf_dparm_unpack_letoh(&(cdr->u.dev.omd_parm),
		(char *)&(mc_omf->pdrs_parm), OMF_SB_DESC_UNDEF,
		mdcver, UNPACKCONVERT);

	return ev(err);
}


/*
 * mdcrec_version
 */

/**
 * omf_mdcver_pack_htole() - Pack mdc content version record into outbuf
 *	little-endian.
 * @cdr:
 * @outbuf:
 *
 * Return: bytes packed.
 */
static u64 omf_mdcver_pack_htole(struct omf_mdcrec_data *cdr, char *outbuf)
{
	struct mdcver_omf  *pv_omf;

	pv_omf = (struct mdcver_omf *)outbuf;

	omf_set_pv_rtype(pv_omf, cdr->omd_rtype);
	omf_set_pv_mdcv_major(pv_omf, cdr->u.omd_version.mdcv_major);
	omf_set_pv_mdcv_minor(pv_omf, cdr->u.omd_version.mdcv_minor);
	omf_set_pv_mdcv_patch(pv_omf, cdr->u.omd_version.mdcv_patch);
	omf_set_pv_mdcv_dev(pv_omf, cdr->u.omd_version.mdcv_dev);

	return sizeof(*pv_omf);
}

void omf_mdcver_unpack_letoh(struct omf_mdcrec_data *cdr, const char *inbuf)
{
	struct mdcver_omf  *pv_omf;

	pv_omf = (struct mdcver_omf *)inbuf;

	cdr->omd_rtype = omf_pv_rtype(pv_omf);
	cdr->u.omd_version.mdcv_major = omf_pv_mdcv_major(pv_omf);
	cdr->u.omd_version.mdcv_minor = omf_pv_mdcv_minor(pv_omf);
	cdr->u.omd_version.mdcv_patch = omf_pv_mdcv_patch(pv_omf);
	cdr->u.omd_version.mdcv_dev   = omf_pv_mdcv_dev(pv_omf);
}


/*
 * mdcrec_mcspare
 */
u64 omf_mdcrec_mcspare_pack_htole(struct omf_mdcrec_data *cdr, char *outbuf)
{
	struct mdcrec_data_mcspare_omf *mcs_omf;

	mcs_omf = (struct mdcrec_data_mcspare_omf *)outbuf;
	omf_set_pdra_rtype(mcs_omf, cdr->omd_rtype);
	omf_set_pdra_mclassp(mcs_omf, cdr->u.mcs.omd_mclassp);
	omf_set_pdra_spzone(mcs_omf, cdr->u.mcs.omd_spzone);

	return sizeof(*mcs_omf);
}

/**
 * omf_mdcrec_mcspare_unpack_letoh_v1() -
 *	Unpack little-endian mdc media class spare record from inbuf.
 * @cdr:
 * @inbuf:
 */
static merr_t omf_mdcrec_mcspare_unpack_letoh_v1(void *out, const char *inbuf)
{
	struct mdcrec_data_mcspare_omf *mcs_omf;
	struct omf_mdcrec_data         *cdr = out;

	mcs_omf = (struct mdcrec_data_mcspare_omf *)inbuf;

	cdr->omd_rtype = omf_pdra_rtype(mcs_omf);
	cdr->u.mcs.omd_mclassp = omf_pdra_mclassp(mcs_omf);
	cdr->u.mcs.omd_spzone = omf_pdra_spzone(mcs_omf);

	return 0;
}

/**
 * omf_mdcrec_mcspare_unpack_letoh() -
 *	Unpack little-endian mdc media class spare record from inbuf.
 * @cdr:
 * @inbuf:
 */
static merr_t
omf_mdcrec_mcspare_unpack_letoh(
	struct omf_mdcrec_data     *cdr,
	const char                 *inbuf,
	enum sb_descriptor_ver_omf  sbver,
	struct omf_mdcver          *mdcver)
{
	merr_t err;

	err = omf_unpack_letoh_and_convert(cdr, sizeof(*cdr), inbuf,
				mdcrec_data_mcspare_table,
				ARRAY_SIZE(mdcrec_data_mcspare_table),
				sbver, mdcver);
	return ev(err);
}


/*
 * mdcrec_mpconfig
 */

/**
 * omf_mdcrec_mpconfig_pack_htole() - Pack an mpool config record
 * @cdr:
 * @outbuf:
 *
 * Return: bytes packed.
 */
static u64
omf_mdcrec_mpconfig_pack_htole(struct omf_mdcrec_data *cdr, char *outbuf)
{
	struct mdcrec_data_mpconfig_omf    *cfg_omf;
	struct mpool_config                *cfg;

	cfg = &cdr->u.omd_cfg;

	cfg_omf = (struct mdcrec_data_mpconfig_omf *)outbuf;
	omf_set_pdmc_rtype(cfg_omf, cdr->omd_rtype);
	omf_set_pdmc_oid1(cfg_omf, cfg->mc_oid1);
	omf_set_pdmc_oid2(cfg_omf, cfg->mc_oid2);
	omf_set_pdmc_uid(cfg_omf, cfg->mc_uid);
	omf_set_pdmc_gid(cfg_omf, cfg->mc_gid);
	omf_set_pdmc_mode(cfg_omf, cfg->mc_mode);
	omf_set_pdmc_mclassp(cfg_omf, cfg->mc_mclassp);
	omf_set_pdmc_captgt(cfg_omf, cfg->mc_captgt);
	omf_set_pdmc_ra_pages_max(cfg_omf, cfg->mc_ra_pages_max);
	omf_set_pdmc_vma_size_max(cfg_omf, cfg->mc_vma_size_max);
	omf_set_pdmc_rsvd1(cfg_omf, cfg->mc_rsvd1);
	omf_set_pdmc_rsvd2(cfg_omf, cfg->mc_rsvd2);
	omf_set_pdmc_rsvd3(cfg_omf, cfg->mc_rsvd3);
	omf_set_pdmc_rsvd4(cfg_omf, cfg->mc_rsvd4);
	omf_set_pdmc_utype(cfg_omf, &cfg->mc_utype, sizeof(cfg->mc_utype));
	omf_set_pdmc_label(cfg_omf, cfg->mc_label, sizeof(cfg->mc_label));

	return sizeof(*cfg_omf);
}

/**
 * omf_mdcrec_mpconfig_unpack_letoh() - Unpack an mpool config record
 * @cdr:
 * @inbuf:
 *
 * Return: bytes packed.
 */
static void
omf_mdcrec_mpconfig_unpack_letoh(struct omf_mdcrec_data *cdr, const char *inbuf)
{
	struct mdcrec_data_mpconfig_omf    *cfg_omf;
	struct mpool_config                *cfg;

	cfg = &cdr->u.omd_cfg;

	cfg_omf = (struct mdcrec_data_mpconfig_omf *)inbuf;
	cdr->omd_rtype = omf_pdmc_rtype(cfg_omf);
	cfg->mc_oid1 = omf_pdmc_oid1(cfg_omf);
	cfg->mc_oid2 = omf_pdmc_oid2(cfg_omf);
	cfg->mc_uid = omf_pdmc_uid(cfg_omf);
	cfg->mc_gid = omf_pdmc_gid(cfg_omf);
	cfg->mc_mode = omf_pdmc_mode(cfg_omf);
	cfg->mc_mclassp = omf_pdmc_mclassp(cfg_omf);
	cfg->mc_captgt = omf_pdmc_captgt(cfg_omf);
	cfg->mc_ra_pages_max = omf_pdmc_ra_pages_max(cfg_omf);
	cfg->mc_vma_size_max = omf_pdmc_vma_size_max(cfg_omf);
	cfg->mc_rsvd1 = omf_pdmc_rsvd1(cfg_omf);
	cfg->mc_rsvd2 = omf_pdmc_rsvd2(cfg_omf);
	cfg->mc_rsvd3 = omf_pdmc_rsvd3(cfg_omf);
	cfg->mc_rsvd4 = omf_pdmc_rsvd4(cfg_omf);
	omf_pdmc_utype(cfg_omf, &cfg->mc_utype, sizeof(cfg->mc_utype));
	omf_pdmc_label(cfg_omf, cfg->mc_label, sizeof(cfg->mc_label));
}

/**
 * mdcrec_type_objcmn() - Determine if the data record type corresponds to
 *	an object.
 * @rtype: record type
 *
 * Return: true if the type is of an object data record.
 */
static bool mdcrec_type_objcmn(enum mdcrec_type_omf rtype)
{
	return (rtype == OMF_MDR_OCREATE ||
		rtype == OMF_MDR_OUPDATE ||
		rtype == OMF_MDR_ODELETE ||
		rtype == OMF_MDR_OIDCKPT ||
		rtype == OMF_MDR_OERASE);
}

int omf_mdcrec_isobj_le(const char *inbuf)
{
	/* rtype is byte so no endian conversion */
	const u8 rtype = inbuf[0];

	return mdcrec_type_objcmn(rtype);
}


/*
 * mdcrec
 */
int
omf_mdcrec_pack_htole(
	struct mpool_descriptor    *mp,
	struct omf_mdcrec_data     *cdr,
	char                       *outbuf)
{
	u8 rtype = (char)cdr->omd_rtype;

	if (mdcrec_type_objcmn(rtype))
		return omf_mdcrec_objcmn_pack_htole(mp, cdr, outbuf);
	else if (rtype == OMF_MDR_VERSION)
		return omf_mdcver_pack_htole(cdr, outbuf);
	else if (rtype == OMF_MDR_MCCONFIG)
		return omf_mdcrec_mcconfig_pack_htole(cdr, outbuf);
	else if (rtype == OMF_MDR_MCSPARE)
		return omf_mdcrec_mcspare_pack_htole(cdr, outbuf);
	else if (rtype == OMF_MDR_MPCONFIG)
		return omf_mdcrec_mpconfig_pack_htole(cdr, outbuf);

	mp_pr_warn("mpool %s, invalid record type %u in mdc log",
		   mp->pds_name, rtype);

	return ev(-EINVAL);
}

merr_t
omf_mdcrec_unpack_letoh(
	struct omf_mdcver          *mdcver,
	struct mpool_descriptor    *mp,
	struct omf_mdcrec_data     *cdr,
	const char                 *inbuf)
{
	u8 rtype = (u8)*inbuf;

	/* rtype is byte so no endian conversion */

	if (mdcrec_type_objcmn(rtype))
		return omf_mdcrec_objcmn_unpack_letoh(mp, mdcver, cdr, inbuf);
	else if (rtype == OMF_MDR_VERSION)
		omf_mdcver_unpack_letoh(cdr, inbuf);
	else if (rtype == OMF_MDR_MCCONFIG)
		omf_mdcrec_mcconfig_unpack_letoh(mdcver, cdr, inbuf);
	else if (rtype == OMF_MDR_MCSPARE)
		omf_mdcrec_mcspare_unpack_letoh(cdr, inbuf, OMF_SB_DESC_UNDEF,
						mdcver);
	else if (rtype == OMF_MDR_MPCONFIG)
		omf_mdcrec_mpconfig_unpack_letoh(cdr, inbuf);
	else {
		mp_pr_warn("mpool %s, unknown record type %u in mdc log",
			   mp->pds_name, rtype);
		return merr(EINVAL);
	}

	return 0;
}

u8 omf_mdcrec_unpack_type_letoh(const char *inbuf)
{
	/* rtype is byte so no endian conversion */
	return (u8)*inbuf;
}


/*
 * logblock_header
 */
bool omf_logblock_empty_le(char *lbuf)
{
	bool   ret_val = true;
	int    i       = 0;

	for (i = 0; i < OMF_LOGBLOCK_HDR_PACKLEN; i++) {
		if (0 != (u8)lbuf[i]) {
			ret_val = false;
			break;
		}
	}

	return ret_val;
}

merr_t
omf_logblock_header_pack_htole(
	struct omf_logblock_header *lbh,
	char                       *outbuf)
{
	struct logblock_header_omf *lbh_omf;

	lbh_omf = (struct logblock_header_omf *)outbuf;

	if (lbh->olh_vers != OMF_LOGBLOCK_VERS)
		return merr(EINVAL);

	omf_set_polh_vers(lbh_omf, lbh->olh_vers);
	omf_set_polh_magic(lbh_omf, lbh->olh_magic.uuid, MPOOL_UUID_SIZE);
	omf_set_polh_gen(lbh_omf, lbh->olh_gen);
	omf_set_polh_pfsetid(lbh_omf, lbh->olh_pfsetid);
	omf_set_polh_cfsetid(lbh_omf, lbh->olh_cfsetid);

	return 0;
}

merr_t
omf_logblock_header_unpack_letoh(
	struct omf_logblock_header *lbh,
	const char                 *inbuf)
{
	struct logblock_header_omf *lbh_omf;

	lbh_omf = (struct logblock_header_omf *)inbuf;

	lbh->olh_vers    = omf_polh_vers(lbh_omf);
	omf_polh_magic(lbh_omf, lbh->olh_magic.uuid, MPOOL_UUID_SIZE);
	lbh->olh_gen     = omf_polh_gen(lbh_omf);
	lbh->olh_pfsetid = omf_polh_pfsetid(lbh_omf);
	lbh->olh_cfsetid = omf_polh_cfsetid(lbh_omf);

	return 0;
}

int omf_logblock_header_len_le(char *lbuf)
{
	struct logblock_header_omf *lbh_omf;

	lbh_omf = (struct logblock_header_omf *)lbuf;

	if (omf_polh_vers(lbh_omf) == OMF_LOGBLOCK_VERS)
		return OMF_LOGBLOCK_HDR_PACKLEN;

	ev(1);
	return -EINVAL;
}


/*
 * logrec_descriptor
 */
static bool logrec_type_valid(enum logrec_type_omf rtype)
{
	return rtype <= OMF_LOGREC_CEND;
}

bool logrec_type_datarec(enum logrec_type_omf rtype)
{
	return rtype && rtype <= OMF_LOGREC_DATALAST;
}

merr_t
omf_logrec_desc_pack_htole(
	struct omf_logrec_descriptor   *lrd,
	char                           *outbuf)
{
	struct logrec_descriptor_omf   *lrd_omf;

	if (logrec_type_valid(lrd->olr_rtype)) {

		lrd_omf = (struct logrec_descriptor_omf *)outbuf;
		omf_set_polr_tlen(lrd_omf, lrd->olr_tlen);
		omf_set_polr_rlen(lrd_omf, lrd->olr_rlen);
		omf_set_polr_rtype(lrd_omf, lrd->olr_rtype);

		return 0;
	}

	return merr(EINVAL);
}

void
omf_logrec_desc_unpack_letoh(
	struct omf_logrec_descriptor   *lrd,
	const char                     *inbuf)
{
	struct logrec_descriptor_omf   *lrd_omf;

	lrd_omf = (struct logrec_descriptor_omf *)inbuf;
	lrd->olr_tlen  = omf_polr_tlen(lrd_omf);
	lrd->olr_rlen  = omf_polr_rlen(lrd_omf);
	lrd->olr_rtype = omf_polr_rtype(lrd_omf);
}
