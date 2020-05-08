/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_OMF_INT_H
#define MPOOL_OMF_INT_H

enum unpack_only {
	UNPACKONLY,
	UNPACKCONVERT
};

/**
 * omf_sb_unpack_letoh_v1()- unpack version 1 omf sb descriptor into
 *                           in-memory format
 * @out: in-memory format
 * @inbuf: omf format
 */
merr_t omf_sb_unpack_letoh_v1(void *out, const char *inbuf);

/**
 * omf_layout_unpack_letoh_v1: unpack omf layout descriptor (version 1)
 * @out: in-memory layout descriptor
 * @in: on-media layout descriptor
 */
merr_t omf_layout_unpack_letoh_v1(void *out, const char *inbuf);

/**
 * omf_ecio_layout_pack_htole() - Pack ecio_layout desc into outbuf
 *	little-endian.
 * @mp:
 * @rtype:
 * @ecl:
 * @outbuf:
 *
 * NOTE: Assumes that there is enough space in outbuf for the layout
 *
 * Return: bytes packed if successful, -EINVAL otherwise
 */
int
omf_ecio_layout_pack_htole(
	const struct mpool_descriptor  *mp,
	u8                              rtype,
	struct ecio_layout             *ecl,
	char                           *outbuf);

/**
 * omf_dparm_pack_htole() - pack dparm
 * @dp: struct omf_devparm_descriptor *
 * @outbuf: char *
 *
 * Pack dparm into outbuf little-endian
 *
 * Translate pd_devtype into devtype_omf
 */
void omf_dparm_pack_htole(struct omf_devparm_descriptor *dp, char *outbuf);

/**
 * omf_dparm_unpack_letoh() - unpack dparm
 * @dp: struct omf_devparm_descriptor *
 * @inbuf: char *
 * @sbver: superblock version
 * @mdccver: mdc version
 * @unpackonly: If UNPACKONLY don't do a conversion
 *
 * Unpack little-endian devparm descriptor from inbuf
 *
 * Translate devtype_omf into pd_devtype
 */
merr_t
omf_dparm_unpack_letoh(
	struct omf_devparm_descriptor *dp,
	const char                    *inbuf,
	enum sb_descriptor_ver_omf     sbver,
	struct omf_mdccver            *mdccver,
	enum unpack_only	       unpackonly);

/**
 * omf_mdcrec_mcspare_pack_htole() - Pack mdc media class spare record into
 *	outbuf little-endian.
 * @cdr:
 * @outbuf:
 *
 * Return: bytes packed if successful, -EINVAL otherwise
 */
u64 omf_mdcrec_mcspare_pack_htole(struct omf_mdcrec_data *cdr, char *outbuf);

/**
 * omf_layout_pack_htole() - pack layout descriptor
 * @ld: struct omf_layout_descriptor *
 * @outbuf: char *
 *
 * Pack layout descriptor into outbuf little-endian
 *
 * Translate mp_ecode_type into ecode_type_omf
 * Translate mp_cksum_type into cksum_type_omf
 */
void
omf_layout_pack_htole(const struct omf_layout_descriptor *ld, char *outbuf);

/**
 * omf_layout_unpack_letoh() - unpack layout descriptor
 * @ld: struct omf_layout_descriptor *
 * @inbuf: char *
 * @ver: superblock version
 * @mdccver: mdc version
 * @unpackonly: if UNPACKONLY, then do not convert.
 *
 * Unpack little-endian layout descriptor from inbuf
 *
 * Translate ecode_type_omf into mp_ecode_type
 * Translate cksum_type_omf into mp_cksum_type
 */
merr_t
omf_layout_unpack_letoh(
	struct omf_layout_descriptor   *ld,
	const char                     *inbuf,
	enum sb_descriptor_ver_omf      sbver,
	struct omf_mdccver             *mdccver,
	enum unpack_only                unpackonly);

/**
 * omf_unpack_letoh_and_convert() - unpack OMF meta data and convert
 *         it to the lattest version
 * @out: in-memory structure
 * @outsz: size of in-memory structure
 * @inbuf: OMF structure
 * @upg_hist_tbl: upgrade history table
 * @tblsz: number of elements in upg_hist_tbl
 * @sbver: superblock version
 * @mdccver: mdc version. if set to NULL, use sbver to find
 *           the corresponding nested structure upgrade table
 */
merr_t
omf_unpack_letoh_and_convert(
	void                           *out,
	size_t                          outsz,
	const char                     *inbuf,
	struct upg_history             *upg_hist_tbl,
	size_t                          tblsz,
	enum sb_descriptor_ver_omf      sbver,
	struct omf_mdccver             *mdccver);

/**
 * omf_upgrade_unpack_only() - unpack OMF meta data
 * @out: output buffer for in-memory structure
 * @outsz: size of output buffer
 * @inbuf: OMF structure
 * @upg_hist_tbl: upgrade history table
 * @tblsz: NELEM of upg_hist_tbl
 * @sbver: superblock version
 * @mdccver: mpool MDC content version
 */
merr_t
omf_upgrade_unpack_only(
	void                           *out,
	size_t                          outsz,
	const char                     *inbuf,
	struct upg_history             *upg_hist_tbl,
	size_t                          tblsz,
	enum sb_descriptor_ver_omf      sbver,
	struct omf_mdccver             *mdccver);

/**
 * omf_upgrade_convert_only()- convert a nested metadata structure
 *         in mpool superblock or MDC from v1 to v2 (v1 <= v2);
 * @out: v2 in-memory metadata structure
 * @outsz: size of v2 in-memory metadata structure
 * @in: v1 in-memory metadata structure
 * @upg_hist_tbl: upgrade history table for this structure
 * @tblsz: NELEM(upg_hist_tbl)
 * @sbver_v1: superblock version converting from
 * @sbver_v2: superblock version converting to
 * @mdccver_v1: mdc version converting from
 * @mdccver_v1: mdc version converting to
 *
 * Note that callers can pass in either mdc beg/end versions
 * (mdccver_v1/mdccver_v2), or superblock beg/end versions
 * (sbver_v1/sbver_v2). Set both mdccver_v1 and mdccver_v2
 * to NULL, if caller wants to use superblock versions
 */
merr_t
omf_upgrade_convert_only(
	void                           *out,
	size_t                          outsz,
	const void                     *in,
	struct upg_history             *upg_hist_tbl,
	size_t                          tblsz,
	enum sb_descriptor_ver_omf      sbver_v1,
	enum sb_descriptor_ver_omf      sbver_v2,
	struct omf_mdccver             *mdccver_v1,
	struct omf_mdccver             *mdccver_v2);

/**
 * omf_find_upgrade_hist() - Given a superblock version or a
 *	mpool MDC content version, find the corresponding upgrade history
 *	entry which matches the given sb or mdc version.
 *	That is the entry with the highest version such as
 *	entry version <= the version passed in.
 *
 * @upgrade_table:
 * @table_sz: NELEM of upgrade_table
 * @sbver: superblock version
 * @mdccver: mdc version
 *
 * Note that caller of this routine can pass in either a valid superblock
 * version or a valid mdc verison. If a valid superblock version is passed in,
 * mdccver need to be set to NULL. If a mdc version is passed in, sbver
 * need to set to 0.
 *
 * For example,
 * We update a structure "struct abc" three times, which is part of mpool
 * superblock or MDC. when superblock version is  1, 3 and 5 respectively.
 * Each time we add an entry in the upgrade table for this structure.
 * The upgrade history table looks like:
 *
 * struct upg_history abc_hist[] =
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
struct upg_history *
omf_find_upgrade_hist(
	struct upg_history             *upgrade_table,
	size_t                          table_sz,
	enum sb_descriptor_ver_omf      sbver,
	struct omf_mdccver             *mdccver);

/*
 * omf_cksum_crc32c_le() -
 *   Compute 4-byte checksum of type CRC32C for data buffer dbuf with
 *   length dlen and store in obuf little-endian;
 *   CRC32C is the only crypto algorithm we currently support
 * @dbuf: data buf
 * @dlen: data length
 * @obuf: output buf
 *   Return: 0 if successful, merr_t(EINVAL) otherwise
 */
merr_t omf_cksum_crc32c_le(const char *dbuf, u64 dlen, u8 *obuf);

#define OMF_LAYOUT_DESC_TABLE_SZ           1
#define OMF_DEVPARM_DESC_TABLE_SZ          1
#define OMF_MDCREC_DATA_MCSPARE_TABLE_SZ   1
#define OMF_SB_DESC_TABLE_SZ               1
#define OMF_MDCREC_DATA_OCREATE_TABLE_SZ   1

extern struct upg_history layout_descriptor_table[OMF_LAYOUT_DESC_TABLE_SZ];
extern struct upg_history devparm_descriptor_table[OMF_DEVPARM_DESC_TABLE_SZ];
extern struct upg_history
	mdcrec_data_mcspare_table[OMF_MDCREC_DATA_MCSPARE_TABLE_SZ];
extern struct upg_history sb_descriptor_table[OMF_SB_DESC_TABLE_SZ];
extern struct upg_history
	mdcrec_data_ocreate_table[OMF_MDCREC_DATA_OCREATE_TABLE_SZ];

#endif
