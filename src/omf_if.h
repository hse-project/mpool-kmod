/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_OMF_IF_PRIV_H
#define MPOOL_OMF_IF_PRIV_H

/*
 * Common defs: versioned via version number field of enclosing structs
 */

/*
 * struct omf_layout_descriptor: version 1 layout descriptor
 *
 * @ol_zaddr:
 * @ol_zcnt: number of zones
 * @ol_pdh:
 */
struct omf_layout_descriptor {
	u64    ol_zaddr;
	u32    ol_zcnt;
	u16    ol_pdh;
};

/*
 * struct omf_devparm_descriptor: version 1 devparm descriptor
 *
 * @odp_devid:     UUID for drive
 * @odp_devsz:     size, in bytes, of the volume/device
 * @odp_zonetot:    total number of virtual erase blocks
 *
 * The fields below uniquely identify the media class of the PD.
 * All drives in a media class must have the same values in the below fields.
 *
 * @odp_zonepg: virtual erase block size in PAGE_SIZE units for drive
 * @odp_mclassp:   enum mp_media_classp
 * @odp_devtype:   PD type. Enum pd_devtype
 * @odp_sectorsz:  2^podp_sectorsz = sector size
 * @odp_features:  Features, ored bits of enum mp_mc_features
 */
struct omf_devparm_descriptor {
	struct mpool_uuid  odp_devid;
	u64                odp_devsz;
	u32                odp_zonetot;

	u32                odp_zonepg;
	u8                 odp_mclassp;
	u8                 odp_devtype;
	u8                 odp_sectorsz;
	u64                odp_features;
};

/*
 * Superblock (sb) -- version 1
 *
 * Note this is 8-byte-wide reversed to get correct ascii order
 */
#define OMF_SB_MAGIC  0x7665446c6f6f706dULL  /* ASCII mpoolDev - no null */

/*
 * struct omf_sb_descriptor - version 1 superblock descriptor
 *
 * @osb_magic:  mpool magic value
 * @osb_name:   mpool name, contains a terminating 0 byte
 * @osb_cktype: enum mp_cksum_type value
 * @osb_vers:   sb format version
 * @osb_poolid: UUID of pool this drive belongs to
 * @osb_gen:    sb generation number on this drive
 * @osb_parm:   parameters for this drive
 *
 * @osb_mdc01gen:   mdc0 log1 generation number
 * @osb_mdc01uuid:
 * @osb_mdc01devid:
 * @osb_mdc01desc:  mdc0 log1 layout
 *
 * @osb_mdc02gen:   mdc0 log2 generation number
 * @osb_mdc02uuid:
 * @osb_mdc02devid:
 * @osb_mdc02desc:  mdc0 log2 layout
 *
 * osb_mdc0dev:   drive param for mdc0
 */
struct omf_sb_descriptor {
	u64                            osb_magic;
	u8                             osb_name[MPOOL_NAME_LEN_MAX];
	u8                             osb_cktype;
	u16                            osb_vers;
	struct mpool_uuid              osb_poolid;
	u32                            osb_gen;
	struct omf_devparm_descriptor  osb_parm;

	u64                            osb_mdc01gen;
	struct mpool_uuid              osb_mdc01uuid;
	struct mpool_uuid              osb_mdc01devid;
	struct omf_layout_descriptor   osb_mdc01desc;

	u64                            osb_mdc02gen;
	struct mpool_uuid              osb_mdc02uuid;
	struct mpool_uuid              osb_mdc02devid;
	struct omf_layout_descriptor   osb_mdc02desc;

	struct omf_devparm_descriptor  osb_mdc0dev;
};

/* struct omf_logrec_descriptor-
 *
 * @olr_tlen:  logical length of data record (all chunks)
 * @olr_rlen:  length of data chunk in this log record
 * @olr_rtype: enum logrec_type_omf value
 *
 */
struct omf_logrec_descriptor {
	u32    olr_tlen;
	u16    olr_rlen;
	u8     olr_rtype;
};

/*
 * struct omf_logblock_header-
 *
 * @olh_magic:   unique ID per mlog
 * @olh_pfsetid: flush set ID of the previous log block
 * @olh_cfsetid: flush set ID this log block
 * @olh_gen:     generation number
 * @olh_vers:    log block format version
 */
struct omf_logblock_header {
	struct mpool_uuid    olh_magic;
	u32                olh_pfsetid;
	u32                olh_cfsetid;
	u64                olh_gen;
	u16                olh_vers;
};

/**
 * struct omf_mdcver - version of an mpool MDC content.
 * @mdcver:
 *
 * mdcver[0]: major version number
 * mdcver[1]: minor version number
 * mdcver[2]: patch version number
 * mdcver[3]: development version number. Used during development cycle when
 *            the above numbers don't change.
 *
 * This is not the version of the message framing used for the MDC.
 * This the version of the binary that introduced that version of the MDC
 * content.
 */
struct omf_mdcver {
	u16    mdcver[4];
};

#define mdcv_major    mdcver[0]
#define mdcv_minor    mdcver[1]
#define mdcv_patch    mdcver[2]
#define mdcv_dev      mdcver[3]

/*
 * struct omf_mdcrec_data -
 *
 * @omd_version:  OMF_MDR_VERSION record
 *
 * object-related rtypes:
 * ODELETE, OIDCKPT: objid field only; others ignored
 * OERASE: objid and gen fields only; others ignored
 * OCREATE, OUPDATE: layout field only; others ignored
 * @omd_objid:  object identifier
 * @omd_gen:    object generation number
 * @omd_layout:
 * @omd_mblen:  Length of written data in object
 * @omd_old:
 * @omd_uuid:
 *
 * drive_state-
 * @omd_parm:
 *
 * media_cls_spare-
 * @omd_mclassp: mp_media_classp
 * @omd_spzone:   percent spare zones for drives in media class
 *
 * @omd_cfg:
 *
 * @omd_rtype: enum mdcrec_type_omf value
 */
struct omf_mdcrec_data {
	union ustruct {
		struct omf_mdcver omd_version;

		struct object {
			u64                             omd_objid;
			u64                             omd_gen;
			struct pmd_layout              *omd_layout;
			u64                             omd_mblen;
			struct omf_layout_descriptor    omd_old;
			struct mpool_uuid               omd_uuid;
			u8                              omd_mclass;
		} obj;

		struct drive_state {
			struct omf_devparm_descriptor  omd_parm;
		} dev;

		struct media_cls_spare {
			u8 omd_mclassp;
			u8 omd_spzone;
		} mcs;

		struct mpool_config    omd_cfg;
	} u;

	u8             omd_rtype;
};

/**
 * objid_type()
 *
 * Return the type field from an objid.  Retuned as int, so it can also be
 * used for handles, which have the OMF_OBJ_UHANDLE bit set in addition to
 * a type.
 */
static inline int objid_type(u64 objid)
{
	return ((objid & 0xF00) >> 8);
}

static inline bool objtype_valid(enum obj_type_omf otype)
{
	return otype && (otype <= 2);
};

/*
 * omf API functions -- exported functions for working with omf structures
 */

/**
 * omf_sb_pack_htole() - pack superblock
 * @sb: struct omf_sb_descriptor *
 * outbuf: char *
 *
 * Pack superblock into outbuf little-endian computing specified checksum.
 *
 * Return: 0 if successful, merr_t(EINVAL) otherwise
 */
merr_t omf_sb_pack_htole(struct omf_sb_descriptor *sb, char *outbuf);

/**
 * omf_sb_unpack_letoh() - unpack superblock
 * @sb: struct omf_sb_descriptor *
 * @inbuf: char *
 * @omf_ver: on-media-format superblock version
 * @devrpt:
 * Unpack little-endian superblock from inbuf into sb verifying checksum.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
omf_sb_unpack_letoh(
	struct omf_sb_descriptor   *sb,
	const char                 *inbuf,
	u16                        *omf_ver,
	struct mpool_devrpt        *devrpt);

/**
 * omf_sb_has_magic_le() - Determine if buffer has superblock magic value
 * @inbuf: char *
 *
 * Determine if little-endian buffer inbuf has superblock magic value
 * where expected; does NOT imply inbuf is a valid superblock.
 *
 * Return: 1 if true; 0 otherwise
 */
bool omf_sb_has_magic_le(const char *inbuf);

/**
 * omf_logblock_empty_le() - Determine if log block is empty
 * @lbuf: char *
 *
 * Check little-endian log block in lbuf to see if empty (unwritten).
 *
 * Return: 1 if log block is empty; 0 otherwise
 */
bool omf_logblock_empty_le(char *lbuf);

/**
 * omf_logblock_header_pack_htole() - pack log block header
 * @lbh: struct omf_logblock_header *
 * @outbuf: char *
 *
 * Pack header into little-endian log block buffer lbuf, ex-checksum.
 *
 * Return: 0 if successful, merr_t otherwise
 */
merr_t
omf_logblock_header_pack_htole(struct omf_logblock_header *lbh, char *lbuf);

/**
 * omf_logblock_header_len_le() - Determine header length of log block
 * @lbuf: char *
 *
 * Check little-endian log block in lbuf to determine header length.
 *
 * Return: bytes in packed header; -EINVAL if invalid header vers
 */
int omf_logblock_header_len_le(char *lbuf);

/**
 * omf_logblock_header_unpack_letoh() - unpack log block header
 * @lbh: struct omf_logblock_header *
 * @inbuf: char *
 *
 * Unpack little-endian log block header from lbuf into lbh; does not
 * verify checksum.
 *
 * Return: 0 if successful, merr_t (EINVAL) if invalid log block header vers
 */
merr_t
omf_logblock_header_unpack_letoh(
	struct omf_logblock_header *lbh,
	const char                 *inbuf);

/**
 * omf_logrec_desc_pack_htole() - pack log record descriptor
 * @lrd: struct omf_logrec_descriptor *
 * @outbuf: char *
 *
 * Pack log record descriptor into outbuf little-endian.
 *
 * Return: 0 if successful, merr_t (EINVAL) if invalid log rec type
 */
merr_t
omf_logrec_desc_pack_htole(struct omf_logrec_descriptor *lrd, char *outbuf);

/**
 * omf_logrec_desc_unpack_letoh() - unpack log record descriptor
 * @lrd: struct omf_logrec_descriptor *
 * @inbuf: char *
 *
 * Unpack little-endian log record descriptor from inbuf into lrd.
 */
void
omf_logrec_desc_unpack_letoh(
	struct omf_logrec_descriptor   *lrd,
	const char                     *inbuf);

/**
 * omf_mdcrec_pack_htole() - pack mdc record
 * @mp: struct mpool_descriptor *
 * @cdr: struct omf_mdcrec_data *
 * @outbuf: char *
 *
 * Pack mdc record into outbuf little-endian.
 * NOTE: Assumes outbuf has enough space for the layout structure.
 *
 * Return: bytes packed if successful, -EINVAL otherwise
 */
int
omf_mdcrec_pack_htole(
	struct mpool_descriptor    *mp,
	struct omf_mdcrec_data     *cdr,
	char                       *outbuf);

/**
 * omf_mdcrec_unpack_letoh() - unpack mdc record
 * @mdcver: mdc content version of the mdc from which this data comes.
 *          NULL means latest MDC content version known by this binary.
 * @mp:     struct mpool_descriptor *
 * @cdr:    struct omf_mdcrec_data *
 * @inbuf:  char *
 *
 * Unpack little-endian mdc record from inbuf into cdr.
 *
 * Return: 0 if successful, merr_t on error
 */
merr_t
omf_mdcrec_unpack_letoh(
	struct omf_mdcver          *mdcver,
	struct mpool_descriptor    *mp,
	struct omf_mdcrec_data     *cdr,
	const char                 *inbuf);

/**
 * omf_mdcrec_isobj_le() - determine if mdc recordis object-related
 * @inbuf: char *
 *
 * Return true if little-endian mdc record in inbuf is object-related.
 */
int omf_mdcrec_isobj_le(const char *inbuf);

/**
 * omf_mdcver_unpack_letoh() - Unpack le mdc version record from inbuf.
 * @cdr:
 * @inbuf:
 */
void omf_mdcver_unpack_letoh(struct omf_mdcrec_data *cdr, const char *inbuf);

/**
 * omf_mdcrec_unpack_type_letoh() - extract the record type from a
 *	packed MDC record.
 * @inbuf: packed MDC record.
 */
u8 omf_mdcrec_unpack_type_letoh(const char *inbuf);

/**
 * logrec_type_datarec() - data record or not
 * @rtype:
 *
 * Return: true if the log record type is related to a data record.
 */
bool logrec_type_datarec(enum logrec_type_omf rtype);

/**
 * omf_sbver_to_mdcver() - Returns the matching mdc version for a given
 *                          superblock version
 * @sbver: superblock version
 */
struct omf_mdcver *omf_sbver_to_mdcver(enum sb_descriptor_ver_omf sbver);

#endif /* MPOOL_OMF_IF_PRIV_H */
