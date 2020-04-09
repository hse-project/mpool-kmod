/* SPDX-License-Identifier: GPL-2.0-only */
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
 * That includes structures and enums used by the on-drive format.
 *
 * All mpool metadata is versioned and stored on media in little-endian format.
 *
 * Naming conventions:
 * -------------------
 * The name of the structures ends with _omf
 * The name of the structure members start with a "p" that means "packed".
 */

#ifndef MPCORE_OMF_H
#define MPCORE_OMF_H

#include <asm/byteorder.h>

/* The following two macros exist solely to enable the OMF_SETGET macros to
 * work on 8 bit members as well as 16, 32 and 64 bit members.
 */
#define le8_to_cpu(x)  (x)
#define cpu_to_le8(x)  (x)


/* Helper macro to define set/get methods for 8, 16, 32 or 64 bit
 * scalar OMF struct members.
 */
#define OMF_SETGET(type, member, bits) \
	OMF_SETGET2(type, member, bits, member)

#define OMF_SETGET2(type, member, bits, name)				\
	static __always_inline u##bits omf_##name(const type * s)	\
	{								\
		BUILD_BUG_ON(sizeof(((type *)0)->member)*8 != (bits));	\
		return le##bits##_to_cpu(s->member);			\
	}								\
	static __always_inline void omf_set_##name(type *s, u##bits val)\
	{								\
		s->member = cpu_to_le##bits(val);			\
	}

/* Helper macro to define set/get methods for character strings
 * embedded in OMF structures.
 */
#define OMF_SETGET_CHBUF(type, member) \
	OMF_SETGET_CHBUF2(type, member, member)

#define OMF_SETGET_CHBUF2(type, member, name)				\
	static inline void omf_set_##name(type *s, const void *p, size_t plen) \
	{								\
		size_t len = sizeof(((type *)0)->member);		\
		memcpy(s->member, p, len < plen ? len : plen);		\
	}								\
	static inline void omf_##name(const type *s, void *p, size_t plen)\
	{								\
		size_t len = sizeof(((type *)0)->member);		\
		memcpy(p, s->member, len < plen ? len : plen);		\
	}

#define OMF_GET_VER(type, member, bits, ver)                            \
	static __always_inline u##bits omf_##member##_##ver(const type *s)    \
	{                                                               \
		BUILD_BUG_ON(sizeof(((type *)0)->member)*8 != (bits));	\
		return le##bits##_to_cpu(s->member);			\
	}

#define OMF_GET_CHBUF_VER(type, member, ver)                                   \
	static inline void omf_##member##_##ver(const type *s,                 \
						void *p, size_t plen)          \
	{							               \
		size_t len = sizeof(((type *)0)->member);                      \
		memcpy(p, s->member, len < plen ? len : plen);                 \
	}


/* MPOOL_NAME_LEN_MAX should match OMF_MPOOL_NAME_LEN */
#define OMF_MPOOL_NAME_LEN 32

/* MPOOL_UUID_SIZE should match OMF_UUID_PACKLEN */
#define OMF_UUID_PACKLEN 16

/**
 * enum cksum_type_omf - on media checksum types
 *
 * @OMF_CK_UNDEF:
 * @OMF_CK_NONE:
 * @OMF_CK_DIF:
 *
 * The values below are never written on media.
 * @OMF_CK_NUMBER: number of checksum types.
 * @OMF_CK_INVALID:
 */
enum cksum_type_omf {
	OMF_CK_UNDEF  = 0,
	OMF_CK_NONE   = 1,
	OMF_CK_DIF    = 2,
	OMF_CK_NUMBER,
	OMF_CK_INVALID = OMF_CK_NUMBER
};


/**
 * enum mc_features_omf - Drive features that participate in media classes
 *	                  definition. These values are ored in a 64 bits field.
 */
enum mc_features_omf {
	OMF_MC_FEAT_MLOG_TGT   = 0x1,
	OMF_MC_FEAT_MBLOCK_TGT = 0x2,
	OMF_MC_FEAT_CHECKSUM   = 0x4,
};


/**
 * enum devtype_omf -
 *
 * @OMF_PD_DEV_TYPE_BLOCK_STREAM: Block device implementing streams.
 * @OMF_PD_DEV_TYPE_BLOCK_STD:    Standard (non-streams) device (SSD, HDD).
 * @OMF_PD_DEV_TYPE_FILE:	  File in user space for UT.
 * @OMF_PD_DEV_TYPE_MEM:	  Memory semantic device. Such as NVDIMM
 *                                direct access (raw or dax mode).
 * @OMF_PD_DEV_TYPE_ZONE:	  zone-like device, such as open channel SSD
 *				  (OC-SSD) and SMR HDD (using ZBC/ZAC).
 * @OMF_PD_DEV_TYPE_BLOCK_NVDIMM: Standard (non-streams) NVDIMM in sector mode.
 */
enum devtype_omf {
	OMF_PD_DEV_TYPE_BLOCK_STREAM	= 1,
	OMF_PD_DEV_TYPE_BLOCK_STD	= 2,
	OMF_PD_DEV_TYPE_FILE		= 3,
	OMF_PD_DEV_TYPE_MEM		= 4,
	OMF_PD_DEV_TYPE_ZONE		= 5,
	OMF_PD_DEV_TYPE_BLOCK_NVDIMM    = 6,
};


/**
 * struct layout_descriptor_omf - Layout descriptor version 1.
 * Introduced with binary version 1.0.0.0.
 * "pol_" = packed omf layout
 * @pol_zcnt: number of zones
 * @pol_zaddr: zone start addr
 */
struct layout_descriptor_omf {
	__le32 pol_zcnt;
	__le64 pol_zaddr;
} __packed;

/* Define set/get methods for layout_descriptor_omf */
OMF_SETGET(struct layout_descriptor_omf, pol_zcnt, 32)
OMF_SETGET(struct layout_descriptor_omf, pol_zaddr, 64)
#define OMF_LAYOUT_DESC_PACKLEN (sizeof(struct layout_descriptor_omf))


/**
 * struct devparm descriptor_omf -
 * "podp_" = packed omf devparm descriptor
 *
 * @podp_devid: UUID for drive
 * @podp_zonetot: total number of virtual erase blocks
 * @podp_devsz: size of partition in bytes
 * @podp_features:  Features, ored bits of enum mc_features_omf
 *
 * The fields below uniquely identify the media class of the PD.
 * All drives in a media class must have the same values in the below
 * fields.
 * @podp_mclassp:   enum mp_media_classp
 * @podp_devtype:   PD type (enum devtype_omf)
 * @podp_sectorsz:  2^podp_sectorsz = sector size
 * @podp_zonepg: virtual erase block size in PAGE_SIZE units for drive.
 */
struct devparm_descriptor_omf {
	u8     podp_mclassp;
	u8     podp_devtype;
	u8     podp_sectorsz;
	u8     podp_devid[OMF_UUID_PACKLEN];
	u8     podp_pad[5];
	__le32 podp_zonepg;
	__le32 podp_zonetot;
	__le64 podp_devsz;
	__le64 podp_features;
} __packed;

/* Define set/get methods for devparm_descriptor_omf */
OMF_SETGET(struct devparm_descriptor_omf, podp_mclassp, 8)
OMF_SETGET(struct devparm_descriptor_omf, podp_devtype, 8)
OMF_SETGET(struct devparm_descriptor_omf, podp_sectorsz, 8)
OMF_SETGET_CHBUF(struct devparm_descriptor_omf, podp_devid)
OMF_SETGET(struct devparm_descriptor_omf, podp_zonepg, 32)
OMF_SETGET(struct devparm_descriptor_omf, podp_zonetot, 32)
OMF_SETGET(struct devparm_descriptor_omf, podp_devsz, 64)
OMF_SETGET(struct devparm_descriptor_omf, podp_features, 64)
#define OMF_DEVPARM_DESC_PACKLEN (sizeof(struct devparm_descriptor_omf))


/*
 * mlog structure:
 * + An mlog comprises a consecutive sequence of log blocks,
 *   where each log block is a single page within a zone
 * + A log block comprises a header and a consecutive sequence of records
 * + A record is a typed blob
 *
 * Log block headers must be versioned. Log block records do not
 * require version numbers because they are typed and new types can
 * always be added.
 */

/**
 * Log block format -- version 1
 *
 * log block := header record+ eolb? trailer?
 *
 * header := struct omf_logblock_header where vers=2
 *
 * record := lrd byte*
 *
 * lrd := struct omf_logrec_descriptor with value
 *   (<record length>, <chunk length>, enum logrec_type_omf value)
 *
 * eolb (end of log block marker) := struct omf_logrec_descriptor with value
 *   (0, 0, enum logrec_type_omf.EOLB/0)
 *
 * trailer := zero bytes from end of last log block record to end of log block
 *
 * OMF_LOGREC_CEND must be the max. value for this enum.
 */
/*
 *  enum logrec_type_omf -
 *
 *  A log record type of 0 signifies EOLB. This is really the start of the
 *  trailer but this simplifies parsing for partially filled log blocks.
 *  DATAFIRST, -MID, -LAST types are used for chunking logical data records.
 *
 *  @OMF_LOGREC_EOLB:      end of log block marker (start of trailer)
 *  @OMF_LOGREC_DATAFULL:  data record; contains all specified data
 *  @OMF_LOGREC_DATAFIRST: data record; contains first part of specified data
 *  @OMF_LOGREC_DATAMID:   data record; contains interior part of data
 *  @OMF_LOGREC_DATALAST:  data record; contains final part of specified data
 *  @OMF_LOGREC_CSTART:    compaction start marker
 *  @OMF_LOGREC_CEND:      compaction end marker
 */
enum logrec_type_omf {
	OMF_LOGREC_EOLB      = 0,
	OMF_LOGREC_DATAFULL  = 1,
	OMF_LOGREC_DATAFIRST = 2,
	OMF_LOGREC_DATAMID   = 3,
	OMF_LOGREC_DATALAST  = 4,
	OMF_LOGREC_CSTART    = 5,
	OMF_LOGREC_CEND      = 6,
};


/**
 * struct logrec_descriptor_omf -
 * "polr_" = packed omf logrec descriptor
 *
 * @polr_tlen:  logical length of data record (all chunks)
 * @polr_rlen:  length of data chunk in this log record
 * @polr_rtype: enum logrec_type_omf value
 */
struct logrec_descriptor_omf {
	__le32 polr_tlen;
	__le16 polr_rlen;
	u8     polr_rtype;
	u8     polr_pad;
} __packed;

/* Define set/get methods for logrec_descriptor_omf */
OMF_SETGET(struct logrec_descriptor_omf, polr_tlen, 32)
OMF_SETGET(struct logrec_descriptor_omf, polr_rlen, 16)
OMF_SETGET(struct logrec_descriptor_omf, polr_rtype, 8)
#define OMF_LOGREC_DESC_PACKLEN (sizeof(struct logrec_descriptor_omf))
#define OMF_LOGREC_DESC_RLENMAX 65535


#define OMF_LOGBLOCK_VERS    1

/**
 * struct logblock_header_omf - for all versions
 * "polh_" = packed omf logblock header
 *
 * @polh_vers:    log block hdr version, offset 0 in all vers
 * @polh_magic:   unique magic per mlog
 * @polh_pfsetid: flush set ID of the previous log block
 * @polh_cfsetid: flush set ID this log block belongs to
 * @polh_gen:     generation number
 */
struct logblock_header_omf {
	__le16 polh_vers;
	u8     polh_magic[OMF_UUID_PACKLEN];
	u8     polh_pad[6];
	__le32 polh_pfsetid;
	__le32 polh_cfsetid;
	__le64 polh_gen;
} __packed;

/* Define set/get methods for logblock_header_omf */
OMF_SETGET(struct logblock_header_omf, polh_vers, 16)
OMF_SETGET_CHBUF(struct logblock_header_omf, polh_magic)
OMF_SETGET(struct logblock_header_omf, polh_pfsetid, 32)
OMF_SETGET(struct logblock_header_omf, polh_cfsetid, 32)
OMF_SETGET(struct logblock_header_omf, polh_gen, 64)
/* On-media log block header length */
#define OMF_LOGBLOCK_HDR_PACKLEN (sizeof(struct logblock_header_omf))


/*
 * Metadata container (mdc) mlog data record formats.
 *
 * NOTE: mdc records are typed and as such do not need a version number as new
 * types can always be added as required.
 */
/**
 * enum mdcrec_type_omf -
 *
 * @OMF_MDR_UNDEF:   undefined; should never occur
 * @OMF_MDR_OCREATE:  object create
 * @OMF_MDR_OUPDATE:  object update
 * @OMF_MDR_ODELETE:  object delete
 * @OMF_MDR_OIDCKPT:  object id checkpoint
 * @OMF_MDR_OERASE:   object erase, also log mlog gen number
 * @OMF_MDR_MCCONFIG: media class config
 * @OMF_MDR_MCSPARE:  media class spare zones set
 * @OMF_MDR_VERSION:  MDC content version.
 * @OMF_MDR_MPCONFIG:  mpool config record
 */
enum mdcrec_type_omf {
	OMF_MDR_UNDEF       = 0,
	OMF_MDR_OCREATE     = 1,
	OMF_MDR_OUPDATE     = 2,
	OMF_MDR_ODELETE     = 3,
	OMF_MDR_OIDCKPT     = 4,
	OMF_MDR_OERASE      = 5,
	OMF_MDR_MCCONFIG    = 6,
	OMF_MDR_MCSPARE     = 7,
	OMF_MDR_VERSION     = 8,
	OMF_MDR_MPCONFIG    = 9,
	OMF_MDR_MAX         = 10,
};

/**
 * struct mdccver_omf - version of an mpool MDC content.
 *
 * This is not the version of the message framing used for the MDC. This is
 * version of the binary that introduced that version of the MDC content.
 * "pv_"= packed mdc version.
 *
 * @pv_rtype: OMF_MDR_VERSION
 * @pv_mdccver_major: to compare with MAJOR in binary version.
 * @pv_mdccver_minor: to compare with MINOR in binary version.
 * @pv_mdccver_patch: to compare with PATCH in binary version.
 * @pv_mdccver_dev:   used during development cycle when the above
 *	numbers don't change.
 *
 */
struct mdccver_omf {
	u8     pv_rtype;
	u8     pv_pad;
	__le16 pv_mdccver_major;
	__le16 pv_mdccver_minor;
	__le16 pv_mdccver_patch;
	__le16 pv_mdccver_dev;
} __packed;

/* Define set/get methods for mdcrec_version_omf */
OMF_SETGET(struct mdccver_omf, pv_rtype, 8)
OMF_SETGET(struct mdccver_omf, pv_mdccver_major, 16)
OMF_SETGET(struct mdccver_omf, pv_mdccver_minor, 16)
OMF_SETGET(struct mdccver_omf, pv_mdccver_patch, 16)
OMF_SETGET(struct mdccver_omf, pv_mdccver_dev,   16)


/**
 * struct mdcrec_data_odelete_omf -
 * "pdro_" = packed data record odelete
 *
 * @pdro_rtype: mdrec_type_omf:OMF_MDR_ODELETE, OMF_MDR_OIDCKPT
 * @pdro_objid: object identifier
 */
struct mdcrec_data_odelete_omf {
	u8     pdro_rtype;
	u8     pdro_pad[7];
	__le64 pdro_objid;
} __packed;

/* Define set/get methods for  mdcrec_data_odelete_omf */
OMF_SETGET(struct  mdcrec_data_odelete_omf, pdro_rtype, 8)
OMF_SETGET(struct  mdcrec_data_odelete_omf, pdro_objid, 64)


/**
 * struct mdcrec_data_oerase_omf -
 * "pdrt_" = packed data record oerase
 *
 * @pdrt_rtype: mdrec_type_omf: OMF_MDR_OERASE
 * @pdrt_objid: object identifier
 * @pdrt_gen:   object generation number
 */
struct mdcrec_data_oerase_omf {
	u8     pdrt_rtype;
	u8     pdrt_pad[7];
	__le64 pdrt_objid;
	__le64 pdrt_gen;
} __packed;

/* Define set/get methods for mdcrec_data_oerase_omf */
OMF_SETGET(struct mdcrec_data_oerase_omf, pdrt_rtype, 8)
OMF_SETGET(struct mdcrec_data_oerase_omf, pdrt_objid, 64)
OMF_SETGET(struct mdcrec_data_oerase_omf, pdrt_gen, 64)
#define OMF_MDCREC_OERASE_PACKLEN (sizeof(struct mdcrec_data_oerase_omf))


/**
 * struct mdcrec_data_mcconfig_omf -
 * "pdrs_" = packed data record mclass config
 *
 * @pdrs_rtype: mdrec_type_omf: OMF_MDR_MCCONFIG
 * @pdrs_parm:
 */
struct mdcrec_data_mcconfig_omf {
	u8                             pdrs_rtype;
	u8                             pdrs_pad[7];
	struct devparm_descriptor_omf  pdrs_parm;
} __packed;


OMF_SETGET(struct mdcrec_data_mcconfig_omf, pdrs_rtype, 8)
#define OMF_MDCREC_MCCONFIG_PACKLEN (sizeof(struct mdcrec_data_mcconfig_omf))


/**
 * struct mdcrec_data_mcspare_omf -
 * "pdra_" = packed data record mcspare
 *
 * @pdra_rtype:   mdrec_type_omf: OMF_MDR_MCSPARE
 * @pdra_mclassp: enum mp_media_classp
 * @pdra_spzone:   percent spare zones for drives in media class
 */
struct mdcrec_data_mcspare_omf {
	u8     pdra_rtype;
	u8     pdra_mclassp;
	u8     pdra_spzone;
} __packed;

/* Define set/get methods for mdcrec_data_mcspare_omf */
OMF_SETGET(struct mdcrec_data_mcspare_omf, pdra_rtype, 8)
OMF_SETGET(struct mdcrec_data_mcspare_omf, pdra_mclassp, 8)
OMF_SETGET(struct mdcrec_data_mcspare_omf, pdra_spzone, 8)
#define OMF_MDCREC_CLS_SPARE_PACKLEN (sizeof(struct mdcrec_data_mcspare_omf))


/**
 * struct mdcrec_data_ocreate_omf -
 * "pdrc_" = packed data record ocreate
 *
 * @pdrc_rtype:     mdrec_type_omf: OMF_MDR_OCREATE or OMF_MDR_OUPDATE
 * @pdrc_mclass:
 * @pdrc_uuid:
 * @pdrc_ld:
 * @pdrc_objid:     object identifier
 * @pdrc_gen:       object generation number
 * @pdrc_mblen:     amount of data written in the mblock, for mlog this is 0
 * @pdrc_uuid:      Used only for mlogs. Must be at the end of this struct.
 */
struct mdcrec_data_ocreate_omf {
	u8                             pdrc_rtype;
	u8                             pdrc_mclass;
	u8                             pdrc_pad[2];
	struct layout_descriptor_omf   pdrc_ld;
	__le64                         pdrc_objid;
	__le64                         pdrc_gen;
	__le64                         pdrc_mblen;
	u8                             pdrc_uuid[];
} __packed;

/* Define set/get methods for mdcrec_data_ocreate_omf */
OMF_SETGET(struct mdcrec_data_ocreate_omf, pdrc_rtype, 8)
OMF_SETGET(struct mdcrec_data_ocreate_omf, pdrc_mclass, 8)
OMF_SETGET(struct mdcrec_data_ocreate_omf, pdrc_objid, 64)
OMF_SETGET(struct mdcrec_data_ocreate_omf, pdrc_gen, 64)
OMF_SETGET(struct mdcrec_data_ocreate_omf, pdrc_mblen, 64)
#define OMF_MDCREC_OBJCMN_PACKLEN (sizeof(struct mdcrec_data_ocreate_omf) + \
				   OMF_UUID_PACKLEN)


/**
 * struct mdcrec_data_mpconfig_omf -
 * "pdmc_" = packed data mpool config
 *
 * @pdmc_rtype:
 * @pdmc_oid1:
 * @pdmc_oid2:
 * @pdmc_uid:
 * @pdmc_gid:
 * @pdmc_mode:
 * @pdmc_mclassp:
 * @pdmc_captgt:
 * @pdmc_ra_pages_max:
 * @pdmc_vma_size_max:
 * @pdmc_utype:         user-defined type (uuid)
 * @pdmc_label:         user-defined label (ascii)
 */
struct mdcrec_data_mpconfig_omf {
	u8      pdmc_rtype;
	u8      pdmc_pad[7];
	__le64  pdmc_oid1;
	__le64  pdmc_oid2;
	__le32  pdmc_uid;
	__le32  pdmc_gid;
	__le32  pdmc_mode;
	__le32  pdmc_mclassp;
	__le64  pdmc_captgt;
	__le32  pdmc_ra_pages_max;
	__le32  pdmc_vma_size_max;
	__le32  pdmc_rsvd1;
	__le32  pdmc_rsvd2;
	__le64  pdmc_rsvd3;
	__le64  pdmc_rsvd4;
	u8      pdmc_utype[16];
	u8      pdmc_label[MPOOL_LABELSZ_MAX];
} __packed;

/* Define set/get methods for mdcrec_data_mpconfig_omf */
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_rtype, 8)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_oid1, 64)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_oid2, 64)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_uid, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_gid, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_mode, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_mclassp, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_captgt, 64)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_ra_pages_max, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_vma_size_max, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_rsvd1, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_rsvd2, 32)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_rsvd3, 64)
OMF_SETGET(struct mdcrec_data_mpconfig_omf, pdmc_rsvd4, 64)
OMF_SETGET_CHBUF(struct mdcrec_data_mpconfig_omf, pdmc_utype)
OMF_SETGET_CHBUF(struct mdcrec_data_mpconfig_omf, pdmc_label)
#define OMF_MDCREC_MPCONFIG_PACKLEN (sizeof(struct mdcrec_data_mpconfig_omf))


/**
 * Object types embedded in opaque uint64 object ids by the pmd module.
 * This encoding is also present in the object ids stored in the
 * data records on media.
 *
 * The obj_type field is 4 bits. There are two valid obj types.
 * In memory, but not on media, we use the high order bit to differrentiate
 * an objid from a user handle for the object.  If the high order bit
 * (OMF_OBJ_UHANDLE) is set, it's a user handle and not an objid
 * (but we can convert it back to a handle by clearing that bit).
 */
enum obj_type_omf {
	OMF_OBJ_UNDEF       = 0,
	OMF_OBJ_MBLOCK      = 1,
	OMF_OBJ_MLOG        = 2,
	OMF_OBJ_UHANDLE     = 8,
};


/**
 * sb_descriptor_ver_omf - Mpool super block version
 * @OMF_SB_DESC_UNDEF: value not on media
 */
enum sb_descriptor_ver_omf {
	OMF_SB_DESC_UNDEF        = 0,
	OMF_SB_DESC_V1           = 1,

};
#define OMF_SB_DESC_VER_LAST   OMF_SB_DESC_V1


/*
 * struct sb_descriptor_omf - super block descriptor format version 1.
 * "psb_" = packed super block
 *
 * Note: these fields, up to and including psb_cksum1, are known to libblkid.
 * cannot change them without havoc. Fields from psb_magic to psb_cksum1
 * included are at same offset in all versions.
 *
 * @psb_magic:  mpool magic value; offset 0 in all vers
 * @psb_name:   mpool name
 * @psb_poolid: UUID of pool this drive belongs to
 * @psb_vers:   sb format version; offset 56
 * @psb_gen:    sb generation number on this drive
 * @psb_cksum1: checksum of all fields above
 *
 * @psb_parm:   parameters for this drive
 * @psb_cksum2: checksum of psb_parm
 *
 * @psb_mdc01gen:   mdc0 log1 generation number
 * @psb_mdc01uuid:
 * @psb_mdc01devid: mdc0 log1 device UUID
 * @psb_mdc01strip: mdc0 log1 strip desc.
 * @psb_mdc01desc:  mdc0 log1 layout
 *
 * @psb_mdc02gen:   mdc0 log2 generation number
 * @psb_mdc02uuid:
 * @psb_mdc02devid: mdc0 log2 device UUID
 * @psb_mdc02strip: mdc0 log2 strip desc.
 * @psb_mdc02desc:  mdc0 log2 layout
 *
 * @psb_mdc0dev:    drive param for mdc0 strip
 */
struct sb_descriptor_omf {
	__le64                         psb_magic;
	u8                             psb_name[OMF_MPOOL_NAME_LEN];
	u8                             psb_poolid[OMF_UUID_PACKLEN];
	__le16                         psb_vers;
	__le32                         psb_gen;
	u8                             psb_cksum1[4];

	u8                             psb_pad1[6];
	struct devparm_descriptor_omf  psb_parm;
	u8                             psb_cksum2[4];

	u8                             psb_pad2[4];
	__le64                         psb_mdc01gen;
	u8                             psb_mdc01uuid[OMF_UUID_PACKLEN];
	u8                             psb_mdc01devid[OMF_UUID_PACKLEN];
	struct layout_descriptor_omf   psb_mdc01desc;

	u8                             psb_pad3[4];
	__le64                         psb_mdc02gen;
	u8                             psb_mdc02uuid[OMF_UUID_PACKLEN];
	u8                             psb_mdc02devid[OMF_UUID_PACKLEN];
	struct layout_descriptor_omf   psb_mdc02desc;

	u8                             psb_pad4[4];
	struct devparm_descriptor_omf  psb_mdc0dev;
} __packed;

OMF_SETGET(struct sb_descriptor_omf, psb_magic, 64)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_name)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_poolid)
OMF_SETGET(struct sb_descriptor_omf, psb_vers, 16)
OMF_SETGET(struct sb_descriptor_omf, psb_gen, 32)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_cksum1)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_cksum2)
OMF_SETGET(struct sb_descriptor_omf, psb_mdc01gen, 64)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_mdc01uuid)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_mdc01devid)
OMF_SETGET(struct sb_descriptor_omf, psb_mdc02gen, 64)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_mdc02uuid)
OMF_SETGET_CHBUF(struct sb_descriptor_omf, psb_mdc02devid)
#define OMF_SB_DESC_PACKLEN (sizeof(struct sb_descriptor_omf))

/*
 * For object-related records OCREATE/OUPDATE is max so compute that here as:
 * rtype + objid + gen + layout desc
 */
#define OMF_MDCREC_PACKLEN_MAX max(OMF_MDCREC_OBJCMN_PACKLEN,            \
				   max(OMF_MDCREC_MCCONFIG_PACKLEN,      \
				       max(OMF_MDCREC_CLS_SPARE_PACKLEN, \
					   OMF_MDCREC_MPCONFIG_PACKLEN)))

#endif /* MPCORE_OMF_H */
