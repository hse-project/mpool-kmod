/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PARAMS_H
#define MPOOL_PARAMS_H

#include "merr.h"

#define MPOOL_MDC_SET_SZ                16

/* Mpool metadata container compaction retries; keep relatively small */
#define MPOOL_MDC_COMPACT_RETRY_DEFAULT 5

/*
 * Space map allocation zones per drive; bounds number of concurrent obj
 * allocs
 */
#define MPOOL_SMAP_RGNCNT_DEFAULT       4

/*
 * Space map alignment in number of zones.
 */
#define MPOOL_SMAP_ZONEALIGN_DEFAULT    1

/*
 * Number of concurent jobs for loading user MDC 1~N
 */
#define MPOOL_OBJ_LOAD_JOBS_DEFAULT     8

/*
 * Defaults for MDC1/255 pre-compaction.
 */
#define MPOOL_PCO_PCTFULL               70
#define MPOOL_PCO_PCTGARBAGE            20
#define MPOOL_PCO_NBNOALLOC              2
#define MPOOL_PCO_PERIOD                 5
#define MPOOL_PCO_FILLBIAS	      1000
#define MPOOL_PD_USAGE_PERIOD        60000
#define MPOOL_CREATE_MDC_PCTFULL  (MPOOL_PCO_PCTFULL - MPOOL_PCO_PCTGARBAGE)
#define MPOOL_CREATE_MDC_PCTGRBG   MPOOL_PCO_PCTGARBAGE


/*
 * struct mpcore_params - mpool core parameters. Not exported to public API.
 *
 * @mp_mdc0cap: MDC0 capacity,  *ONLY* for testing purpose
 * @mp_mdcncap: MDCN capacity,  *ONLY* for testing purpose
 * @mp_mdcnnum: Number of MDCs, *ONLY* for testing purpose
 * @mp_smaprgnc:
 * @mp_smapalign:
 * @mp_spare:
 * @mp_objloadjobs: number of concurrent MDC loading jobs
 *
 * The below parameters starting with "pco" are used for the pre-compaction
 * of MDC1/255
 * @mp_pcopctfull:  % (0-100) of fill of MDCi active mlog that must be reached
 *	before a pre-compaction is attempted.
 * @mp_pcopctgarbage:  % (0-100) of garbage in MDCi active mlog that must be
 *	reached	before a pre-compaction is attempted.
 * @mp_pconbnoalloc: Number of MDCs from which no object is allocated from.
 *	If 0, that disable the background pre compaction.
 * @mp_pcoperiod: In seconds. Period at which a background thread check if
 *	a MDC needs compaction.
 * @mp_pcofillbias: If the next mpool MDC has less objects than
 *	(current MDC objects - pcofillbias), then allocate an object
 *	from the next MDC instead of from the current one.
 *	This bias favors object allocation from less filled MDCs (in term
 *	of number of committed objects).
 *	The bigger the number, the less bias.
 * @mp_crtmdcpctfull: percent full threshold across all MDCs in combination
 *      with crtmdcpctgrbg percent is used as a trigger to create new MDCs
 * @mp_crtmdcpctgrbg: percent garbage threshold in combination with
 *      @crtmdcpctfull percent is used as a trigger to create new MDCs
 * @mp_mpusageperiod: period at which a background thread check mpool space
 * usage, in milliseconds
 */
struct mpcore_params {
	u64    mp_mdcnum;
	u64    mp_mdc0cap;
	u64    mp_mdcncap;
	u64    mp_smaprgnc;
	u64    mp_smapalign;
	u64    mp_spare;
	u64    mp_objloadjobs;
	u64    mp_pcopctfull;
	u64    mp_pcopctgarbage;
	u64    mp_pconbnoalloc;
	u64    mp_pcoperiod;
	u64    mp_pcofillbias;
	u64    mp_crtmdcpctfull;
	u64    mp_crtmdcpctgrbg;
	u64    mp_mpusageperiod;
};

/**
 * mpcore_params_defaults() -
 */
void mpcore_params_defaults(struct mpcore_params *params);

#endif /* MPOOL_PARAMS_H */
