// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "mpcore_defs.h"

/*
 * Refer to mpcore_params.h for description on these parameters.
 */
void mpcore_params_defaults(struct mpcore_params *params)
{
	params->mp_mdcnum          = MPOOL_MDCNUM_DEFAULT;
	params->mp_mdc0cap         = 0;
	params->mp_mdcncap         = 0;
	params->mp_smaprgnc        = MPOOL_SMAP_RGNCNT_DEFAULT;
	params->mp_smapalign       = MPOOL_SMAP_ZONEALIGN_DEFAULT;
	params->mp_spare           = MPOOL_SPARES_DEFAULT;
	params->mp_pcopctfull	   = MPOOL_PCO_PCTFULL;
	params->mp_pcopctgarbage   = MPOOL_PCO_PCTGARBAGE;
	params->mp_pconbnoalloc    = MPOOL_PCO_NBNOALLOC;
	params->mp_pcoperiod       = MPOOL_PCO_PERIOD;
	params->mp_pcofillbias     = MPOOL_PCO_FILLBIAS;
	params->mp_crtmdcpctfull   = MPOOL_CREATE_MDC_PCTFULL;
	params->mp_crtmdcpctgrbg   = MPOOL_CREATE_MDC_PCTGRBG;
	params->mp_mpusageperiod   = MPOOL_PD_USAGE_PERIOD;
	params->mp_objloadjobs     = MPOOL_OBJ_LOAD_JOBS_DEFAULT;
}
