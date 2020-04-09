/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_PD_BIO_PRIV_H
#define MPOOL_PD_BIO_PRIV_H

#include "pd.h"

/**
 * PD bio layers operation performed on the Linux block layer.
 */
enum pd_bio_op {
	PD_BIO_OP_READ,
	PD_BIO_OP_WRITE,
	PD_BIO_OP_DISCARD,
	PD_BIO_OP_FLUSH,
};

#endif
