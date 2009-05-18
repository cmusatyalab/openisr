/*
 * libisrcrypto - cryptographic library for the OpenISR (R) system
 *
 * Copyright (C) 2008-2009 Carnegie Mellon University
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.  A copy of the GNU Lesser General
 * Public License should have been distributed along with this library in the
 * file LICENSE.LGPL.
 *          
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 */

#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"
#include "dh_tab.h"

struct isrcry_dh_desc {
	unsigned max_entropy;  /* in bytes; this is a sanity check only */
	unsigned generator;
	const char *prime;
	unsigned primelen;
};

#define PRIME(a) .prime = a, .primelen = sizeof(a)

/* IKE group 14 from RFC 3526 */
static const struct isrcry_dh_desc _isrcry_dh_ike_2048_desc = {
	.max_entropy = 20,
	.generator = 2,
	PRIME(_isrcry_dh_ike_2048_prime),
};

#undef PRIME

struct isrcry_dh_ctx {
	const struct isrcry_dh_desc *desc;
	struct isrcry_random_ctx *rctx;
	mpz_t generator;
	mpz_t prime;
	mpz_t private;
	mpz_t public;
};

static const struct isrcry_dh_desc *dh_desc(enum isrcry_dh type)
{
	switch (type) {
	case ISRCRY_DH_IKE_2048:
		return &_isrcry_dh_ike_2048_desc;
	}
	return NULL;
}

static void write_val(struct isrcry_dh_ctx *dctx, mpz_t val, void *out)
{
	int padlen;

	padlen = dctx->desc->primelen - mpz_unsigned_bin_size(val);
	g_assert(padlen >= 0);
	memset(out, 0, padlen);
	mpz_to_unsigned_bin(out + padlen, val);
}

exported struct isrcry_dh_ctx *isrcry_dh_alloc(enum isrcry_dh type,
			struct isrcry_random_ctx *rctx)
{
	struct isrcry_dh_ctx *dctx;

	if (rctx == NULL)
		return NULL;
	dctx = g_slice_new0(struct isrcry_dh_ctx);
	dctx->desc = dh_desc(type);
	if (dctx->desc == NULL) {
		g_slice_free(struct isrcry_dh_ctx, dctx);
		return NULL;
	}
	dctx->rctx = rctx;
	mpz_init_multi(&dctx->generator, &dctx->prime, &dctx->private,
				&dctx->public, NULL);
	mpz_set_ui(dctx->generator, dctx->desc->generator);
	mpz_from_unsigned_bin(dctx->prime, dctx->desc->prime,
				dctx->desc->primelen);
	return dctx;
}

exported void isrcry_dh_free(struct isrcry_dh_ctx *dctx)
{
	mpz_clear_multi(&dctx->generator, &dctx->prime, &dctx->private,
				&dctx->public, NULL);
	g_slice_free(struct isrcry_dh_ctx, dctx);
}

exported enum isrcry_result isrcry_dh_init(struct isrcry_dh_ctx *dctx,
			unsigned entropy_bytes)
{
	char buf[entropy_bytes * 2];

	if (entropy_bytes > dctx->desc->max_entropy)
		return ISRCRY_INVALID_ARGUMENT;
	do {
		isrcry_random_bytes(dctx->rctx, buf, sizeof(buf));
		mpz_from_unsigned_bin(dctx->private, buf, sizeof(buf));
		mpz_powm(dctx->public, dctx->generator, dctx->private,
				dctx->prime);
	} while (mpz_popcount(dctx->public) <= 1);
	return ISRCRY_OK;
}

exported enum isrcry_result isrcry_dh_get_public(struct isrcry_dh_ctx *dctx,
			void *out)
{
	if (!mpz_cmp_ui(dctx->public, 0))
		return ISRCRY_NEED_KEY;
	write_val(dctx, dctx->public, out);
	return ISRCRY_OK;
}

exported enum isrcry_result isrcry_dh_run(struct isrcry_dh_ctx *dctx,
			const void *peerkey, void *out)
{
	mpz_t peer;
	mpz_t shared;
	enum isrcry_result ret = ISRCRY_OK;

	if (!mpz_cmp_ui(dctx->private, 0))
		return ISRCRY_NEED_KEY;
	mpz_init_multi(&peer, &shared, NULL);
	mpz_from_unsigned_bin(peer, peerkey, dctx->desc->primelen);
	if (mpz_popcount(peer) > 1 && mpz_cmp(peer, dctx->prime) < 0) {
		mpz_powm(shared, peer, dctx->private, dctx->prime);
		write_val(dctx, shared, out);
	} else {
		ret = ISRCRY_BAD_FORMAT;
	}
	mpz_clear_multi(&peer, &shared, NULL);
	return ret;
}

exported unsigned isrcry_dh_key_len(enum isrcry_dh type)
{
	const struct isrcry_dh_desc *desc = dh_desc(type);
	if (desc == NULL)
		return 0;
	return desc->primelen;
}
