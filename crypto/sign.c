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

#include <stdlib.h>
#include <glib.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

static const struct isrcry_sign_desc *sign_desc(enum isrcry_sign type)
{
	switch (type) {
	case ISRCRY_SIGN_RSA_PSS_SHA1:
		return &_isrcry_rsa_pss_sha1_desc;
	}
	return NULL;
}

static int key_type_ok(enum isrcry_key_type type)
{
	switch (type) {
	case ISRCRY_KEY_PUBLIC:
	case ISRCRY_KEY_PRIVATE:
		return 1;
	}
	return 0;
}

static int key_format_ok(enum isrcry_key_format fmt)
{
	switch (fmt) {
	case ISRCRY_KEY_FORMAT_RAW:
		return 1;
	}
	return 0;
}

exported struct isrcry_sign_ctx *isrcry_sign_alloc(enum isrcry_sign type,
			struct isrcry_random_ctx *rctx)
{
	struct isrcry_sign_ctx *sctx;

	sctx = g_slice_new0(struct isrcry_sign_ctx);
	sctx->desc = sign_desc(type);
	if (sctx->desc == NULL) {
		g_slice_free(struct isrcry_sign_ctx, sctx);
		return NULL;
	}
	sctx->hctx = isrcry_hash_alloc(sctx->desc->hash);
	if (sctx->hctx == NULL) {
		g_slice_free(struct isrcry_sign_ctx, sctx);
		return NULL;
	}
	sctx->rctx = rctx;
	return sctx;
}

exported void isrcry_sign_free(struct isrcry_sign_ctx *sctx)
{
	sctx->desc->free(sctx);
	isrcry_hash_free(sctx->hctx);
	g_free(sctx->salt);
	g_slice_free(struct isrcry_sign_ctx, sctx);
}

exported enum isrcry_result isrcry_sign_make_keys(struct isrcry_sign_ctx *sctx,
			unsigned length)
{
	return sctx->desc->make_keys(sctx, length);
}

exported enum isrcry_result isrcry_sign_get_key(struct isrcry_sign_ctx *sctx,
			enum isrcry_key_type type, enum isrcry_key_format fmt,
			void *out, unsigned *outlen)
{
	if (!key_type_ok(type) || !key_format_ok(fmt))
		return ISRCRY_INVALID_ARGUMENT;
	return sctx->desc->get_key(sctx, type, fmt, out, outlen);
}

exported enum isrcry_result isrcry_sign_set_key(struct isrcry_sign_ctx *sctx,
			enum isrcry_key_type type, enum isrcry_key_format fmt,
			const void *key, unsigned keylen)
{
	if (!key_type_ok(type) || !key_format_ok(fmt))
		return ISRCRY_INVALID_ARGUMENT;
	return sctx->desc->set_key(sctx, type, fmt, key, keylen);
}

exported enum isrcry_result isrcry_sign_set_salt(struct isrcry_sign_ctx *sctx,
			const void *salt, unsigned saltlen)
{
	void *copy;

	if (salt == NULL) {
		g_free(sctx->salt);
		sctx->salt = NULL;
		return ISRCRY_OK;
	}
	if (saltlen != sctx->desc->saltlen)
		return ISRCRY_INVALID_ARGUMENT;
	copy = g_memdup(salt, saltlen);
	if (sctx->salt != NULL)
		g_free(sctx->salt);
	sctx->salt = copy;
	return ISRCRY_OK;
}

exported void isrcry_sign_update(struct isrcry_sign_ctx *sctx,
			const void *data, unsigned datalen)
{
	isrcry_hash_update(sctx->hctx, data, datalen);
}

exported enum isrcry_result isrcry_sign_sign(struct isrcry_sign_ctx *sctx,
			void *out, unsigned *outlen)
{
	return sctx->desc->sign(sctx, out, outlen);
}

exported enum isrcry_result isrcry_sign_verify(struct isrcry_sign_ctx *sctx,
			const void *sig, unsigned siglen)
{
	return sctx->desc->verify(sctx, sig, siglen);
}
