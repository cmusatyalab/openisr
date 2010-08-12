/*
 * libisrutil - utility library for the OpenISR (R) system
 *
 * Copyright (C) 2006-2010 Carnegie Mellon University
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <string.h>
#include "isrcrypto.h"
#define LIBISRUTIL_INTERNAL
#include "internal.h"

/* Crypto */

exported enum iu_chunk_crypto iu_chunk_crypto_parse(const char *desc)
{
	if (!strcmp(desc, "aes-sha1"))
		return IU_CHUNK_CRY_AES_SHA1;
	return IU_CHUNK_CRY_UNKNOWN;
}

static gboolean crypto_get_algs(enum iu_chunk_crypto crypto,
			enum isrcry_cipher *_cipher, enum isrcry_mode *_mode,
			enum isrcry_padding *_padding, enum isrcry_hash *_hash)
{
	enum isrcry_cipher cipher;
	enum isrcry_mode mode;
	enum isrcry_padding padding;
	enum isrcry_hash hash;

	switch (crypto) {
	case IU_CHUNK_CRY_AES_SHA1:
		cipher = ISRCRY_CIPHER_AES;
		mode = ISRCRY_MODE_CBC;
		padding = ISRCRY_PADDING_PKCS5;
		hash = ISRCRY_HASH_SHA1;
		break;
	default:
		return FALSE;
	}
	if (_cipher)
		*_cipher = cipher;
	if (_mode)
		*_mode = mode;
	if (_padding)
		*_padding = padding;
	if (_hash)
		*_hash = hash;
	return TRUE;
}

exported gboolean iu_chunk_crypto_is_valid(enum iu_chunk_crypto type)
{
	return crypto_get_algs(type, NULL, NULL, NULL, NULL);
}

exported unsigned iu_chunk_crypto_hashlen(enum iu_chunk_crypto type)
{
	enum isrcry_hash alg;

	if (!crypto_get_algs(type, NULL, NULL, NULL, &alg))
		return 0;
	return isrcry_hash_len(alg);
}

exported gboolean iu_chunk_crypto_digest(enum iu_chunk_crypto crypto,
			void *out, const void *in, unsigned len)
{
	struct isrcry_hash_ctx *ctx;
	enum isrcry_hash alg;

	if (!crypto_get_algs(crypto, NULL, NULL, NULL, &alg)) {
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
					"Invalid crypto suite requested");
		return FALSE;
	}
	ctx = isrcry_hash_alloc(alg);
	if (ctx == NULL) {
		g_log(G_LOG_DOMAIN, G_LOG_LEVEL_CRITICAL,
					"Couldn't allocate digest context");
		return FALSE;
	}
	isrcry_hash_update(ctx, in, len);
	isrcry_hash_final(ctx, out);
	isrcry_hash_free(ctx);
	return TRUE;
}

/* Compress */

exported enum iu_chunk_compress iu_chunk_compress_parse(const char *desc)
{
	if (!strcmp(desc, "none"))
		return IU_CHUNK_COMP_NONE;
	if (!strcmp(desc, "zlib"))
		return IU_CHUNK_COMP_ZLIB;
	if (!strcmp(desc, "lzf"))
		return IU_CHUNK_COMP_LZF;
	return IU_CHUNK_COMP_UNKNOWN;
}

exported gboolean iu_chunk_compress_is_enabled(unsigned enabled_map,
			enum iu_chunk_compress type)
{
	if (type <= IU_CHUNK_COMP_UNKNOWN || type >= 8 * sizeof(enabled_map))
		return FALSE;
	return !!(enabled_map & (1 << type));
}
