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

#ifndef LIBISRCRYPTO_H
#define LIBISRCRYPTO_H

#include <stdint.h>

enum isrcry_result {
	ISRCRY_OK			= 0,
	ISRCRY_INVALID_ARGUMENT		= 1,
	ISRCRY_BAD_PADDING		= 2,
};

enum isrcry_direction {
	ISRCRY_DECRYPT			= 0,
	ISRCRY_ENCRYPT			= 1
};

enum isrcry_cipher {
	ISRCRY_CIPHER_AES		= 0,
	ISRCRY_CIPHER_BLOWFISH		= 1,
};

enum isrcry_mode {
	ISRCRY_MODE_ECB			= 0,
	ISRCRY_MODE_CBC			= 1,
};

enum isrcry_padding {
	ISRCRY_PADDING_PKCS5		= 0,
};

enum isrcry_hash {
	ISRCRY_HASH_SHA1		= 0,
	ISRCRY_HASH_MD5			= 1,
};

struct isrcry_cipher_ctx;
struct isrcry_hash_ctx;


struct isrcry_cipher_ctx *isrcry_cipher_alloc(enum isrcry_cipher cipher,
			enum isrcry_mode mode);
void isrcry_cipher_free(struct isrcry_cipher_ctx *cctx);
enum isrcry_result isrcry_cipher_init(struct isrcry_cipher_ctx *cctx,
			enum isrcry_direction direction,
			const unsigned char *key, int keylen,
			const unsigned char *iv);
enum isrcry_result isrcry_cipher_process(struct isrcry_cipher_ctx *cctx,
			const unsigned char *in, unsigned long inlen,
			unsigned char *out);
enum isrcry_result isrcry_cipher_final(struct isrcry_cipher_ctx *cctx,
			enum isrcry_padding padding,
			const unsigned char *in, unsigned long inlen,
			unsigned char *out, unsigned long *outlen);
unsigned isrcry_cipher_block(enum isrcry_cipher type);

struct isrcry_hash_ctx *isrcry_hash_alloc(enum isrcry_hash type);
void isrcry_hash_free(struct isrcry_hash_ctx *ctx);
void isrcry_hash_update(struct isrcry_hash_ctx *ctx,
			const unsigned char *buffer, unsigned length);
void isrcry_hash_final(struct isrcry_hash_ctx *ctx, unsigned char *digest);
unsigned isrcry_hash_len(enum isrcry_hash type);

const char *isrcry_strerror(enum isrcry_result result);

#endif
