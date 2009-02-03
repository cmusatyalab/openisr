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

enum isrcry_hash {
	ISRCRY_HASH_SHA1		= 0,
	ISRCRY_HASH_MD5			= 1,
};

#define ISRCRY_AES_BLOCKSIZE 16
#define ISRCRY_BLOWFISH_BLOCKSIZE 8

struct isrcry_aes_key {
	uint32_t eK[60], dK[60];
	int Nr;
};

struct isrcry_blowfish_key {
	uint32_t S[4][256];
	uint32_t K[18];
};

struct isrcry_hash_ctx;

#define CIPHER_INIT(alg) \
	enum isrcry_result isrcry_ ## alg ## _init(const unsigned char *key, \
				int keylen, \
				struct isrcry_ ## alg ## _key *skey);

#define CIPHER(alg, mode, direction) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## direction ( \
				const unsigned char *in, unsigned long len, \
				unsigned char *out, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv);
#define ENCRYPT_PAD(alg, mode, pad) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## pad ## \
				_encrypt (const unsigned char *in, \
				unsigned long inlen, unsigned char *out, \
				unsigned long outlen, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv);
#define DECRYPT_PAD(alg, mode, pad) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## pad ## \
				_decrypt (const unsigned char *in, \
				unsigned long inlen, unsigned char *out, \
				unsigned long *outlen, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv);

CIPHER_INIT(aes)
CIPHER_INIT(blowfish)

CIPHER(aes, cbc, encrypt)
CIPHER(aes, cbc, decrypt)
CIPHER(blowfish, cbc, encrypt)
CIPHER(blowfish, cbc, decrypt)

ENCRYPT_PAD(aes, cbc, pkcs5)
DECRYPT_PAD(aes, cbc, pkcs5)
ENCRYPT_PAD(blowfish, cbc, pkcs5)
DECRYPT_PAD(blowfish, cbc, pkcs5)

#undef CIPHER_INIT
#undef CIPHER
#undef ENCRYPT_PAD
#undef DECRYPT_PAD

struct isrcry_hash_ctx *isrcry_hash_alloc(enum isrcry_hash type);
void isrcry_hash_free(struct isrcry_hash_ctx *ctx);
void isrcry_hash_init(struct isrcry_hash_ctx *ctx);
void isrcry_hash_update(struct isrcry_hash_ctx *ctx,
			const unsigned char *buffer, unsigned length);
void isrcry_hash_final(struct isrcry_hash_ctx *ctx, unsigned char *digest);
unsigned isrcry_hash_len(enum isrcry_hash type);

const char *isrcry_strerror(enum isrcry_result result);

#endif
