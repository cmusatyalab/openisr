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

#ifndef LIBISRCRYPTO_DEFS_H
#define LIBISRCRYPTO_DEFS_H

#ifndef LIBISRCRYPTO_INTERNAL
#error This header is for internal use by libisrcrypto
#endif

#include <string.h>
#include "config.h"

#ifdef HAVE_VISIBILITY
#define exported __attribute__ ((visibility ("default")))
#else
#define exported
#endif

#define MAX_BLOCK_LEN 16

struct isrcry_cipher_desc {
	enum isrcry_result (*init)(struct isrcry_cipher_ctx *cctx,
				const unsigned char *key, int keylen);
	enum isrcry_result (*encrypt)(struct isrcry_cipher_ctx *cctx,
				const unsigned char *in,
				unsigned char *out);
	enum isrcry_result (*decrypt)(struct isrcry_cipher_ctx *cctx,
				const unsigned char *in,
				unsigned char *out);
	unsigned blocklen;
	unsigned ctxlen;
};

extern const struct isrcry_cipher_desc _isrcry_aes_desc;
extern const struct isrcry_cipher_desc _isrcry_bf_desc;

struct isrcry_mode_desc {
	enum isrcry_result (*encrypt)(struct isrcry_cipher_ctx *cctx,
				const unsigned char *in, unsigned long len,
				unsigned char *out);
	enum isrcry_result (*decrypt)(struct isrcry_cipher_ctx *cctx,
				const unsigned char *in, unsigned long len,
				unsigned char *out);
};

extern const struct isrcry_mode_desc _isrcry_ecb_desc;
extern const struct isrcry_mode_desc _isrcry_cbc_desc;

struct isrcry_pad_desc {
	enum isrcry_result (*pad)(unsigned char *buf, unsigned blocklen,
			unsigned datalen);
	enum isrcry_result (*unpad)(unsigned char *buf, unsigned blocklen,
			unsigned *datalen);
};

extern const struct isrcry_pad_desc _isrcry_pkcs5_desc;

struct isrcry_cipher_ctx {
	const struct isrcry_cipher_desc *cipher;
	const struct isrcry_mode_desc *mode;
	void *key;
	unsigned char iv[MAX_BLOCK_LEN];
	enum isrcry_direction direction;
};

struct isrcry_hash_desc {
	void (*init)(struct isrcry_hash_ctx *hctx);
	void (*update)(struct isrcry_hash_ctx *hctx,
				const unsigned char *buffer, unsigned length);
	void (*final)(struct isrcry_hash_ctx *ctx, unsigned char *digest);
	unsigned digest_size;
	unsigned ctxlen;
};

struct isrcry_hash_ctx {
	const struct isrcry_hash_desc *desc;
	void *ctx;
};

extern const struct isrcry_hash_desc _isrcry_sha1_desc;
extern const struct isrcry_hash_desc _isrcry_md5_desc;

struct isrcry_random_ctx {
	struct isrcry_cipher_ctx *aes;
	uint8_t pool[16];
	uint8_t last[16];
	uint32_t counter;
};

/* The helper macros below are originally from libtomcrypt. */

/* Extract a byte portably */
#define byte(x, n) (((x) >> (8 * (n))) & 255)

#if defined(HAVE_X86_32) || defined(HAVE_X86_64)
#define ISRCRY_FAST_TYPE unsigned long
#define STORE32H(x, y)           \
asm __volatile__ (               \
   "bswapl %0     \n\t"          \
   "movl   %0,(%1)\n\t"          \
   "bswapl %0     \n\t"          \
      ::"r"(x), "r"(y));

#define LOAD32H(x, y)          \
asm __volatile__ (             \
   "movl (%1),%0\n\t"          \
   "bswapl %0\n\t"             \
   :"=r"(x): "r"(y));

#define STORE32L(x, y) \
	{ uint32_t __t = (x); memcpy((y), &__t, 4); }

#define LOAD32L(x, y) \
	memcpy(&(x), (y), 4)
#else
#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
           ((unsigned long)((y)[1] & 255)<<16) | \
           ((unsigned long)((y)[2] & 255)<<8)  | \
           ((unsigned long)((y)[3] & 255)); }

#define STORE32L(x, y)                                                                     \
     { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((unsigned long)((y)[3] & 255)<<24) | \
           ((unsigned long)((y)[2] & 255)<<16) | \
           ((unsigned long)((y)[1] & 255)<<8)  | \
           ((unsigned long)((y)[0] & 255)); }
#endif

#endif
