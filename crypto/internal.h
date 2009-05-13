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
#include <stdarg.h>
#include <gmp.h>
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
	unsigned block_size;
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

struct isrcry_mac_desc {
	void *(*alloc)(struct isrcry_mac_ctx *mctx);
	enum isrcry_result (*init)(struct isrcry_mac_ctx *mctx,
				const unsigned char *key, unsigned keylen);
	void (*update)(struct isrcry_mac_ctx *mctx,
				const unsigned char *buffer, unsigned length);
	enum isrcry_result (*final)(struct isrcry_mac_ctx *mctx,
				unsigned char *out, unsigned outlen);
	void (*free)(struct isrcry_mac_ctx *mctx);
	enum isrcry_hash hash;
	unsigned mac_size;
};

extern const struct isrcry_mac_desc _isrcry_hmac_sha1_desc;

struct isrcry_mac_ctx {
	const struct isrcry_mac_desc *desc;
	void *ctx;
};

struct isrcry_sign_desc {
	enum isrcry_result (*make_keys)(struct isrcry_sign_ctx *sctx,
				unsigned length);
	enum isrcry_result (*get_key)(struct isrcry_sign_ctx *sctx,
				enum isrcry_key_type type,
				enum isrcry_key_format format,
				unsigned char *out, unsigned *outlen);
	enum isrcry_result (*set_key)(struct isrcry_sign_ctx *sctx,
				enum isrcry_key_type type,
				enum isrcry_key_format format,
				const unsigned char *key, unsigned keylen);
	enum isrcry_result (*sign)(struct isrcry_sign_ctx *sctx,
				unsigned char *out, unsigned *outlen);
	enum isrcry_result (*verify)(struct isrcry_sign_ctx *sctx,
				const unsigned char *sig, unsigned siglen);
	void (*free)(struct isrcry_sign_ctx *sctx);
	enum isrcry_hash hash;
	unsigned saltlen;
};

extern const struct isrcry_sign_desc _isrcry_rsa_pss_sha1_desc;

struct isrcry_sign_ctx {
	const struct isrcry_sign_desc *desc;
	struct isrcry_hash_ctx *hctx;
	struct isrcry_random_ctx *rctx;
	void *pubkey;
	void *privkey;
	void *salt;
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

int mp_init(void **a);
void mp_clear(void *a);
int mp_init_multi(void **a, ...);
void mp_clear_multi(void *a, ...);
void mp_copy(void *a, void *b);
void mp_set_int(void *a, unsigned long b);
int mp_cmp(void *a, void *b);
int mp_cmp_d(void *a, unsigned long b);
int mp_count_bits(void *a);
int mp_cnt_lsb(void *a);
void mp_2expt(void *a, int n);
unsigned long mp_unsigned_bin_size(void *a);
void mp_to_unsigned_bin(void *a, unsigned char *b);
void mp_read_unsigned_bin(void *a, unsigned char *b, unsigned long len);
void mp_add(void *a, void *b, void *c);
void mp_sub(void *a, void *b, void *c);
void mp_sub_d(void *a, unsigned long b, void *c);
void mp_mul(void *a, void *b, void *c);
void mp_div(void *a, void *b, void *c, void *d);
void mp_mod(void *a, void *b, void *c);
void mp_gcd(void *a, void *b, void *c);
void mp_lcm(void *a, void *b, void *c);
void mp_mulmod(void *a, void *b, void *c, void *d);
int mp_invmod(void *a, void *b, void *c);
void mp_exptmod(void *a, void *b, void *c, void *d);
void mp_prime_is_prime(void *a, int rounds, int *b);
int rand_prime(void *N, unsigned len, struct isrcry_random_ctx *rctx);

static inline void mpz_init_multi(mpz_t *a, ...)
{
	mpz_t *cur = a;
	va_list args;

	va_start(args, a);
	while (cur != NULL) {
		mpz_init(*cur);
		cur = va_arg(args, mpz_t *);
	}
	va_end(args);
}

static inline void mpz_clear_multi(mpz_t *a, ...)
{
	mpz_t *cur = a;
	va_list args;

	va_start(args, a);
	while (cur != NULL) {
		mpz_clear(*cur);
		cur = va_arg(args, mpz_t *);
	}
	va_end(args);
}

static inline unsigned mpz_unsigned_bin_size(mpz_t a)
{
	unsigned t;

	if (mpz_cmp_ui(a, 0) == 0)
		return 0;
	t = mpz_sizeinbase(a, 2);
	return (t >> 3) + ((t & 7) ? 1 : 0);
}

static inline void mpz_to_unsigned_bin(void *dst, mpz_t src)
{
	mpz_export(dst, NULL, 1, 1, 1, 0, src);
}

static inline void mpz_from_unsigned_bin(mpz_t dst, const void *src, unsigned len)
{
	mpz_import(dst, len, 1, 1, 1, 0, src);
}

#endif
