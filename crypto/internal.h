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

enum {
 LTC_ASN1_EOL,
 LTC_ASN1_INTEGER,
 LTC_ASN1_SHORT_INTEGER,
 LTC_ASN1_BIT_STRING,
 LTC_ASN1_OCTET_STRING,
 LTC_ASN1_NULL,
 LTC_ASN1_OBJECT_IDENTIFIER,
 LTC_ASN1_SEQUENCE,
};

/** A LTC ASN.1 list type */
typedef struct ltc_asn1_list_ {
   /** The LTC ASN.1 enumerated type identifier */
   int           type;
   /** The data to encode or place for decoding */
   void         *data;
   /** The size of the input or resulting output */
   unsigned long size;
   /** The used flag, this is used by the CHOICE ASN.1 type to indicate which choice was made */
   int           used;
   /** prev/next entry in the list */
   struct ltc_asn1_list_ *prev, *next, *child, *parent;
} ltc_asn1_list;

#define LTC_SET_ASN1(list, index, Type, Data, Size)  \
   do {                                              \
      int LTC_MACRO_temp            = (index);       \
      ltc_asn1_list *LTC_MACRO_list = (list);        \
      LTC_MACRO_list[LTC_MACRO_temp].type = (Type);  \
      LTC_MACRO_list[LTC_MACRO_temp].data = (void*)(Data);  \
      LTC_MACRO_list[LTC_MACRO_temp].size = (Size);  \
      LTC_MACRO_list[LTC_MACRO_temp].used = 0;       \
   } while (0);

enum isrcry_result der_encode_sequence(ltc_asn1_list *list, unsigned long inlen,
                           unsigned char *out,  unsigned long *outlen);
enum isrcry_result der_decode_sequence(const unsigned char *in, unsigned long  inlen,
                           ltc_asn1_list *list,     unsigned long  outlen);

/* VA list handy helpers with triplets of <type, size, data> */
enum isrcry_result der_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...);
enum isrcry_result der_decode_sequence_multi(const unsigned char *in, unsigned long inlen, ...);

#endif
