/*
 * sha1 - optimized SHA1 hash algorithm for CryptoAPI
 *
 * Originally from Nettle
 * Ported to CryptoAPI by Benjamin Gilbert <bgilbert@cs.cmu.edu>
 *
 * Copyright (C) 2001 Peter Gutmann, Andrew Kuchling, Niels Möller
 * Copyright (C) 2006-2007 Carnegie Mellon University
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

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/crypto.h>

#ifdef CONFIG_X86_64
#define DRIVER_NAME "sha1-x86_64"
#else
#define DRIVER_NAME "sha1-i586"
#endif

#define SHA1_DIGEST_SIZE 20
#define SHA1_DATA_SIZE 64

struct sha1_ctx {
	u32 digest[SHA1_DIGEST_SIZE / 4];	/* Message digest */
	u64 count;				/* Blocks processed */
	u8 block[SHA1_DATA_SIZE];		/* SHA1 data buffer */
	unsigned int index;			/* index into buffer */
};

/* Compression function. @state points to 5 u32 words, and @data points to
   64 bytes of input data, possibly unaligned. */
asmlinkage void sha1_compress(u32 *state, const u8 *data);

/* Writes a 32-bit integer to an arbitrary pointer in big-endian byte order */
static inline void write_u32_be(void *ptr, u32 i)
{
	u32 *p=ptr;
	*p=cpu_to_be32(i);
}

static void sha1_init(struct crypto_tfm *tfm)
{
	struct sha1_ctx *ctx = crypto_tfm_ctx(tfm);
	
	/* Set the h-vars to their initial values */
	ctx->digest[0] = 0x67452301L;
	ctx->digest[1] = 0xEFCDAB89L;
	ctx->digest[2] = 0x98BADCFEL;
	ctx->digest[3] = 0x10325476L;
	ctx->digest[4] = 0xC3D2E1F0L;
	
	/* Initialize block count */
	ctx->count = 0;
	
	/* Initialize buffer */
	ctx->index = 0;
}

static void sha1_update(struct crypto_tfm *tfm, const u8 *buffer,
			unsigned length)
{
	struct sha1_ctx *ctx = crypto_tfm_ctx(tfm);
	if (ctx->index) {
		/* Try to fill partial block */
		unsigned left = SHA1_DATA_SIZE - ctx->index;
		if (length < left) {
			memcpy(ctx->block + ctx->index, buffer, length);
			ctx->index += length;
			return;	/* Finished */
		} else {
			memcpy(ctx->block + ctx->index, buffer, left);
			sha1_compress(ctx->digest, ctx->block);
			ctx->count++;
			buffer += left;
			length -= left;
		}
	}
	while (length >= SHA1_DATA_SIZE) {
		sha1_compress(ctx->digest, buffer);
		ctx->count++;
		buffer += SHA1_DATA_SIZE;
		length -= SHA1_DATA_SIZE;
	}
	if ((ctx->index = length))
		/* Buffer leftovers */
		memcpy(ctx->block, buffer, length);
}

/* Final wrapup - pad to SHA1_DATA_SIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */
static void sha1_final(struct crypto_tfm *tfm, u8 *digest)
{
	struct sha1_ctx *ctx = crypto_tfm_ctx(tfm);
	u64 bitcount;
	unsigned i = ctx->index;
	
	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	BUG_ON(i >= SHA1_DATA_SIZE);
	ctx->block[i++] = 0x80;
	
	if (i > (SHA1_DATA_SIZE - 8)) {
		/* No room for length in this block. Process it and
		   pad with another one */
		memset(ctx->block + i, 0, SHA1_DATA_SIZE - i);
		sha1_compress(ctx->digest, ctx->block);
		i = 0;
	}
	if (i < (SHA1_DATA_SIZE - 8))
		memset(ctx->block + i, 0, (SHA1_DATA_SIZE - 8) - i);
	
	/* There are 512 = 2^9 bits in one block */
	bitcount = (ctx->count << 9) | (ctx->index << 3);
	
	/* This is slightly inefficient, as the numbers are converted to
	   big-endian format, and will be converted back by the compression
	   function. It's probably not worth the effort to fix this. */
	write_u32_be(ctx->block + (SHA1_DATA_SIZE - 8), bitcount >> 32);
	write_u32_be(ctx->block + (SHA1_DATA_SIZE - 4), bitcount);
	
	sha1_compress(ctx->digest, ctx->block);
	
	for (i = 0; i < SHA1_DIGEST_SIZE / 4; i++, digest += 4)
		write_u32_be(digest, ctx->digest[i]);
	
	/* Wipe context */
	memset(ctx, 0, sizeof(*ctx));
}

static struct crypto_alg alg = {
	.cra_name	=	"sha1",
	.cra_driver_name=	DRIVER_NAME,
	.cra_priority	=	200,
	.cra_flags	=	CRYPTO_ALG_TYPE_DIGEST,
	.cra_blocksize	=	SHA1_DATA_SIZE,
	.cra_ctxsize	=	sizeof(struct sha1_ctx),
	.cra_module	=	THIS_MODULE,
	.cra_alignmask	=	3,
	.cra_list	=	LIST_HEAD_INIT(alg.cra_list),
	.cra_u		=	{ .digest = {
	.dia_digestsize	=	SHA1_DIGEST_SIZE,
	.dia_init	=	sha1_init,
	.dia_update	=	sha1_update,
	.dia_final	=	sha1_final } }
};

static int __init init(void)
{
	return crypto_register_alg(&alg);
}

static void __exit fini(void)
{
	crypto_unregister_alg(&alg);
}

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("x86-optimized SHA1 hash algorithm");
