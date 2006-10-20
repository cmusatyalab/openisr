/* sha1.c
 *
 * The sha1 hash function.
 * Defined by http://www.itl.nist.gov/fipspubs/fip180-1.htm.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Peter Gutmann, Andrew Kuchling, Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/crypto.h>

/* Writes a 32-bit integer, in network, big-endian, byte order */
/* XXX can we replace this with an existing function? */
static inline void write_uint32(char *p, u32 i)
{
	(p)[0] = ((i) >> 24) & 0xff;
	(p)[1] = ((i) >> 16) & 0xff;
	(p)[2] = ((i) >> 8) & 0xff;
	(p)[3] = (i) & 0xff;
}

#define SHA1_DIGEST_SIZE 20
#define SHA1_DATA_SIZE 64

struct sha1_ctx {
	u32 digest[SHA1_DIGEST_SIZE / 4];	/* Message digest */
	u64 count;				/* Blocks processed */
	u8 block[SHA1_DATA_SIZE];		/* SHA1 data buffer */
	unsigned int index;			/* index into buffer */
};

/* Compression function, written in assembly. STATE points to 5 u32 words,
   and DATA points to 64 bytes of input data, possibly unaligned. */
void sha1_compress(u32 * state, const u8 * data);

/* Initialize the SHA values */

static void sha1_init(void *data)
{
	struct sha1_ctx *ctx = data;
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

static void sha1_update(void *data, const u8 * buffer, unsigned length)
{
	struct sha1_ctx *ctx = data;
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
	if ((ctx->index = length))  /* This assignment is intended */
		/* Buffer leftovers */
		memcpy(ctx->block, buffer, length);
}

/* Final wrapup - pad to SHA1_DATA_SIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */
static void sha1_final(void *data, u8 * digest)
{
	struct sha1_ctx *ctx = data;
	u64 bitcount;
	unsigned i;
	
	i = ctx->index;
	
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
	write_uint32(ctx->block + (SHA1_DATA_SIZE - 8), bitcount >> 32);
	write_uint32(ctx->block + (SHA1_DATA_SIZE - 4), bitcount);
	
	sha1_compress(ctx->digest, ctx->block);
	
	for (i = 0; i < SHA1_DIGEST_SIZE / 4; i++, digest += 4)
		write_uint32(digest, ctx->digest[i]);
	
	/* Wipe context */
	memset(ctx, 0, sizeof(*ctx));
}

static struct crypto_alg alg = {
	.cra_name	=	"sha1",
	.cra_driver_name=	"sha1-i386",
	.cra_priority	=	200,
	.cra_flags	=	CRYPTO_ALG_TYPE_DIGEST,
	.cra_blocksize	=	SHA1_DATA_SIZE,
	.cra_ctxsize	=	sizeof(struct sha1_ctx),
	.cra_module	=	THIS_MODULE,
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
