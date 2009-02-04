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

/* This file is adapted from libtomcrypt, whose license block follows. */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.com
 */

#include <stdlib.h>
#include <stdint.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"
#include "blowfish_tab.h"

static enum isrcry_result blowfish_encrypt(struct isrcry_cipher_ctx *cctx,
			const unsigned char *in, unsigned char *out);

 /**
    Initialize the Blowfish block cipher
    @param cctx The cipher context in which to store the scheduled key
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @return ISRCRY_OK if successful
 */
static enum isrcry_result blowfish_init(struct isrcry_cipher_ctx *cctx,
			const unsigned char *key, int keylen)
{
   struct isrcry_blowfish_key *skey = &cctx->bf;
   uint32_t x, y, z, A;
   unsigned char B[8];

   if (key == NULL || keylen < 8 || keylen > 56)
	   return ISRCRY_INVALID_ARGUMENT;

   /* load in key bytes (Supplied by David Hopwood) */
   for (x = y = 0; x < 18; x++) {
       A = 0;
       for (z = 0; z < 4; z++) {
           A = (A << 8) | ((uint32_t)key[y++] & 255);
           if (y == (uint32_t)keylen) { 
              y = 0; 
           }
       }
       skey->K[x] = ORIG_P[x] ^ A;
   }

   /* copy sboxes */
   for (x = 0; x < 4; x++) {
       for (y = 0; y < 256; y++) {
           skey->S[x][y] = ORIG_S[x][y];
       }
   }

   /* encrypt K array */
   for (x = 0; x < 8; x++) {
       B[x] = 0;
   }
   
   for (x = 0; x < 18; x += 2) {
       /* encrypt it */
       blowfish_encrypt(cctx, B, B);
       /* copy it */
       LOAD32H(skey->K[x], &B[0]);
       LOAD32H(skey->K[x+1], &B[4]);
   }

   /* encrypt S array */
   for (x = 0; x < 4; x++) {
       for (y = 0; y < 256; y += 2) {
          /* encrypt it */
          blowfish_encrypt(cctx, B, B);
          /* copy it */
          LOAD32H(skey->S[x][y], &B[0]);
          LOAD32H(skey->S[x][y+1], &B[4]);
       }
   }

   return ISRCRY_OK;
}

#define F(x) ((skey->S[0][byte(x,3)] + skey->S[1][byte(x,2)]) ^ skey->S[2][byte(x,1)]) + skey->S[3][byte(x,0)]

/**
  Encrypts a block of text with Blowfish
  @param cctx The cipher context
  @param in The input plaintext (8 bytes)
  @param out The output ciphertext (8 bytes)
  @return ISRCRY_OK if successful
*/
static enum isrcry_result blowfish_encrypt(struct isrcry_cipher_ctx *cctx,
			const unsigned char *in, unsigned char *out)
{
   struct isrcry_blowfish_key *skey = &cctx->bf;
   uint32_t L, R;
   int r;

   if (in == NULL || out == NULL)
	   return ISRCRY_INVALID_ARGUMENT;

   /* load it */
   LOAD32H(L, &in[0]);
   LOAD32H(R, &in[4]);

   /* do 16 rounds */
   for (r = 0; r < 16; ) {
      L ^= skey->K[r++];  R ^= F(L);
      R ^= skey->K[r++];  L ^= F(R);
      L ^= skey->K[r++];  R ^= F(L);
      R ^= skey->K[r++];  L ^= F(R);
   }

   /* last keying */
   R ^= skey->K[17];
   L ^= skey->K[16];

   /* store */
   STORE32H(R, &out[0]);
   STORE32H(L, &out[4]);

   return ISRCRY_OK;
}

/**
  Decrypts a block of text with Blowfish
  @param cctx The cipher context
  @param in The input ciphertext (8 bytes)
  @param out The output plaintext (8 bytes)
  @return ISRCRY_OK if successful
*/
static enum isrcry_result blowfish_decrypt(struct isrcry_cipher_ctx *cctx,
			const unsigned char *in, unsigned char *out)
{
   struct isrcry_blowfish_key *skey = &cctx->bf;
   uint32_t L, R;
   int r;

   if (in == NULL || out == NULL)
	   return ISRCRY_INVALID_ARGUMENT;
    
   /* load it */
   LOAD32H(R, &in[0]);
   LOAD32H(L, &in[4]);

   /* undo last keying */
   R ^= skey->K[17];
   L ^= skey->K[16];

   /* do 16 rounds */
   for (r = 15; r > 0; ) {
      L ^= F(R); R ^= skey->K[r--];
      R ^= F(L); L ^= skey->K[r--];
      L ^= F(R); R ^= skey->K[r--];
      R ^= F(L); L ^= skey->K[r--];
   }

   /* store */
   STORE32H(L, &out[0]);
   STORE32H(R, &out[4]);
   return ISRCRY_OK;
}

const struct isrcry_cipher_desc _isrcry_bf_desc = {
	.init = blowfish_init,
	.encrypt = blowfish_encrypt,
	.decrypt = blowfish_decrypt,
	.blocklen = 8
};
