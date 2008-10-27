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

#include "tomcrypt.h"
#include "blowfish_tab.h"

 /**
    Initialize the Blowfish block cipher
    @param key The symmetric key you wish to pass
    @param keylen The key length in bytes
    @param skey The key in as scheduled by this function.
    @return CRYPT_OK if successful
 */
int isrcry_blowfish_init(const unsigned char *key, int keylen,
                   struct isrcry_blowfish_key *skey)
{
   ulong32 x, y, z, A;
   unsigned char B[8];

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(skey != NULL);

   /* check key length */
   if (keylen < 8 || keylen > 56) {
      return CRYPT_INVALID_KEYSIZE;
   }

   /* load in key bytes (Supplied by David Hopwood) */
   for (x = y = 0; x < 18; x++) {
       A = 0;
       for (z = 0; z < 4; z++) {
           A = (A << 8) | ((ulong32)key[y++] & 255);
           if (y == (ulong32)keylen) { 
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
       blowfish_ecb_encrypt(B, B, skey);
       /* copy it */
       LOAD32H(skey->K[x], &B[0]);
       LOAD32H(skey->K[x+1], &B[4]);
   }

   /* encrypt S array */
   for (x = 0; x < 4; x++) {
       for (y = 0; y < 256; y += 2) {
          /* encrypt it */
          blowfish_ecb_encrypt(B, B, skey);
          /* copy it */
          LOAD32H(skey->S[x][y], &B[0]);
          LOAD32H(skey->S[x][y+1], &B[4]);
       }
   }

#ifdef LTC_CLEAN_STACK
   zeromem(B, sizeof(B));
#endif

   return CRYPT_OK;
}

#define F(x) ((skey->S[0][byte(x,3)] + skey->S[1][byte(x,2)]) ^ skey->S[2][byte(x,1)]) + skey->S[3][byte(x,0)]

/**
  Encrypts a block of text with Blowfish
  @param pt The input plaintext (8 bytes)
  @param ct The output ciphertext (8 bytes)
  @param skey The key as scheduled
  @return CRYPT_OK if successful
*/
int _isrcry_blowfish_encrypt(const unsigned char *pt, unsigned char *ct,
			struct isrcry_blowfish_key *skey)
{
   ulong32 L, R;
   int r;

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);

   /* load it */
   LOAD32H(L, &pt[0]);
   LOAD32H(R, &pt[4]);

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
   STORE32H(R, &ct[0]);
   STORE32H(L, &ct[4]);

   return CRYPT_OK;
}

#if 0
int blowfish_ecb_encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    int err = _blowfish_ecb_encrypt(pt, ct, skey);
    burn_stack(sizeof(ulong32) * 2 + sizeof(int));
    return err;
}
#endif

/**
  Decrypts a block of text with Blowfish
  @param ct The input ciphertext (8 bytes)
  @param pt The output plaintext (8 bytes)
  @param skey The key as scheduled 
  @return CRYPT_OK if successful
*/
int _isrcry_blowfish_decrypt(const unsigned char *ct, unsigned char *pt,
			struct isrcry_blowfish_key *skey)
{
   ulong32 L, R;
   int r;

    LTC_ARGCHK(pt   != NULL);
    LTC_ARGCHK(ct   != NULL);
    LTC_ARGCHK(skey != NULL);
    
   /* load it */
   LOAD32H(R, &ct[0]);
   LOAD32H(L, &ct[4]);

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
   STORE32H(L, &pt[0]);
   STORE32H(R, &pt[4]);
   return CRYPT_OK;
}

#if 0
int blowfish_ecb_decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    int err = _blowfish_ecb_decrypt(ct, pt, skey);
    burn_stack(sizeof(ulong32) * 2 + sizeof(int));
    return err;
}
#endif