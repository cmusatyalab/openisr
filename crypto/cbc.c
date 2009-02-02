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

/**
   Initialize a CBC context
   @param cipher      The index of the cipher desired
   @param IV          The initial vector
   @param key         The secret key 
   @param keylen      The length of the secret key (octets)
   @param num_rounds  Number of rounds in the cipher desired (0 for default)
   @param cbc         The CBC state to initialize
   @return CRYPT_OK if successful
*/
int cbc_start(int cipher, const unsigned char *IV, const unsigned char *key, 
              int keylen, int num_rounds, symmetric_CBC *cbc)
{
   int x, err;
 
   LTC_ARGCHK(IV != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(cbc != NULL);

   /* bad param? */
   if ((err = cipher_is_valid(cipher)) != CRYPT_OK) {
      return err;
   }

   /* setup cipher */
   if ((err = cipher_descriptor[cipher].setup(key, keylen, num_rounds, &cbc->key)) != CRYPT_OK) {
      return err;
   }

   /* copy IV */
   cbc->blocklen = cipher_descriptor[cipher].block_length;
   cbc->cipher   = cipher;
   for (x = 0; x < cbc->blocklen; x++) {
       cbc->IV[x] = IV[x];
   }
   return CRYPT_OK;
}

/** Terminate the chain
  @param cbc    The CBC chain to terminate
  @return CRYPT_OK on success
*/
int cbc_done(symmetric_CBC *cbc)
{
   int err;
   LTC_ARGCHK(cbc != NULL);

   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK) {
      return err;
   }
   cipher_descriptor[cbc->cipher].done(&cbc->key);
   return CRYPT_OK;
}

/**
  CBC encrypt
  @param pt     Plaintext
  @param ct     [out] Ciphertext
  @param len    The number of bytes to process (must be multiple of block length)
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
int cbc_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;

   LTC_ARGCHK(pt != NULL);
   LTC_ARGCHK(ct != NULL);
   LTC_ARGCHK(cbc != NULL);

   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK) {
       return err;
   }
   
   /* is blocklen valid? */
   if (cbc->blocklen < 1 || cbc->blocklen > (int)sizeof(cbc->IV)) {
      return CRYPT_INVALID_ARG;
   }    

   if (len % cbc->blocklen) {
      return CRYPT_INVALID_ARG;
   }
#ifdef LTC_FAST
   if (cbc->blocklen % sizeof(LTC_FAST_TYPE)) {   
      return CRYPT_INVALID_ARG;
   }
#endif

   if (cipher_descriptor[cbc->cipher].accel_cbc_encrypt != NULL) {
      return cipher_descriptor[cbc->cipher].accel_cbc_encrypt(pt, ct, len / cbc->blocklen, cbc->IV, &cbc->key);
   } else {
      while (len) {
         /* xor IV against plaintext */
         #if defined(LTC_FAST)
        for (x = 0; x < cbc->blocklen; x += sizeof(LTC_FAST_TYPE)) {
            *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) ^= *((LTC_FAST_TYPE*)((unsigned char *)pt + x));
        }
    #else 
            for (x = 0; x < cbc->blocklen; x++) {
               cbc->IV[x] ^= pt[x];
            }
    #endif

         /* encrypt */
         if ((err = cipher_descriptor[cbc->cipher].ecb_encrypt(cbc->IV, ct, &cbc->key)) != CRYPT_OK) {
            return err;
         }

        /* store IV [ciphertext] for a future block */
         #if defined(LTC_FAST)
        for (x = 0; x < cbc->blocklen; x += sizeof(LTC_FAST_TYPE)) {
            *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) = *((LTC_FAST_TYPE*)((unsigned char *)ct + x));
        }
    #else 
             for (x = 0; x < cbc->blocklen; x++) {
                cbc->IV[x] = ct[x];
             }
    #endif
        
        ct  += cbc->blocklen;
        pt  += cbc->blocklen;
        len -= cbc->blocklen;
     }
   }
   return CRYPT_OK;
}

/**
  CBC decrypt
  @param ct     Ciphertext
  @param pt     [out] Plaintext
  @param len    The number of bytes to process (must be multiple of block length)
  @param cbc    CBC state
  @return CRYPT_OK if successful
*/
int cbc_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long len, symmetric_CBC *cbc)
{
   int x, err;
   unsigned char tmp[16];
#ifdef LTC_FAST
   LTC_FAST_TYPE tmpy;
#else
   unsigned char tmpy;
#endif         

   LTC_ARGCHK(pt  != NULL);
   LTC_ARGCHK(ct  != NULL);
   LTC_ARGCHK(cbc != NULL);

   if ((err = cipher_is_valid(cbc->cipher)) != CRYPT_OK) {
       return err;
   }
   
   /* is blocklen valid? */
   if (cbc->blocklen < 1 || cbc->blocklen > (int)sizeof(cbc->IV)) {
      return CRYPT_INVALID_ARG;
   }    

   if (len % cbc->blocklen) {
      return CRYPT_INVALID_ARG;
   }
#ifdef LTC_FAST
   if (cbc->blocklen % sizeof(LTC_FAST_TYPE)) {   
      return CRYPT_INVALID_ARG;
   }
#endif
   
   if (cipher_descriptor[cbc->cipher].accel_cbc_decrypt != NULL) {
      return cipher_descriptor[cbc->cipher].accel_cbc_decrypt(ct, pt, len / cbc->blocklen, cbc->IV, &cbc->key);
   } else {
      while (len) {
         /* decrypt */
         if ((err = cipher_descriptor[cbc->cipher].ecb_decrypt(ct, tmp, &cbc->key)) != CRYPT_OK) {
            return err;
         }

         /* xor IV against plaintext */
         #if defined(LTC_FAST)
        for (x = 0; x < cbc->blocklen; x += sizeof(LTC_FAST_TYPE)) {
            tmpy = *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) ^ *((LTC_FAST_TYPE*)((unsigned char *)tmp + x));
       *((LTC_FAST_TYPE*)((unsigned char *)cbc->IV + x)) = *((LTC_FAST_TYPE*)((unsigned char *)ct + x));
       *((LTC_FAST_TYPE*)((unsigned char *)pt + x)) = tmpy;
        }
    #else 
            for (x = 0; x < cbc->blocklen; x++) {
               tmpy       = tmp[x] ^ cbc->IV[x];
               cbc->IV[x] = ct[x];
               pt[x]      = tmpy;
            }
    #endif
       
         ct  += cbc->blocklen;
         pt  += cbc->blocklen;
         len -= cbc->blocklen;
      }
   }
   return CRYPT_OK;
}

/**
   Get the current initial vector
   @param IV   [out] The destination of the initial vector
   @param len  [in/out]  The max size and resulting size of the initial vector
   @param cbc  The CBC state
   @return CRYPT_OK if successful
*/
int cbc_getiv(unsigned char *IV, unsigned long *len, symmetric_CBC *cbc)
{
   LTC_ARGCHK(IV  != NULL);
   LTC_ARGCHK(len != NULL);
   LTC_ARGCHK(cbc != NULL);
   if ((unsigned long)cbc->blocklen > *len) {
      *len = cbc->blocklen;
      return CRYPT_BUFFER_OVERFLOW;
   }
   XMEMCPY(IV, cbc->IV, cbc->blocklen);
   *len = cbc->blocklen;

   return CRYPT_OK;
}

/**
   Set an initial vector
   @param IV   The initial vector
   @param len  The length of the vector (in octets)
   @param cbc  The CBC state
   @return CRYPT_OK if successful
*/
int cbc_setiv(const unsigned char *IV, unsigned long len, symmetric_CBC *cbc)
{
   LTC_ARGCHK(IV  != NULL);
   LTC_ARGCHK(cbc != NULL);
   if (len != (unsigned long)cbc->blocklen) {
      return CRYPT_INVALID_ARG;
   }
   XMEMCPY(cbc->IV, IV, len);
   return CRYPT_OK;
}
