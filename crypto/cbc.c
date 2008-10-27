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
  CBC encrypt
  @param in       Plaintext
  @param len      The number of bytes to process (must be multiple of block length)
  @param out      [out] Ciphertext
  @param key      Key
  @param iv       [in/out] Initialization vector
  @param blocklen The block size
  @return ISRCRY_OK if successful
*/
enum isrcry_result _isrcry_cbc_encrypt(const unsigned char *in,
			unsigned long len, unsigned char *out,
			cipher_fn *encrypt, unsigned blocklen, void *key,
			unsigned char *iv)
{
   int x;
   enum isrcry_result err;

   if (in == NULL || out == NULL || key == NULL || iv == NULL)
	   return ISRCRY_INVALID_ARGUMENT;
   if (blocklen < 1 || len % cbc->blocklen)
	   return ISRCRY_INVALID_ARGUMENT;
#ifdef LTC_FAST
   if (cbc->blocklen % sizeof(LTC_FAST_TYPE))
	   return ISRCRY_INVALID_ARGUMENT;
#endif

   while (len) {
      /* xor IV against plaintext */
#if defined(LTC_FAST)
      for (x = 0; x < blocklen; x += sizeof(LTC_FAST_TYPE)) {
	  *((LTC_FAST_TYPE*)(iv + x)) ^= *((LTC_FAST_TYPE*)(in + x));
      }
#else 
      for (x = 0; x < blocklen; x++) {
          iv[x] ^= in[x];
      }
#endif

       /* encrypt */
      if ((err = encrypt(iv, out, key)) != ISRCRY_OK) {
	  return err;
      }

      /* store IV [ciphertext] for a future block */
#if defined(LTC_FAST)
      for (x = 0; x < blocklen; x += sizeof(LTC_FAST_TYPE)) {
	  *((LTC_FAST_TYPE*)((unsigned char *)iv + x)) = *((LTC_FAST_TYPE*)((unsigned char *)out + x));
      }
#else 
      for (x = 0; x < cbc->blocklen; x++) {
	  iv[x] = out[x];
      }
#endif
      
      out += blocklen;
      in  += blocklen;
      len -= blocklen;
   }
   return ISRCRY_OK;
}

/**
  CBC decrypt
  @param in       Ciphertext
  @param len      The number of bytes to process (must be multiple of block length)
  @param out      [out] Plaintext
  @param key      Key
  @param iv       [in/out] Initialization vector
  @param blocklen The block size
  @return ISRCRY_OK if successful
*/
enum isrcry_result _isrcry_cbc_decrypt(const unsigned char *in,
			unsigned long len, unsigned char *out,
			cipher_fn *decrypt, unsigned blocklen, void *key,
			unsigned char *iv)
{
   int x;
   enum isrcry_result err;
   unsigned char tmp[16];
#ifdef LTC_FAST
   LTC_FAST_TYPE tmpy;
#else
   unsigned char tmpy;
#endif         

   if (in == NULL || out == NULL || key == NULL || iv == NULL)
	   return ISRCRY_INVALID_ARGUMENT;
   if (blocklen < 1 || len % cbc->blocklen)
	   return ISRCRY_INVALID_ARGUMENT;
#ifdef LTC_FAST
   if (cbc->blocklen % sizeof(LTC_FAST_TYPE))
	   return ISRCRY_INVALID_ARGUMENT;
#endif
   
    while (len) {
       /* decrypt */
       if ((err = decrypt(in, tmp, key)) != ISRCRY_OK)
	       return err;

       /* xor IV against plaintext */
#if defined(LTC_FAST)
      for (x = 0; x < cbc->blocklen; x += sizeof(LTC_FAST_TYPE)) {
          tmpy = *((LTC_FAST_TYPE*)(iv + x)) ^ *((LTC_FAST_TYPE*)(tmp + x));
          *((LTC_FAST_TYPE*)(iv + x)) = *((LTC_FAST_TYPE*)(in + x));
          *((LTC_FAST_TYPE*)(out + x)) = tmpy;
      }
#else 
      for (x = 0; x < blocklen; x++) {
         tmpy       = tmp[x] ^ iv[x];
         iv[x]      = in[x];
         out[x]     = tmpy;
      }
#endif
     
       in  += cbc->blocklen;
       out += cbc->blocklen;
       len -= cbc->blocklen;
   }
   return ISRCRY_OK;
}
