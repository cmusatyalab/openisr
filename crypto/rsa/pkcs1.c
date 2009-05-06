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

/* always stores the same # of bytes, pads with leading zero bytes
   as required
 */
/**
   PKCS #1 Integer to binary
   @param n             The integer to store
   @param modulus_len   The length of the RSA modulus
   @param out           [out] The destination for the integer
   @return CRYPT_OK if successful
*/
int pkcs_1_i2osp(void *n, unsigned long modulus_len, unsigned char *out)
{
   unsigned long size;

   size = mp_unsigned_bin_size(n);

   if (size > modulus_len) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store it */
   zeromem(out, modulus_len);
   return mp_to_unsigned_bin(n, out+(modulus_len-size));
}

/**
  Read a binary string into an mp_int
  @param n          [out] The mp_int destination
  @param in         The binary string to read
  @param inlen      The length of the binary string
  @return CRYPT_OK if successful
*/
int pkcs_1_os2ip(void *n, unsigned char *in, unsigned long inlen)
{
   return mp_read_unsigned_bin(n, in, inlen);
}

/**
   Perform PKCS #1 MGF1 (internal)
   @param seed        The seed for MGF1
   @param seedlen     The length of the seed
   @param hash_idx    The index of the hash desired
   @param mask        [out] The destination
   @param masklen     The length of the mask desired
   @return CRYPT_OK if successful
*/
int pkcs_1_mgf1(int                  hash_idx,
                const unsigned char *seed, unsigned long seedlen,
                      unsigned char *mask, unsigned long masklen)
{
   unsigned long hLen, x;
   ulong32       counter;
   int           err;
   hash_state    *md;
   unsigned char *buf;
 
   LTC_ARGCHK(seed != NULL);
   LTC_ARGCHK(mask != NULL);

   /* ensure valid hash */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) { 
      return err;
   }

   /* get hash output size */
   hLen = hash_descriptor[hash_idx].hashsize;

   /* allocate memory */
   md  = XMALLOC(sizeof(hash_state));
   buf = XMALLOC(hLen);
   if (md == NULL || buf == NULL) {
      if (md != NULL) {
         XFREE(md);
      }
      if (buf != NULL) {
         XFREE(buf);
      }
      return CRYPT_MEM;
   }

   /* start counter */
   counter = 0;

   while (masklen > 0) {
       /* handle counter */
       STORE32H(counter, buf);
       ++counter;

       /* get hash of seed || counter */
       if ((err = hash_descriptor[hash_idx].init(md)) != CRYPT_OK) {
          goto LBL_ERR;
       }
       if ((err = hash_descriptor[hash_idx].process(md, seed, seedlen)) != CRYPT_OK) {
          goto LBL_ERR;
       }
       if ((err = hash_descriptor[hash_idx].process(md, buf, 4)) != CRYPT_OK) {
          goto LBL_ERR;
       }
       if ((err = hash_descriptor[hash_idx].done(md, buf)) != CRYPT_OK) {
          goto LBL_ERR;
       }

       /* store it */
       for (x = 0; x < hLen && masklen > 0; x++, masklen--) {
          *mask++ = buf[x];
       }
   }

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, hLen);
   zeromem(md,  sizeof(hash_state));
#endif

   XFREE(buf);
   XFREE(md);

   return err;
}

/**
   PKCS #1 v2.00 Signature Encoding
   @param msghash          The hash to encode
   @param msghashlen       The length of the hash (octets)
   @param saltlen          The length of the salt desired (octets)
   @param prng             An active PRNG context
   @param prng_idx         The index of the PRNG desired
   @param hash_idx         The index of the hash desired
   @param modulus_bitlen   The bit length of the RSA modulus
   @param out              [out] The destination of the encoding
   @param outlen           [in/out] The max size and resulting size of the encoded data
   @return CRYPT_OK if successful
*/
int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen,
                            unsigned long saltlen,  prng_state   *prng,     
                            int           prng_idx, int           hash_idx,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen)
{
   unsigned char *DB, *mask, *salt, *hash;
   unsigned long x, y, hLen, modulus_len;
   int           err;
   hash_state    md;

   LTC_ARGCHK(msghash != NULL);
   LTC_ARGCHK(out     != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* ensure hash and PRNG are valid */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }
   if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
      return err;
   }

   hLen        = hash_descriptor[hash_idx].hashsize;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* check sizes */
   if ((saltlen > modulus_len) || (modulus_len < hLen + saltlen + 2)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* allocate ram for DB/mask/salt/hash of size modulus_len */
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   salt = XMALLOC(modulus_len);
   hash = XMALLOC(modulus_len);
   if (DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (salt != NULL) {
         XFREE(salt);
      }
      if (hash != NULL) {
         XFREE(hash);
      }
      return CRYPT_MEM;
   }


   /* generate random salt */
   if (saltlen > 0) {
      if (prng_descriptor[prng_idx].read(salt, saltlen, prng) != saltlen) {
         err = CRYPT_ERROR_READPRNG;
         goto LBL_ERR;
      }
   }

   /* M = (eight) 0x00 || msghash || salt, hash = H(M) */
   if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   zeromem(DB, 8);
   if ((err = hash_descriptor[hash_idx].process(&md, DB, 8)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, msghash, msghashlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, salt, saltlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[hash_idx].done(&md, hash)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* generate DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */
   x = 0;
   XMEMSET(DB + x, 0, modulus_len - saltlen - hLen - 2);
   x += modulus_len - saltlen - hLen - 2;
   DB[x++] = 0x01;
   XMEMCPY(DB + x, salt, saltlen);
   x += saltlen;

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = pkcs_1_mgf1(hash_idx, hash, hLen, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* output is DB || hash || 0xBC */
   if (*outlen < modulus_len) {
      *outlen = modulus_len;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* DB len = modulus_len - hLen - 1 */
   y = 0;
   XMEMCPY(out + y, DB, modulus_len - hLen - 1);
   y += modulus_len - hLen - 1;

   /* hash */
   XMEMCPY(out + y, hash, hLen);
   y += hLen;

   /* 0xBC */
   out[y] = 0xBC;

   /* now clear the 8*modulus_len - modulus_bitlen most significant bits */
   out[0] &= 0xFF >> ((modulus_len<<3) - (modulus_bitlen-1));

   /* store output size */
   *outlen = modulus_len;
   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(DB,   modulus_len);   
   zeromem(mask, modulus_len);   
   zeromem(salt, modulus_len);   
   zeromem(hash, modulus_len);   
#endif

   XFREE(hash);
   XFREE(salt);
   XFREE(mask);
   XFREE(DB);

   return err;
}

/**
   PKCS #1 v2.00 PSS decode
   @param  msghash         The hash to verify
   @param  msghashlen      The length of the hash (octets)
   @param  sig             The signature data (encoded data)
   @param  siglen          The length of the signature data (octets)
   @param  saltlen         The length of the salt used (octets)
   @param  hash_idx        The index of the hash desired
   @param  modulus_bitlen  The bit length of the RSA modulus
   @param  res             [out] The result of the comparison, 1==valid, 0==invalid
   @return CRYPT_OK if successful (even if the comparison failed)
*/
int pkcs_1_pss_decode(const unsigned char *msghash, unsigned long msghashlen,
                      const unsigned char *sig,     unsigned long siglen,
                            unsigned long saltlen,  int           hash_idx,
                            unsigned long modulus_bitlen, int    *res)
{
   unsigned char *DB, *mask, *salt, *hash;
   unsigned long x, y, hLen, modulus_len;
   int           err;
   hash_state    md;

   LTC_ARGCHK(msghash != NULL);
   LTC_ARGCHK(res     != NULL);

   /* default to invalid */
   *res = 0;

   /* ensure hash is valid */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }

   hLen        = hash_descriptor[hash_idx].hashsize;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);

   /* check sizes */
   if ((saltlen > modulus_len) || 
       (modulus_len < hLen + saltlen + 2) || (siglen != modulus_len)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* allocate ram for DB/mask/salt/hash of size modulus_len */
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   salt = XMALLOC(modulus_len);
   hash = XMALLOC(modulus_len);
   if (DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (salt != NULL) {
         XFREE(salt);
      }
      if (hash != NULL) {
         XFREE(hash);
      }
      return CRYPT_MEM;
   }

   /* ensure the 0xBC byte */
   if (sig[siglen-1] != 0xBC) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* copy out the DB */
   x = 0;
   XMEMCPY(DB, sig + x, modulus_len - hLen - 1);
   x += modulus_len - hLen - 1;

   /* copy out the hash */
   XMEMCPY(hash, sig + x, hLen);
   x += hLen;

   /* check the MSB */
   if ((sig[0] & ~(0xFF >> ((modulus_len<<3) - (modulus_bitlen-1)))) != 0) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = pkcs_1_mgf1(hash_idx, hash, hLen, mask, modulus_len - hLen - 1)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLen - 1); y++) {
      DB[y] ^= mask[y];
   }
   
   /* now clear the first byte [make sure smaller than modulus] */
   DB[0] &= 0xFF >> ((modulus_len<<3) - (modulus_bitlen-1));

   /* DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */

   /* check for zeroes and 0x01 */
   for (x = 0; x < modulus_len - saltlen - hLen - 2; x++) {
       if (DB[x] != 0x00) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
       }
   }

   /* check for the 0x01 */
   if (DB[x++] != 0x01) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* M = (eight) 0x00 || msghash || salt, mask = H(M) */
   if ((err = hash_descriptor[hash_idx].init(&md)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   zeromem(mask, 8);
   if ((err = hash_descriptor[hash_idx].process(&md, mask, 8)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, msghash, msghashlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[hash_idx].process(&md, DB+x, saltlen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[hash_idx].done(&md, mask)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* mask == hash means valid signature */
   if (XMEMCMP(mask, hash, hLen) == 0) {
      *res = 1;
   }

   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(DB,   modulus_len);   
   zeromem(mask, modulus_len);   
   zeromem(salt, modulus_len);   
   zeromem(hash, modulus_len);   
#endif

   XFREE(hash);
   XFREE(salt);
   XFREE(mask);
   XFREE(DB);

   return err;
}
