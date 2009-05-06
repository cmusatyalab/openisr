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

/** 
   Create an RSA key
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param size     The size of the modulus (key size) desired (octets)
   @param e        The "e" value (public key).  e==65537 is a good choice
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key)
{
   void *p, *q, *tmp1, *tmp2, *tmp3;
   int    err;

   LTC_ARGCHK(ltc_mp.name != NULL);
   LTC_ARGCHK(key         != NULL);

   if ((size < (MIN_RSA_SIZE/8)) || (size > (MAX_RSA_SIZE/8))) {
      return CRYPT_INVALID_KEYSIZE;
   }

   if ((e < 3) || ((e & 1) == 0)) {
      return CRYPT_INVALID_ARG;
   }

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)) != CRYPT_OK) {
      return err;
   }

   /* make primes p and q (optimization provided by Wayne Scott) */
   if ((err = mp_set_int(tmp3, e)) != CRYPT_OK)                      { goto errkey; }  /* tmp3 = e */

   /* make prime "p" */
   do {
       if ((err = rand_prime( p, size/2, prng, wprng)) != CRYPT_OK)  { goto errkey; }
       if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK)               { goto errkey; }  /* tmp1 = p-1 */
       if ((err = mp_gcd( tmp1,  tmp3,  tmp2)) != CRYPT_OK)          { goto errkey; }  /* tmp2 = gcd(p-1, e) */
   } while (mp_cmp_d( tmp2, 1) != 0);                                                  /* while e divides p-1 */

   /* make prime "q" */
   do {
       if ((err = rand_prime( q, size/2, prng, wprng)) != CRYPT_OK)  { goto errkey; }
       if ((err = mp_sub_d( q, 1,  tmp1)) != CRYPT_OK)               { goto errkey; } /* tmp1 = q-1 */
       if ((err = mp_gcd( tmp1,  tmp3,  tmp2)) != CRYPT_OK)          { goto errkey; } /* tmp2 = gcd(q-1, e) */
   } while (mp_cmp_d( tmp2, 1) != 0);                                                 /* while e divides q-1 */

   /* tmp1 = lcm(p-1, q-1) */
   if ((err = mp_sub_d( p, 1,  tmp2)) != CRYPT_OK)                   { goto errkey; } /* tmp2 = p-1 */
                                                                                      /* tmp1 = q-1 (previous do/while loop) */
   if ((err = mp_lcm( tmp1,  tmp2,  tmp1)) != CRYPT_OK)              { goto errkey; } /* tmp1 = lcm(p-1, q-1) */

   /* make key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL)) != CRYPT_OK) {
      goto errkey;
   }

   if ((err = mp_set_int( key->e, e)) != CRYPT_OK)                     { goto errkey; } /* key->e =  e */
   if ((err = mp_invmod( key->e,  tmp1,  key->d)) != CRYPT_OK)         { goto errkey; } /* key->d = 1/e mod lcm(p-1,q-1) */
   if ((err = mp_mul( p,  q,  key->N)) != CRYPT_OK)                    { goto errkey; } /* key->N = pq */

   /* optimize for CRT now */
   /* find d mod q-1 and d mod p-1 */
   if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK)                     { goto errkey; } /* tmp1 = q-1 */
   if ((err = mp_sub_d( q, 1,  tmp2)) != CRYPT_OK)                     { goto errkey; } /* tmp2 = p-1 */
   if ((err = mp_mod( key->d,  tmp1,  key->dP)) != CRYPT_OK)           { goto errkey; } /* dP = d mod p-1 */
   if ((err = mp_mod( key->d,  tmp2,  key->dQ)) != CRYPT_OK)           { goto errkey; } /* dQ = d mod q-1 */
   if ((err = mp_invmod( q,  p,  key->qP)) != CRYPT_OK)                { goto errkey; } /* qP = 1/q mod p */

   if ((err = mp_copy( p,  key->p)) != CRYPT_OK)                       { goto errkey; }
   if ((err = mp_copy( q,  key->q)) != CRYPT_OK)                       { goto errkey; }

   /* set key type (in this case it's CRT optimized) */
   key->type = PK_PRIVATE;

   /* return ok and free temps */
   err       = CRYPT_OK;
   goto cleanup;
errkey:
   mp_clear_multi(key->d, key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
cleanup:
   mp_clear_multi(tmp3, tmp2, tmp1, p, q, NULL);
   return err;
}

/**
  Import an RSAPublicKey or RSAPrivateKey [two-prime only, only support >= 1024-bit keys, defined in PKCS #1 v2.1]
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key *key)
{
   int           err;
   void         *zero;
   unsigned char *tmpbuf;
   unsigned long  t, x, y, z, tmpoid[16];
   ltc_asn1_list ssl_pubkey_hashoid[2];
   ltc_asn1_list ssl_pubkey[2];

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* init key */
   if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, 
                            &key->dP, &key->qP, &key->p, &key->q, NULL)) != CRYPT_OK) {
      return err;
   }

   /* see if the OpenSSL DER format RSA public key will work */
   tmpbuf = XCALLOC(1, MAX_RSA_SIZE*8);
   if (tmpbuf == NULL) {
       err = CRYPT_MEM;
       goto LBL_ERR;
   }

   /* this includes the internal hash ID and optional params (NULL in this case) */
   LTC_SET_ASN1(ssl_pubkey_hashoid, 0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid,                sizeof(tmpoid)/sizeof(tmpoid[0]));   
   LTC_SET_ASN1(ssl_pubkey_hashoid, 1, LTC_ASN1_NULL,              NULL,                  0);

   /* the actual format of the SSL DER key is odd, it stores a RSAPublicKey in a **BIT** string ... so we have to extract it
      then proceed to convert bit to octet 
    */
   LTC_SET_ASN1(ssl_pubkey, 0,         LTC_ASN1_SEQUENCE,          &ssl_pubkey_hashoid,   2);
   LTC_SET_ASN1(ssl_pubkey, 1,         LTC_ASN1_BIT_STRING,        tmpbuf,                MAX_RSA_SIZE*8);

   if (der_decode_sequence(in, inlen,
                           ssl_pubkey, 2UL) == CRYPT_OK) {

      /* ok now we have to reassemble the BIT STRING to an OCTET STRING.  Thanks OpenSSL... */
      for (t = y = z = x = 0; x < ssl_pubkey[1].size; x++) {
          y = (y << 1) | tmpbuf[x];
          if (++z == 8) {
             tmpbuf[t++] = (unsigned char)y;
             y           = 0;
             z           = 0;
          }
      }

      /* now it should be SEQUENCE { INTEGER, INTEGER } */
      if ((err = der_decode_sequence_multi(tmpbuf, t,
                                           LTC_ASN1_INTEGER, 1UL, key->N, 
                                           LTC_ASN1_INTEGER, 1UL, key->e, 
                                           LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         XFREE(tmpbuf);
         goto LBL_ERR;
      }
      XFREE(tmpbuf);
      key->type = PK_PUBLIC;
      return CRYPT_OK;
   }
   XFREE(tmpbuf);

   /* not SSL public key, try to match against PKCS #1 standards */
   if ((err = der_decode_sequence_multi(in, inlen, 
                                  LTC_ASN1_INTEGER, 1UL, key->N, 
                                  LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   if (mp_cmp_d(key->N, 0) == LTC_MP_EQ) {
      if ((err = mp_init(&zero)) != CRYPT_OK) { 
         goto LBL_ERR;
      }
      /* it's a private key */
      if ((err = der_decode_sequence_multi(in, inlen, 
                          LTC_ASN1_INTEGER, 1UL, zero, 
                          LTC_ASN1_INTEGER, 1UL, key->N, 
                          LTC_ASN1_INTEGER, 1UL, key->e,
                          LTC_ASN1_INTEGER, 1UL, key->d, 
                          LTC_ASN1_INTEGER, 1UL, key->p, 
                          LTC_ASN1_INTEGER, 1UL, key->q, 
                          LTC_ASN1_INTEGER, 1UL, key->dP,
                          LTC_ASN1_INTEGER, 1UL, key->dQ, 
                          LTC_ASN1_INTEGER, 1UL, key->qP, 
                          LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         mp_clear(zero);
         goto LBL_ERR;
      }
      mp_clear(zero);
      key->type = PK_PRIVATE;
   } else if (mp_cmp_d(key->N, 1) == LTC_MP_EQ) {
      /* we don't support multi-prime RSA */
      err = CRYPT_PK_INVALID_TYPE;
      goto LBL_ERR;
   } else {
      /* it's a public key and we lack e */
      if ((err = der_decode_sequence_multi(in, inlen, 
                                     LTC_ASN1_INTEGER, 1UL, key->N, 
                                     LTC_ASN1_INTEGER, 1UL, key->e, 
                                     LTC_ASN1_EOL,     0UL, NULL)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      key->type = PK_PUBLIC;
   }
   return CRYPT_OK;
LBL_ERR:
   mp_clear_multi(key->d,  key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
   return err;
}

/**
    This will export either an RSAPublicKey or RSAPrivateKey [defined in PKCS #1 v2.1] 
    @param out       [out] Destination of the packet
    @param outlen    [in/out] The max size and resulting size of the packet
    @param type      The type of exported key (PK_PRIVATE or PK_PUBLIC)
    @param key       The RSA key to export
    @return CRYPT_OK if successful
*/    
int rsa_export(unsigned char *out, unsigned long *outlen, int type, rsa_key *key)
{
   unsigned long zero=0;
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   /* type valid? */
   if (!(key->type == PK_PRIVATE) && (type == PK_PRIVATE)) {
      return CRYPT_PK_INVALID_TYPE;
   }

   if (type == PK_PRIVATE) {
      /* private key */
      /* output is 
            Version, n, e, d, p, q, d mod (p-1), d mod (q - 1), 1/q mod p
       */
      return der_encode_sequence_multi(out, outlen, 
                          LTC_ASN1_SHORT_INTEGER, 1UL, &zero, 
                          LTC_ASN1_INTEGER, 1UL,  key->N, 
                          LTC_ASN1_INTEGER, 1UL,  key->e,
                          LTC_ASN1_INTEGER, 1UL,  key->d, 
                          LTC_ASN1_INTEGER, 1UL,  key->p, 
                          LTC_ASN1_INTEGER, 1UL,  key->q, 
                          LTC_ASN1_INTEGER, 1UL,  key->dP,
                          LTC_ASN1_INTEGER, 1UL,  key->dQ, 
                          LTC_ASN1_INTEGER, 1UL,  key->qP, 
                          LTC_ASN1_EOL,     0UL, NULL);
   } else {
      /* public key */
      return der_encode_sequence_multi(out, outlen, 
                                 LTC_ASN1_INTEGER, 1UL,  key->N, 
                                 LTC_ASN1_INTEGER, 1UL,  key->e, 
                                 LTC_ASN1_EOL,     0UL, NULL);
   }
}

/** 
   Compute an RSA modular exponentiation 
   @param in         The input data to send into RSA
   @param inlen      The length of the input (octets)
   @param out        [out] The destination 
   @param outlen     [in/out] The max size and resulting size of the output
   @param which      Which exponent to use, e.g. PK_PRIVATE or PK_PUBLIC
   @param key        The RSA key to use 
   @return CRYPT_OK if successful
*/   
int rsa_exptmod(const unsigned char *in,   unsigned long inlen,
                      unsigned char *out,  unsigned long *outlen, int which,
                      rsa_key *key)
{
   void         *tmp, *tmpa, *tmpb;
   unsigned long x;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);
  
   /* is the key of the right type for the operation? */
   if (which == PK_PRIVATE && (key->type != PK_PRIVATE)) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* must be a private or public operation */
   if (which != PK_PRIVATE && which != PK_PUBLIC) {
      return CRYPT_PK_INVALID_TYPE;
   }

   /* init and copy into tmp */
   if ((err = mp_init_multi(&tmp, &tmpa, &tmpb, NULL)) != CRYPT_OK)                                    { return err; }
   if ((err = mp_read_unsigned_bin(tmp, (unsigned char *)in, (int)inlen)) != CRYPT_OK)                 { goto error; }

   /* sanity check on the input */
   if (mp_cmp(key->N, tmp) == LTC_MP_LT) {
      err = CRYPT_PK_INVALID_SIZE;
      goto error;
   }

   /* are we using the private exponent and is the key optimized? */
   if (which == PK_PRIVATE) {
      /* tmpa = tmp^dP mod p */
      if ((err = mp_exptmod(tmp, key->dP, key->p, tmpa)) != CRYPT_OK)                               { goto error; }

      /* tmpb = tmp^dQ mod q */
      if ((err = mp_exptmod(tmp, key->dQ, key->q, tmpb)) != CRYPT_OK)                               { goto error; }

      /* tmp = (tmpa - tmpb) * qInv (mod p) */
      if ((err = mp_sub(tmpa, tmpb, tmp)) != CRYPT_OK)                                              { goto error; }
      if ((err = mp_mulmod(tmp, key->qP, key->p, tmp)) != CRYPT_OK)                                { goto error; }

      /* tmp = tmpb + q * tmp */
      if ((err = mp_mul(tmp, key->q, tmp)) != CRYPT_OK)                                             { goto error; }
      if ((err = mp_add(tmp, tmpb, tmp)) != CRYPT_OK)                                               { goto error; }
   } else {
      /* exptmod it */
      if ((err = mp_exptmod(tmp, key->e, key->N, tmp)) != CRYPT_OK)                                { goto error; }
   }

   /* read it back */
   x = (unsigned long)mp_unsigned_bin_size(key->N);
   if (x > *outlen) {
      *outlen = x;
      err = CRYPT_BUFFER_OVERFLOW;
      goto error;
   }

   /* this should never happen ... */
   if (mp_unsigned_bin_size(tmp) > mp_unsigned_bin_size(key->N)) {
      err = CRYPT_ERROR;
      goto error;
   }
   *outlen = x;

   /* convert it */
   zeromem(out, x);
   if ((err = mp_to_unsigned_bin(tmp, out+(x-mp_unsigned_bin_size(tmp)))) != CRYPT_OK)               { goto error; }

   /* clean up and return */
   err = CRYPT_OK;
error:
   mp_clear_multi(tmp, tmpa, tmpb, NULL);
   return err;
}

/**
  PKCS #1 pad then sign
  @param in        The hash to sign
  @param inlen     The length of the hash to sign (octets)
  @param out       [out] The signature
  @param outlen    [in/out] The max size and resulting size of the signature
  @param padding   Type of padding (LTC_PKCS_1_PSS or LTC_PKCS_1_V1_5)
  @param prng      An active PRNG state
  @param prng_idx  The index of the PRNG desired
  @param hash_idx  The index of the hash desired
  @param saltlen   The length of the salt desired (octets)
  @param key       The private RSA key to use
  @return CRYPT_OK if successful
*/
int rsa_sign_hash_ex(const unsigned char *in,       unsigned long  inlen,
                           unsigned char *out,      unsigned long *outlen,
                           int            padding,
                           prng_state    *prng,     int            prng_idx,
                           int            hash_idx, unsigned long  saltlen,
                           rsa_key *key)
{
   unsigned long modulus_bitlen, modulus_bytelen, x, y;
   int           err;

   LTC_ARGCHK(in       != NULL);
   LTC_ARGCHK(out      != NULL);
   LTC_ARGCHK(outlen   != NULL);
   LTC_ARGCHK(key      != NULL);

   /* valid padding? */
   if ((padding != LTC_PKCS_1_V1_5) && (padding != LTC_PKCS_1_PSS)) {
     return CRYPT_PK_INVALID_PADDING;
   }

   if (padding == LTC_PKCS_1_PSS) {
     /* valid prng and hash ? */
     if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
        return err;
     }
     if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
        return err;
     }
   }

   /* get modulus len in bits */
   modulus_bitlen = mp_count_bits((key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size((key->N));
  if (modulus_bytelen > *outlen) {
     *outlen = modulus_bytelen;
     return CRYPT_BUFFER_OVERFLOW;
  }

  if (padding == LTC_PKCS_1_PSS) {
    /* PSS pad the key */
    x = *outlen;
    if ((err = pkcs_1_pss_encode(in, inlen, saltlen, prng, prng_idx,
                                 hash_idx, modulus_bitlen, out, &x)) != CRYPT_OK) {
       return err;
    }
  } else {
    /* PKCS #1 v1.5 pad the hash */
    unsigned char *tmpin;
    ltc_asn1_list digestinfo[2], siginfo[2];

    /* not all hashes have OIDs... so sad */
    if (hash_descriptor[hash_idx].OIDlen == 0) {
       return CRYPT_INVALID_ARG;
    }

    /* construct the SEQUENCE 
      SEQUENCE {
         SEQUENCE {hashoid OID
                   blah    NULL
         }
         hash    OCTET STRING 
      }
   */
    LTC_SET_ASN1(digestinfo, 0, LTC_ASN1_OBJECT_IDENTIFIER, hash_descriptor[hash_idx].OID, hash_descriptor[hash_idx].OIDlen);
    LTC_SET_ASN1(digestinfo, 1, LTC_ASN1_NULL,              NULL,                          0);
    LTC_SET_ASN1(siginfo,    0, LTC_ASN1_SEQUENCE,          digestinfo,                    2);
    LTC_SET_ASN1(siginfo,    1, LTC_ASN1_OCTET_STRING,      in,                            inlen);

    /* allocate memory for the encoding */
    y = mp_unsigned_bin_size(key->N);
    tmpin = XMALLOC(y);
    if (tmpin == NULL) {
       return CRYPT_MEM;
    }

    if ((err = der_encode_sequence(siginfo, 2, tmpin, &y)) != CRYPT_OK) {
       XFREE(tmpin);
       return err;
    }

    x = *outlen;
    if ((err = pkcs_1_v1_5_encode(tmpin, y, LTC_PKCS_1_EMSA,
                                  modulus_bitlen, NULL, 0,
                                  out, &x)) != CRYPT_OK) {
      XFREE(tmpin);
      return err;
    }
    XFREE(tmpin);
  }

  /* RSA encode it */
  return ltc_mp.rsa_me(out, x, out, outlen, PK_PRIVATE, key);
}

/**
  PKCS #1 de-sign then v1.5 or PSS depad
  @param sig              The signature data
  @param siglen           The length of the signature data (octets)
  @param hash             The hash of the message that was signed
  @param hashlen          The length of the hash of the message that was signed (octets)
  @param padding          Type of padding (LTC_PKCS_1_PSS or LTC_PKCS_1_V1_5)
  @param hash_idx         The index of the desired hash
  @param saltlen          The length of the salt used during signature
  @param stat             [out] The result of the signature comparison, 1==valid, 0==invalid
  @param key              The public RSA key corresponding to the key that performed the signature
  @return CRYPT_OK on success (even if the signature is invalid)
*/
int rsa_verify_hash_ex(const unsigned char *sig,      unsigned long siglen,
                       const unsigned char *hash,     unsigned long hashlen,
                             int            padding,
                             int            hash_idx, unsigned long saltlen,
                             int           *stat,     rsa_key      *key)
{
  unsigned long modulus_bitlen, modulus_bytelen, x;
  int           err;
  unsigned char *tmpbuf;

  LTC_ARGCHK(hash  != NULL);
  LTC_ARGCHK(sig   != NULL);
  LTC_ARGCHK(stat  != NULL);
  LTC_ARGCHK(key   != NULL);

  /* default to invalid */
  *stat = 0;

  /* valid padding? */

  if ((padding != LTC_PKCS_1_V1_5) &&
      (padding != LTC_PKCS_1_PSS)) {
    return CRYPT_PK_INVALID_PADDING;
  }

  if (padding == LTC_PKCS_1_PSS) {
    /* valid hash ? */
    if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
       return err;
    }
  }

  /* get modulus len in bits */
  modulus_bitlen = mp_count_bits( (key->N));

  /* outlen must be at least the size of the modulus */
  modulus_bytelen = mp_unsigned_bin_size( (key->N));
  if (modulus_bytelen != siglen) {
     return CRYPT_INVALID_PACKET;
  }

  /* allocate temp buffer for decoded sig */
  tmpbuf = XMALLOC(siglen);
  if (tmpbuf == NULL) {
     return CRYPT_MEM;
  }

  /* RSA decode it  */
  x = siglen;
  if ((err = ltc_mp.rsa_me(sig, siglen, tmpbuf, &x, PK_PUBLIC, key)) != CRYPT_OK) {
     XFREE(tmpbuf);
     return err;
  }

  /* make sure the output is the right size */
  if (x != siglen) {
     XFREE(tmpbuf);
     return CRYPT_INVALID_PACKET;
  }

  if (padding == LTC_PKCS_1_PSS) {
    /* PSS decode and verify it */
    err = pkcs_1_pss_decode(hash, hashlen, tmpbuf, x, saltlen, hash_idx, modulus_bitlen, stat);
  } else {
    /* PKCS #1 v1.5 decode it */
    unsigned char *out;
    unsigned long outlen, loid[16];
    int           decoded;
    ltc_asn1_list digestinfo[2], siginfo[2];

    /* not all hashes have OIDs... so sad */
    if (hash_descriptor[hash_idx].OIDlen == 0) {
       err = CRYPT_INVALID_ARG;
       goto bail_2;
    }

    /* allocate temp buffer for decoded hash */
    outlen = ((modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0)) - 3;
    out    = XMALLOC(outlen);
    if (out == NULL) {
      err = CRYPT_MEM;
      goto bail_2;
    }

    if ((err = pkcs_1_v1_5_decode(tmpbuf, x, LTC_PKCS_1_EMSA, modulus_bitlen, out, &outlen, &decoded)) != CRYPT_OK) {
      XFREE(out);       
      goto bail_2;
    }

    /* now we must decode out[0...outlen-1] using ASN.1, test the OID and then test the hash */
    /* construct the SEQUENCE 
      SEQUENCE {
         SEQUENCE {hashoid OID
                   blah    NULL
         }
         hash    OCTET STRING 
      }
   */
    LTC_SET_ASN1(digestinfo, 0, LTC_ASN1_OBJECT_IDENTIFIER, loid, sizeof(loid)/sizeof(loid[0]));
    LTC_SET_ASN1(digestinfo, 1, LTC_ASN1_NULL,              NULL,                          0);
    LTC_SET_ASN1(siginfo,    0, LTC_ASN1_SEQUENCE,          digestinfo,                    2);
    LTC_SET_ASN1(siginfo,    1, LTC_ASN1_OCTET_STRING,      tmpbuf,                        siglen);
   
    if ((err = der_decode_sequence(out, outlen, siginfo, 2)) != CRYPT_OK) {
       XFREE(out);
       goto bail_2;
    }

    /* test OID */
    if ((digestinfo[0].size == hash_descriptor[hash_idx].OIDlen) &&
        (XMEMCMP(digestinfo[0].data, hash_descriptor[hash_idx].OID, sizeof(unsigned long) * hash_descriptor[hash_idx].OIDlen) == 0) &&
        (siginfo[1].size == hashlen) &&
        (XMEMCMP(siginfo[1].data, hash, hashlen) == 0)) {
       *stat = 1;
    }

#ifdef LTC_CLEAN_STACK
    zeromem(out, outlen);
#endif
    XFREE(out);
  }

bail_2:
#ifdef LTC_CLEAN_STACK
  zeromem(tmpbuf, siglen);
#endif
  XFREE(tmpbuf);
  return err;
}

/**
  Free an RSA key from memory
  @param key   The RSA key to free
*/
void rsa_free(rsa_key *key)
{
   LTC_ARGCHKVD(key != NULL);
   mp_clear_multi(key->e, key->d, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
}
