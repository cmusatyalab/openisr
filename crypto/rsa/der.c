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
  Store a BIT STRING
  @param in       The array of bits to store (one per char)
  @param inlen    The number of bits tostore
  @param out      [out] The destination for the DER encoded BIT STRING
  @param outlen   [in/out] The max size and resulting size of the DER BIT STRING
  @return CRYPT_OK if successful
*/
int der_encode_bit_string(const unsigned char *in, unsigned long inlen,
                                unsigned char *out, unsigned long *outlen)
{
   unsigned long len, x, y;
   unsigned char buf;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* avoid overflows */
   if ((err = der_length_bit_string(inlen, &len)) != CRYPT_OK) {
      return err;
   }

   if (len > *outlen) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* store header (include bit padding count in length) */
   x = 0;
   y = (inlen >> 3) + ((inlen&7) ? 1 : 0) + 1;

   out[x++] = 0x03;
   if (y < 128) {
      out[x++] = (unsigned char)y;
   } else if (y < 256) {
      out[x++] = 0x81;
      out[x++] = (unsigned char)y;
   } else if (y < 65536) {
      out[x++] = 0x82;
      out[x++] = (unsigned char)((y>>8)&255);
      out[x++] = (unsigned char)(y&255);
   }

   /* store number of zero padding bits */
   out[x++] = (unsigned char)((8 - inlen) & 7);

   /* store the bits in big endian format */
   for (y = buf = 0; y < inlen; y++) {
       buf |= (in[y] ? 1 : 0) << (7 - (y & 7));
       if ((y & 7) == 7) {
          out[x++] = buf;
          buf      = 0;
       }
   }
   /* store last byte */
   if (inlen & 7) {
      out[x++] = buf;
   }
   *outlen = x;
   return CRYPT_OK;
}

/**
  Store a BIT STRING
  @param in      The DER encoded BIT STRING
  @param inlen   The size of the DER BIT STRING
  @param out     [out] The array of bits stored (one per char)
  @param outlen  [in/out] The number of bits stored
  @return CRYPT_OK if successful
*/
int der_decode_bit_string(const unsigned char *in,  unsigned long inlen,
                                unsigned char *out, unsigned long *outlen)
{
   unsigned long dlen, blen, x, y;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* packet must be at least 4 bytes */
   if (inlen < 4) {
       return CRYPT_INVALID_ARG;
   }

   /* check for 0x03 */
   if ((in[0]&0x1F) != 0x03) {
      return CRYPT_INVALID_PACKET;
   }

    /* offset in the data */
    x = 1;

   /* get the length of the data */
   if (in[x] & 0x80) {
      /* long format get number of length bytes */
      y = in[x++] & 0x7F;

      /* invalid if 0 or > 2 */
      if (y == 0 || y > 2) {
         return CRYPT_INVALID_PACKET;
      }

      /* read the data len */
      dlen = 0;
      while (y--) {
         dlen = (dlen << 8) | (unsigned long)in[x++];
      }
   } else {
      /* short format */
      dlen = in[x++] & 0x7F;
   }
  
   /* is the data len too long or too short? */
   if ((dlen == 0) || (dlen + x > inlen)) {
       return CRYPT_INVALID_PACKET;
   }

   /* get padding count */
   blen = ((dlen - 1) << 3) - (in[x++] & 7);

   /* too many bits? */
   if (blen > *outlen) {
      *outlen = blen;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* decode/store the bits */
   for (y = 0; y < blen; y++) {
       out[y] = (in[x] & (1 << (7 - (y & 7)))) ? 1 : 0;
       if ((y & 7) == 7) {
          ++x;
       }
   }

   /* we done */
   *outlen = blen;
   return CRYPT_OK;
}

/**
  Gets length of DER encoding of BIT STRING 
  @param nbits  The number of bits in the string to encode
  @param outlen [out] The length of the DER encoding for the given string
  @return CRYPT_OK if successful
*/
int der_length_bit_string(unsigned long nbits, unsigned long *outlen)
{
   unsigned long nbytes;
   LTC_ARGCHK(outlen != NULL);

   /* get the number of the bytes */
   nbytes = (nbits >> 3) + ((nbits & 7) ? 1 : 0) + 1;
 
   if (nbytes < 128) {
      /* 03 LL PP DD DD DD ... */
      *outlen = 2 + nbytes;
   } else if (nbytes < 256) {
      /* 03 81 LL PP DD DD DD ... */
      *outlen = 3 + nbytes;
   } else if (nbytes < 65536) {
      /* 03 82 LL LL PP DD DD DD ... */
      *outlen = 4 + nbytes;
   } else {
      return CRYPT_INVALID_ARG;
   }

   return CRYPT_OK;
}

/* Exports a positive bignum as DER format (upto 2^32 bytes in size) */
/**
  Store a mp_int integer
  @param num      The first mp_int to encode
  @param out      [out] The destination for the DER encoded integers
  @param outlen   [in/out] The max size and resulting size of the DER encoded integers
  @return CRYPT_OK if successful
*/
int der_encode_integer(void *num, unsigned char *out, unsigned long *outlen)
{  
   unsigned long tmplen, y;
   int           err, leading_zero;

   LTC_ARGCHK(num    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* find out how big this will be */
   if ((err = der_length_integer(num, &tmplen)) != CRYPT_OK) {
      return err;
   }

   if (*outlen < tmplen) {
      *outlen = tmplen;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (mp_cmp_d(num, 0) != LTC_MP_LT) {
      /* we only need a leading zero if the msb of the first byte is one */
      if ((mp_count_bits(num) & 7) == 0 || mp_iszero(num) == LTC_MP_YES) {
         leading_zero = 1;
      } else {
         leading_zero = 0;
      }

      /* get length of num in bytes (plus 1 since we force the msbyte to zero) */
      y = mp_unsigned_bin_size(num) + leading_zero;
   } else {
      leading_zero = 0;
      y            = mp_count_bits(num);
      y            = y + (8 - (y & 7));
      y            = y >> 3;
      if (((mp_cnt_lsb(num)+1)==mp_count_bits(num)) && ((mp_count_bits(num)&7)==0)) --y;
   }

   /* now store initial data */
   *out++ = 0x02;
   if (y < 128) {
      /* short form */
      *out++ = (unsigned char)y;
   } else if (y < 256) {
      *out++ = 0x81;
      *out++ = (unsigned char)y;
   } else if (y < 65536UL) {
      *out++ = 0x82;
      *out++ = (unsigned char)((y>>8)&255);
      *out++ = (unsigned char)y;
   } else if (y < 16777216UL) {
      *out++ = 0x83;
      *out++ = (unsigned char)((y>>16)&255);
      *out++ = (unsigned char)((y>>8)&255);
      *out++ = (unsigned char)y;
   } else {
      return CRYPT_INVALID_ARG;
   }

   /* now store msbyte of zero if num is non-zero */
   if (leading_zero) {
      *out++ = 0x00;
   }

   /* if it's not zero store it as big endian */
   if (mp_cmp_d(num, 0) == LTC_MP_GT) {
      /* now store the mpint */
      if ((err = mp_to_unsigned_bin(num, out)) != CRYPT_OK) {
          return err;
      }
   } else if (mp_iszero(num) != LTC_MP_YES) {
      void *tmp;
         
      /* negative */
      if (mp_init(&tmp) != CRYPT_OK) {
         return CRYPT_MEM;
      }

      /* 2^roundup and subtract */
      y = mp_count_bits(num);
      y = y + (8 - (y & 7));
      if (((mp_cnt_lsb(num)+1)==mp_count_bits(num)) && ((mp_count_bits(num)&7)==0)) y -= 8;
      if (mp_2expt(tmp, y) != CRYPT_OK || mp_add(tmp, num, tmp) != CRYPT_OK) {
         mp_clear(tmp);
         return CRYPT_MEM;
      }
      if ((err = mp_to_unsigned_bin(tmp, out)) != CRYPT_OK) {
         mp_clear(tmp);
         return err;
      }
      mp_clear(tmp);
   }

   /* we good */
   *outlen = tmplen; 
   return CRYPT_OK;
}

/**
  Read a mp_int integer
  @param in       The DER encoded data
  @param inlen    Size of DER encoded data
  @param num      The first mp_int to decode
  @return CRYPT_OK if successful
*/
int der_decode_integer(const unsigned char *in, unsigned long inlen, void *num)
{
   unsigned long x, y, z;
   int           err;

   LTC_ARGCHK(num    != NULL);
   LTC_ARGCHK(in     != NULL);

   /* min DER INTEGER is 0x02 01 00 == 0 */
   if (inlen < (1 + 1 + 1)) {
      return CRYPT_INVALID_PACKET;
   }

   /* ok expect 0x02 when we AND with 0001 1111 [1F] */
   x = 0;
   if ((in[x++] & 0x1F) != 0x02) {
      return CRYPT_INVALID_PACKET;
   }

   /* now decode the len stuff */
   z = in[x++];

   if ((z & 0x80) == 0x00) {
      /* short form */

      /* will it overflow? */
      if (x + z > inlen) {
         return CRYPT_INVALID_PACKET;
      }
     
      /* no so read it */
      if ((err = mp_read_unsigned_bin(num, (unsigned char *)in + x, z)) != CRYPT_OK) {
         return err;
      }
   } else {
      /* long form */
      z &= 0x7F;
      
      /* will number of length bytes overflow? (or > 4) */
      if (((x + z) > inlen) || (z > 4) || (z == 0)) {
         return CRYPT_INVALID_PACKET;
      }

      /* now read it in */
      y = 0;
      while (z--) {
         y = ((unsigned long)(in[x++])) | (y << 8);
      }

      /* now will reading y bytes overrun? */
      if ((x + y) > inlen) {
         return CRYPT_INVALID_PACKET;
      }

      /* no so read it */
      if ((err = mp_read_unsigned_bin(num, (unsigned char *)in + x, y)) != CRYPT_OK) {
         return err;
      }
   }

   /* see if it's negative */
   if (in[x] & 0x80) {
      void *tmp;
      if (mp_init(&tmp) != CRYPT_OK) {
         return CRYPT_MEM;
      }

      if (mp_2expt(tmp, mp_count_bits(num)) != CRYPT_OK || mp_sub(num, tmp, num) != CRYPT_OK) {
         mp_clear(tmp);
         return CRYPT_MEM;
      }
      mp_clear(tmp);
   } 

   return CRYPT_OK;

}

/**
  Gets length of DER encoding of num 
  @param num    The int to get the size of 
  @param outlen [out] The length of the DER encoding for the given integer
  @return CRYPT_OK if successful
*/
int der_length_integer(void *num, unsigned long *outlen)
{
   unsigned long z, len;
   int           leading_zero;

   LTC_ARGCHK(num     != NULL);
   LTC_ARGCHK(outlen  != NULL);

   if (mp_cmp_d(num, 0) != LTC_MP_LT) {
      /* positive */

      /* we only need a leading zero if the msb of the first byte is one */
      if ((mp_count_bits(num) & 7) == 0 || mp_iszero(num) == LTC_MP_YES) {
         leading_zero = 1;
      } else {
         leading_zero = 0;
      }

      /* size for bignum */
      z = len = leading_zero + mp_unsigned_bin_size(num);
   } else {
      /* it's negative */
      /* find power of 2 that is a multiple of eight and greater than count bits */
      leading_zero = 0;
      z = mp_count_bits(num);
      z = z + (8 - (z & 7));
      if (((mp_cnt_lsb(num)+1)==mp_count_bits(num)) && ((mp_count_bits(num)&7)==0)) --z;
      len = z = z >> 3;
   }

   /* now we need a length */
   if (z < 128) {
      /* short form */
      ++len;
   } else {
      /* long form (relies on z != 0), assumes length bytes < 128 */
      ++len;

      while (z) {
         ++len;
         z >>= 8;
      }
   }

   /* we need a 0x02 to indicate it's INTEGER */
   ++len;

   /* return length */
   *outlen = len; 
   return CRYPT_OK;
}

/**
  Encode an OID
  @param words   The words to encode  (upto 32-bits each)
  @param nwords  The number of words in the OID
  @param out     [out] Destination of OID data
  @param outlen  [in/out] The max and resulting size of the OID
  @return CRYPT_OK if successful
*/
int der_encode_object_identifier(unsigned long *words, unsigned long  nwords,
                                 unsigned char *out,   unsigned long *outlen)
{
   unsigned long i, x, y, z, t, mask, wordbuf;
   int           err;

   LTC_ARGCHK(words  != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* check length */
   if ((err = der_length_object_identifier(words, nwords, &x)) != CRYPT_OK) {
      return err;
   }
   if (x > *outlen) {
      *outlen = x;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* compute length to store OID data */
   z = 0;
   wordbuf = words[0] * 40 + words[1];
   for (y = 1; y < nwords; y++) {
       t = der_object_identifier_bits(wordbuf);
       z += t/7 + ((t%7) ? 1 : 0) + (wordbuf == 0 ? 1 : 0);
       if (y < nwords - 1) {
          wordbuf = words[y + 1];
       }
   }

   /* store header + length */
   x = 0; 
   out[x++] = 0x06;
   if (z < 128) {
      out[x++] = (unsigned char)z;
   } else if (z < 256) {
      out[x++] = 0x81;
      out[x++] = (unsigned char)z;
   } else if (z < 65536UL) {
      out[x++] = 0x82;
      out[x++] = (unsigned char)((z>>8)&255);
      out[x++] = (unsigned char)(z&255);
   } else {
      return CRYPT_INVALID_ARG;
   }

   /* store first byte */
    wordbuf = words[0] * 40 + words[1];   
    for (i = 1; i < nwords; i++) {
        /* store 7 bit words in little endian */
        t    = wordbuf & 0xFFFFFFFF;
        if (t) {
           y    = x;
           mask = 0;
           while (t) {
               out[x++] = (unsigned char)((t & 0x7F) | mask);
               t    >>= 7;
               mask  |= 0x80;  /* upper bit is set on all but the last byte */
           }
           /* now swap bytes y...x-1 */
           z = x - 1;
           while (y < z) {
               t = out[y]; out[y] = out[z]; out[z] = (unsigned char)t;
               ++y; 
               --z;
           }
       } else {
          /* zero word */
          out[x++] = 0x00;
       }
       
       if (i < nwords - 1) {
          wordbuf = words[i + 1];
       }
   }

   *outlen = x;
   return CRYPT_OK;
}

/**
  Decode OID data and store the array of integers in words
  @param in      The OID DER encoded data
  @param inlen   The length of the OID data
  @param words   [out] The destination of the OID words
  @param outlen  [in/out] The number of OID words
  @return CRYPT_OK if successful
*/
int der_decode_object_identifier(const unsigned char *in,    unsigned long  inlen,
                                       unsigned long *words, unsigned long *outlen)
{
   unsigned long x, y, t, len;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(words  != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* header is at least 3 bytes */
   if (inlen < 3) {
      return CRYPT_INVALID_PACKET;
   }

   /* must be room for at least two words */
   if (*outlen < 2) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* decode the packet header */
   x = 0;
   if ((in[x++] & 0x1F) != 0x06) {
      return CRYPT_INVALID_PACKET;
   }
   
   /* get the length */
   if (in[x] < 128) {
      len = in[x++]; 
   } else {
       if (in[x] < 0x81 || in[x] > 0x82) {
          return CRYPT_INVALID_PACKET;
       }
       y   = in[x++] & 0x7F;
       len = 0;
       while (y--) {
          len = (len << 8) | (unsigned long)in[x++];
       }
   }

   if (len < 1 || (len + x) > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* decode words */
   y = 0;
   t = 0;
   while (len--) {
       t = (t << 7) | (in[x] & 0x7F);
       if (!(in[x++] & 0x80)) {
           /* store t */
           if (y >= *outlen) {
              return CRYPT_BUFFER_OVERFLOW;
           }
      if (y == 0) {
         words[0] = t / 40;
         words[1] = t % 40;
         y = 2;
      } else {
              words[y++] = t;
      }
           t          = 0;
       }
   }
       
   *outlen = y;
   return CRYPT_OK;
}

static unsigned long der_object_identifier_bits(unsigned long x)
{
   unsigned long c;
   x &= 0xFFFFFFFF;
   c  = 0;
   while (x) {
     ++c;
     x >>= 1;
   }
   return c;
}


/**
  Gets length of DER encoding of Object Identifier
  @param nwords   The number of OID words 
  @param words    The actual OID words to get the size of
  @param outlen   [out] The length of the DER encoding for the given string
  @return CRYPT_OK if successful
*/
int der_length_object_identifier(unsigned long *words, unsigned long nwords, unsigned long *outlen)
{
   unsigned long y, z, t, wordbuf;   

   LTC_ARGCHK(words  != NULL);
   LTC_ARGCHK(outlen != NULL);


   /* must be >= 2 words */
   if (nwords < 2) {
      return CRYPT_INVALID_ARG;
   }

   /* word1 = 0,1,2,3 and word2 0..39 */
   if (words[0] > 3 || (words[0] < 2 && words[1] > 39)) {
      return CRYPT_INVALID_ARG;
   }

   /* leading word is the first two */
   z = 0;
   wordbuf = words[0] * 40 + words[1];
   for (y = 1; y < nwords; y++) {
       t = der_object_identifier_bits(wordbuf);
       z += t/7 + ((t%7) ? 1 : 0) + (wordbuf == 0 ? 1 : 0);
       if (y < nwords - 1) {
          /* grab next word */
          wordbuf = words[y+1];
       }
   }

   /* now depending on the length our length encoding changes */
   if (z < 128) {
      z += 2;
   } else if (z < 256) {
      z += 3;
   } else if (z < 65536UL) {
      z += 4;
   } else {
      return CRYPT_INVALID_ARG;
   }

   *outlen = z;
   return CRYPT_OK;
}

/**
  Store an OCTET STRING
  @param in       The array of OCTETS to store (one per char)
  @param inlen    The number of OCTETS to store
  @param out      [out] The destination for the DER encoded OCTET STRING
  @param outlen   [in/out] The max size and resulting size of the DER OCTET STRING
  @return CRYPT_OK if successful
*/
int der_encode_octet_string(const unsigned char *in, unsigned long inlen,
                                  unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y, len;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* get the size */
   if ((err = der_length_octet_string(inlen, &len)) != CRYPT_OK) {
      return err; 
   }

   /* too big? */
   if (len > *outlen) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* encode the header+len */
   x = 0;
   out[x++] = 0x04;
   if (inlen < 128) {
      out[x++] = (unsigned char)inlen;
   } else if (inlen < 256) {
      out[x++] = 0x81;
      out[x++] = (unsigned char)inlen;
   } else if (inlen < 65536UL) {
      out[x++] = 0x82;
      out[x++] = (unsigned char)((inlen>>8)&255);
      out[x++] = (unsigned char)(inlen&255);
   } else if (inlen < 16777216UL) {
      out[x++] = 0x83;
      out[x++] = (unsigned char)((inlen>>16)&255);
      out[x++] = (unsigned char)((inlen>>8)&255);
      out[x++] = (unsigned char)(inlen&255);
   } else {
      return CRYPT_INVALID_ARG;
   }

   /* store octets */
   for (y = 0; y < inlen; y++) {
       out[x++] = in[y];
   }

   /* retun length */
   *outlen = x;

   return CRYPT_OK;
}

/**
  Store a OCTET STRING
  @param in      The DER encoded OCTET STRING
  @param inlen   The size of the DER OCTET STRING
  @param out     [out] The array of octets stored (one per char)
  @param outlen  [in/out] The number of octets stored
  @return CRYPT_OK if successful
*/
int der_decode_octet_string(const unsigned char *in, unsigned long inlen,
                                  unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y, len;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* must have header at least */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* check for 0x04 */
   if ((in[0] & 0x1F) != 0x04) {
      return CRYPT_INVALID_PACKET;
   }
   x = 1;

   /* decode the length */
   if (in[x] & 0x80) {
      /* valid # of bytes in length are 1,2,3 */
      y = in[x] & 0x7F;
      if ((y == 0) || (y > 3) || ((x + y) > inlen)) {
         return CRYPT_INVALID_PACKET;
      }

      /* read the length in */
      len = 0;
      ++x;
      while (y--) {
         len = (len << 8) | in[x++];
      }
   } else {
      len = in[x++] & 0x7F;
   }

   /* is it too long? */
   if (len > *outlen) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   if (len + x > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* read the data */
   for (y = 0; y < len; y++) {
       out[y] = in[x++];
   }

   *outlen = y;

   return CRYPT_OK;
}

/**
  Gets length of DER encoding of OCTET STRING 
  @param noctets  The number of octets in the string to encode
  @param outlen   [out] The length of the DER encoding for the given string
  @return CRYPT_OK if successful
*/
int der_length_octet_string(unsigned long noctets, unsigned long *outlen)
{
   LTC_ARGCHK(outlen != NULL);

   if (noctets < 128) {
      /* 04 LL DD DD DD ... */
      *outlen = 2 + noctets;
   } else if (noctets < 256) {
      /* 04 81 LL DD DD DD ... */
      *outlen = 3 + noctets;
   } else if (noctets < 65536UL) {
      /* 04 82 LL LL DD DD DD ... */
      *outlen = 4 + noctets;
   } else if (noctets < 16777216UL) {
      /* 04 83 LL LL LL DD DD DD ... */
      *outlen = 5 + noctets;
   } else {
      return CRYPT_INVALID_ARG;
   }

   return CRYPT_OK;
}

/**
  Store a short integer in the range (0,2^32-1)
  @param num      The integer to encode
  @param out      [out] The destination for the DER encoded integers
  @param outlen   [in/out] The max size and resulting size of the DER encoded integers
  @return CRYPT_OK if successful
*/
int der_encode_short_integer(unsigned long num, unsigned char *out, unsigned long *outlen)
{  
   unsigned long len, x, y, z;
   int           err;
   
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* force to 32 bits */
   num &= 0xFFFFFFFFUL;

   /* find out how big this will be */
   if ((err = der_length_short_integer(num, &len)) != CRYPT_OK) {
      return err;
   }

   if (*outlen < len) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* get len of output */
   z = 0;
   y = num;
   while (y) {
     ++z;
     y >>= 8;
   }

   /* handle zero */
   if (z == 0) {
      z = 1;
   }

   /* see if msb is set */
   z += (num&(1UL<<((z<<3) - 1))) ? 1 : 0;

   /* adjust the number so the msB is non-zero */
   for (x = 0; (z <= 4) && (x < (4 - z)); x++) {
      num <<= 8;
   }

   /* store header */
   x = 0;
   out[x++] = 0x02;
   out[x++] = (unsigned char)z;

   /* if 31st bit is set output a leading zero and decrement count */
   if (z == 5) {
      out[x++] = 0;
      --z;
   }

   /* store values */
   for (y = 0; y < z; y++) {
      out[x++] = (unsigned char)((num >> 24) & 0xFF);
      num    <<= 8;
   }

   /* we good */
   *outlen = x;
 
   return CRYPT_OK;
}

/**
  Read a short integer
  @param in       The DER encoded data
  @param inlen    Size of data
  @param num      [out] The integer to decode
  @return CRYPT_OK if successful
*/
int der_decode_short_integer(const unsigned char *in, unsigned long inlen, unsigned long *num)
{
   unsigned long len, x, y;

   LTC_ARGCHK(num    != NULL);
   LTC_ARGCHK(in     != NULL);

   /* check length */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* check header */
   x = 0;
   if ((in[x++] & 0x1F) != 0x02) {
      return CRYPT_INVALID_PACKET;
   }

   /* get the packet len */
   len = in[x++];

   if (x + len > inlen) {
      return CRYPT_INVALID_PACKET;
   }

   /* read number */
   y = 0;
   while (len--) {
      y = (y<<8) | (unsigned long)in[x++];
   }
   *num = y;

   return CRYPT_OK;

}

/**
  Gets length of DER encoding of num 
  @param num    The integer to get the size of 
  @param outlen [out] The length of the DER encoding for the given integer
  @return CRYPT_OK if successful
*/
int der_length_short_integer(unsigned long num, unsigned long *outlen)
{
   unsigned long z, y, len;

   LTC_ARGCHK(outlen  != NULL);

   /* force to 32 bits */
   num &= 0xFFFFFFFFUL;

   /* get the number of bytes */
   z = 0;
   y = num;
   while (y) {
     ++z;
     y >>= 8;
   }
   
   /* handle zero */
   if (z == 0) {
      z = 1;
   }

   /* we need a 0x02 to indicate it's INTEGER */
   len = 1;

   /* length byte */
   ++len;

   /* bytes in value */
   len += z;

   /* see if msb is set */
   len += (num&(1UL<<((z<<3) - 1))) ? 1 : 0;

   /* return length */
   *outlen = len; 
   
   return CRYPT_OK;
}

/**
   Encode a SEQUENCE
   @param list      The list of items to encode
   @param inlen     The number of items in the list
   @param out       [out] The destination 
   @param outlen    [in/out] The size of the output
   @param type_of   LTC_ASN1_SEQUENCE or LTC_ASN1_SET/LTC_ASN1_SETOF
   @return CRYPT_OK on success
*/
int der_encode_sequence_ex(ltc_asn1_list *list, unsigned long inlen,
                           unsigned char *out,  unsigned long *outlen, int type_of) 
{
   int           err, type;
   unsigned long size, x, y, z, i;
   void          *data;

   LTC_ARGCHK(list    != NULL);
   LTC_ARGCHK(out     != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* get size of output that will be required */
   y = 0;
   for (i = 0; i < inlen; i++) {
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
            case LTC_ASN1_BOOLEAN:
               if ((err = der_length_boolean(&x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_INTEGER:
               if ((err = der_length_integer(data, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_SHORT_INTEGER:
               if ((err = der_length_short_integer(*((unsigned long*)data), &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_BIT_STRING:
               if ((err = der_length_bit_string(size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_OCTET_STRING:
               if ((err = der_length_octet_string(size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_NULL:
               y += 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               if ((err = der_length_object_identifier(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_IA5_STRING:
               if ((err = der_length_ia5_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_PRINTABLE_STRING:
               if ((err = der_length_printable_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_UTF8_STRING:
               if ((err = der_length_utf8_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_UTCTIME:
               if ((err = der_length_utctime(data, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               if ((err = der_length_sequence(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;
          
           default:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
   }

   /* calc header size */
   z = y;
   if (y < 128) {
      y += 2;
   } else if (y < 256) {
      /* 0x30 0x81 LL */
      y += 3;
   } else if (y < 65536UL) {
      /* 0x30 0x82 LL LL */
      y += 4;
   } else if (y < 16777216UL) {
      /* 0x30 0x83 LL LL LL */
      y += 5;
   } else {
      err = CRYPT_INVALID_ARG;
      goto LBL_ERR;
   }

   /* too big ? */
   if (*outlen < y) {
      *outlen = y;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* store header */
   x = 0;
   out[x++] = (type_of == LTC_ASN1_SEQUENCE) ? 0x30 : 0x31;
      
   if (z < 128) {
      out[x++] = (unsigned char)z;
   } else if (z < 256) {
      out[x++] = 0x81;
      out[x++] = (unsigned char)z;
   } else if (z < 65536UL) {
      out[x++] = 0x82;
      out[x++] = (unsigned char)((z>>8UL)&255);
      out[x++] = (unsigned char)(z&255);
   } else if (z < 16777216UL) {
      out[x++] = 0x83;
      out[x++] = (unsigned char)((z>>16UL)&255);
      out[x++] = (unsigned char)((z>>8UL)&255);
      out[x++] = (unsigned char)(z&255);
   }

   /* store data */
   *outlen -= x;
   for (i = 0; i < inlen; i++) {
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
            case LTC_ASN1_BOOLEAN:
               z = *outlen;
               if ((err = der_encode_boolean(*((int *)data), out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;
          
           case LTC_ASN1_INTEGER:
               z = *outlen;
               if ((err = der_encode_integer(data, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_SHORT_INTEGER:
               z = *outlen;
               if ((err = der_encode_short_integer(*((unsigned long*)data), out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_BIT_STRING:
               z = *outlen;
               if ((err = der_encode_bit_string(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_OCTET_STRING:
               z = *outlen;
               if ((err = der_encode_octet_string(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_NULL:
               out[x++] = 0x05;
               out[x++] = 0x00;
               *outlen -= 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               z = *outlen;
               if ((err = der_encode_object_identifier(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_IA5_STRING:
               z = *outlen;
               if ((err = der_encode_ia5_string(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;
          
           case LTC_ASN1_PRINTABLE_STRING:
               z = *outlen;
               if ((err = der_encode_printable_string(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_UTF8_STRING:
               z = *outlen;
               if ((err = der_encode_utf8_string(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_UTCTIME:
               z = *outlen;
               if ((err = der_encode_utctime(data, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_SET:
               z = *outlen;
               if ((err = der_encode_set(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_SETOF:
               z = *outlen;
               if ((err = der_encode_setof(data, size, out + x, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;

           case LTC_ASN1_SEQUENCE:
               z = *outlen;
               if ((err = der_encode_sequence_ex(data, size, out + x, &z, type)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               x       += z;
               *outlen -= z;
               break;
           
           default:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
   }
   *outlen = x;
   err = CRYPT_OK;   

LBL_ERR:
   return err;
}

/**
   Decode a SEQUENCE
   @param in       The DER encoded input
   @param inlen    The size of the input
   @param list     The list of items to decode
   @param outlen   The number of items in the list
   @param ordered  Search an unordeded or ordered list
   @return CRYPT_OK on success
*/
int der_decode_sequence_ex(const unsigned char *in, unsigned long  inlen,
                           ltc_asn1_list *list,     unsigned long  outlen, int ordered)
{
   int           err, type;
   unsigned long size, x, y, z, i, blksize;
   void          *data;

   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(list != NULL);
   
   /* get blk size */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* sequence type? We allow 0x30 SEQUENCE and 0x31 SET since fundamentally they're the same structure */
   x = 0;
   if (in[x] != 0x30 && in[x] != 0x31) {
      return CRYPT_INVALID_PACKET;
   }
   ++x;

   if (in[x] < 128) {
      blksize = in[x++];
   } else if (in[x] & 0x80) {
      if (in[x] < 0x81 || in[x] > 0x83) {
         return CRYPT_INVALID_PACKET;
      }
      y = in[x++] & 0x7F;

      /* would reading the len bytes overrun? */
      if (x + y > inlen) {
         return CRYPT_INVALID_PACKET;
      }

      /* read len */
      blksize = 0;
      while (y--) {
          blksize = (blksize << 8) | (unsigned long)in[x++];
      }
  }

  /* would this blksize overflow? */
  if (x + blksize > inlen) {
     return CRYPT_INVALID_PACKET;
  }

   /* mark all as unused */
   for (i = 0; i < outlen; i++) {
       list[i].used = 0;
   }     

  /* ok read data */
   inlen = blksize;
   for (i = 0; i < outlen; i++) {
       z    = 0;
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;
       if (!ordered && list[i].used == 1) { continue; }

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
               z = inlen;
               if ((err = der_decode_boolean(in + x, z, ((int *)data))) != CRYPT_OK) {
                   goto LBL_ERR;
               }
               if ((err = der_length_boolean(&z)) != CRYPT_OK) {
                   goto LBL_ERR;
                }
                break;
          
           case LTC_ASN1_INTEGER:
               z = inlen;
               if ((err = der_decode_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered) {  continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_integer(data, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SHORT_INTEGER:
               z = inlen;
               if ((err = der_decode_short_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_short_integer(((unsigned long*)data)[0], &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               
               break;

           case LTC_ASN1_BIT_STRING:
               z = inlen;
               if ((err = der_decode_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_OCTET_STRING:
               z = inlen;
               if ((err = der_decode_octet_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_octet_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_NULL:
               if (inlen < 2 || in[x] != 0x05 || in[x+1] != 0x00) {
                  if (!ordered) { continue; }
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }
               z = 2;
               break;
                  
           case LTC_ASN1_OBJECT_IDENTIFIER:
               z = inlen;
               if ((err = der_decode_object_identifier(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_object_identifier(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_IA5_STRING:
               z = inlen;
               if ((err = der_decode_ia5_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_ia5_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;


           case LTC_ASN1_PRINTABLE_STRING:
               z = inlen;
               if ((err = der_decode_printable_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_printable_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTF8_STRING:
               z = inlen;
               if ((err = der_decode_utf8_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_utf8_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTCTIME:
               z = inlen;
               if ((err = der_decode_utctime(in + x, &z, data)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SET:
               z = inlen;
               if ((err = der_decode_set(in + x, z, data, size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;
           
           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               /* detect if we have the right type */
               if ((type == LTC_ASN1_SETOF && (in[x] & 0x3F) != 0x31) || (type == LTC_ASN1_SEQUENCE && (in[x] & 0x3F) != 0x30)) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }

               z = inlen;
               if ((err = der_decode_sequence(in + x, z, data, size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;


           case LTC_ASN1_CHOICE:
               z = inlen;
               if ((err = der_decode_choice(in + x, &z, data, size)) != CRYPT_OK) {
                  if (!ordered) { continue; }
                  goto LBL_ERR;
               }
               break;

           default:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
       x           += z;
       inlen       -= z;
       list[i].used = 1;
       if (!ordered) { 
          /* restart the decoder */
          i = -1;
       }          
   }
     
   for (i = 0; i < outlen; i++) {
      if (list[i].used == 0) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
      }
   }                
   err = CRYPT_OK;   

LBL_ERR:
   return err;
}

/**
   Get the length of a DER sequence 
   @param list   The sequences of items in the SEQUENCE
   @param inlen  The number of items
   @param outlen [out] The length required in octets to store it 
   @return CRYPT_OK on success
*/
int der_length_sequence(ltc_asn1_list *list, unsigned long inlen,
                        unsigned long *outlen) 
{
   int           err, type;
   unsigned long size, x, y, z, i;
   void          *data;

   LTC_ARGCHK(list    != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* get size of output that will be required */
   y = 0;
   for (i = 0; i < inlen; i++) {
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
              if ((err = der_length_boolean(&x)) != CRYPT_OK) {
                 goto LBL_ERR;
              }
              y += x;
              break;
          
           case LTC_ASN1_INTEGER:
               if ((err = der_length_integer(data, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_SHORT_INTEGER:
               if ((err = der_length_short_integer(*((unsigned long *)data), &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_BIT_STRING:
               if ((err = der_length_bit_string(size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_OCTET_STRING:
               if ((err = der_length_octet_string(size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_NULL:
               y += 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               if ((err = der_length_object_identifier(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_IA5_STRING:
               if ((err = der_length_ia5_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_PRINTABLE_STRING:
               if ((err = der_length_printable_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_UTCTIME:
               if ((err = der_length_utctime(data, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_UTF8_STRING:
               if ((err = der_length_utf8_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               if ((err = der_length_sequence(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

          
           default:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
   }

   /* calc header size */
   z = y;
   if (y < 128) {
      y += 2;
   } else if (y < 256) {
      /* 0x30 0x81 LL */
      y += 3;
   } else if (y < 65536UL) {
      /* 0x30 0x82 LL LL */
      y += 4;
   } else if (y < 16777216UL) {
      /* 0x30 0x83 LL LL LL */
      y += 5;
   } else {
      err = CRYPT_INVALID_ARG;
      goto LBL_ERR;
   }

   /* store size */
   *outlen = y;
   err     = CRYPT_OK;

LBL_ERR:
   return err;
}

/**
  Encode a SEQUENCE type using a VA list
  @param out    [out] Destination for data
  @param outlen [in/out] Length of buffer and resulting length of output
  @remark <...> is of the form <type, size, data> (int, unsigned long, void*)
  @return CRYPT_OK on success
*/  
int der_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...)
{
   int           err, type;
   unsigned long size, x;
   void          *data;
   va_list       args;
   ltc_asn1_list *list;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* get size of output that will be required */
   va_start(args, outlen);
   x = 0;
   for (;;) {
       type = va_arg(args, int);
       size = va_arg(args, unsigned long);
       data = va_arg(args, void*);

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
           case LTC_ASN1_INTEGER:
           case LTC_ASN1_SHORT_INTEGER:
           case LTC_ASN1_BIT_STRING:
           case LTC_ASN1_OCTET_STRING:
           case LTC_ASN1_NULL:
           case LTC_ASN1_OBJECT_IDENTIFIER:
           case LTC_ASN1_IA5_STRING:
           case LTC_ASN1_PRINTABLE_STRING:
           case LTC_ASN1_UTF8_STRING:
           case LTC_ASN1_UTCTIME:
           case LTC_ASN1_SEQUENCE:
           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
                ++x; 
                break;
          
           default:
               va_end(args);
               return CRYPT_INVALID_ARG;
       }
   }
   va_end(args);

   /* allocate structure for x elements */
   if (x == 0) {
      return CRYPT_NOP;
   }

   list = XCALLOC(sizeof(*list), x);
   if (list == NULL) {
      return CRYPT_MEM;
   }

   /* fill in the structure */
   va_start(args, outlen);
   x = 0;
   for (;;) {
       type = va_arg(args, int);
       size = va_arg(args, unsigned long);
       data = va_arg(args, void*);

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
           case LTC_ASN1_INTEGER:
           case LTC_ASN1_SHORT_INTEGER:
           case LTC_ASN1_BIT_STRING:
           case LTC_ASN1_OCTET_STRING:
           case LTC_ASN1_NULL:
           case LTC_ASN1_OBJECT_IDENTIFIER:
           case LTC_ASN1_IA5_STRING:
           case LTC_ASN1_PRINTABLE_STRING:
           case LTC_ASN1_UTF8_STRING:
           case LTC_ASN1_UTCTIME:
           case LTC_ASN1_SEQUENCE:
           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
                list[x].type   = type;
                list[x].size   = size;
                list[x++].data = data;
                break;
         
           default:
               va_end(args);
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
   }
   va_end(args);

   err = der_encode_sequence(list, x, out, outlen);   
LBL_ERR:
   XFREE(list);
   return err;
}

/**
  Decode a SEQUENCE type using a VA list
  @param in    Input buffer
  @param inlen Length of input in octets
  @remark <...> is of the form <type, size, data> (int, unsigned long, void*)
  @return CRYPT_OK on success
*/  
int der_decode_sequence_multi(const unsigned char *in, unsigned long inlen, ...)
{
   int           err, type;
   unsigned long size, x;
   void          *data;
   va_list       args;
   ltc_asn1_list *list;

   LTC_ARGCHK(in    != NULL);

   /* get size of output that will be required */
   va_start(args, inlen);
   x = 0;
   for (;;) {
       type = va_arg(args, int);
       size = va_arg(args, unsigned long);
       data = va_arg(args, void*);

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
           case LTC_ASN1_INTEGER:
           case LTC_ASN1_SHORT_INTEGER:
           case LTC_ASN1_BIT_STRING:
           case LTC_ASN1_OCTET_STRING:
           case LTC_ASN1_NULL:
           case LTC_ASN1_OBJECT_IDENTIFIER:
           case LTC_ASN1_IA5_STRING:
           case LTC_ASN1_PRINTABLE_STRING:
           case LTC_ASN1_UTF8_STRING:
           case LTC_ASN1_UTCTIME:
           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
           case LTC_ASN1_CHOICE:
                ++x; 
                break;
          
           default:
               va_end(args);
               return CRYPT_INVALID_ARG;
       }
   }
   va_end(args);

   /* allocate structure for x elements */
   if (x == 0) {
      return CRYPT_NOP;
   }

   list = XCALLOC(sizeof(*list), x);
   if (list == NULL) {
      return CRYPT_MEM;
   }

   /* fill in the structure */
   va_start(args, inlen);
   x = 0;
   for (;;) {
       type = va_arg(args, int);
       size = va_arg(args, unsigned long);
       data = va_arg(args, void*);

       if (type == LTC_ASN1_EOL) { 
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
           case LTC_ASN1_INTEGER:
           case LTC_ASN1_SHORT_INTEGER:
           case LTC_ASN1_BIT_STRING:
           case LTC_ASN1_OCTET_STRING:
           case LTC_ASN1_NULL:
           case LTC_ASN1_OBJECT_IDENTIFIER:
           case LTC_ASN1_IA5_STRING:
           case LTC_ASN1_PRINTABLE_STRING:
           case LTC_ASN1_UTF8_STRING:
           case LTC_ASN1_UTCTIME:
           case LTC_ASN1_SEQUENCE:
           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:          
           case LTC_ASN1_CHOICE:
                list[x].type   = type;
                list[x].size   = size;
                list[x++].data = data;
                break;
         
           default:
               va_end(args);
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
   }
   va_end(args);

   err = der_decode_sequence(in, inlen, list, x);
LBL_ERR:
   XFREE(list);
   return err;
}
