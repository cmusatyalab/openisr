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

#define DESC_DEF_ONLY
#include "tomcrypt.h"

#ifdef GMP_DESC

#include <stdio.h>
#include <gmp.h>

static int init(void **a)
{ 
   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(__mpz_struct));
   if (*a == NULL) {
      return CRYPT_MEM;
   }
   mpz_init(((__mpz_struct *)*a));
   return CRYPT_OK;
}

static void deinit(void *a)
{
   LTC_ARGCHKVD(a != NULL);
   mpz_clear(a);
   XFREE(a);
}

static int copy(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_set(b, a);
   return CRYPT_OK;
}

/* ---- trivial ---- */
static int set_int(void *a, unsigned long b)
{
   LTC_ARGCHK(a != NULL);
   mpz_set_ui(((__mpz_struct *)a), b);
   return CRYPT_OK;
}

static int compare(void *a, void *b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   ret = mpz_cmp(a, b);
   if (ret < 0) {
      return LTC_MP_LT;
   } else if (ret > 0) {
      return LTC_MP_GT;
   } else {
      return LTC_MP_EQ;
   }
}

static int compare_d(void *a, unsigned long b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   ret = mpz_cmp_ui(((__mpz_struct *)a), b);
   if (ret < 0) {
      return LTC_MP_LT;
   } else if (ret > 0) {
      return LTC_MP_GT;
   } else {
      return LTC_MP_EQ;
   }
}

static int count_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_sizeinbase(a, 2);
}

static int count_lsb_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_scan1(a, 0);
}


static int twoexpt(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   mpz_set_ui(a, 0);
   mpz_setbit(a, n);
   return CRYPT_OK;
}

/* ---- conversions ---- */

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
   unsigned long t;
   LTC_ARGCHK(a != NULL);
   t = mpz_sizeinbase(a, 2);
   if (mpz_cmp_ui(((__mpz_struct *)a), 0) == 0) return 0;
   return (t>>3) + ((t&7)?1:0);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_export(b, NULL, 1, 1, 1, 0, ((__mpz_struct*)a));
   return CRYPT_OK;
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_import(a, len, 1, 1, 1, 0, b);
   return CRYPT_OK;
}

/* add */
static int add(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_add(c, a, b);
   return CRYPT_OK;
}

/* sub */
static int sub(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_sub(c, a, b);
   return CRYPT_OK;
}

static int subi(void *a, unsigned long b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_sub_ui(c, a, b);
   return CRYPT_OK;
}

/* mul */
static int mul(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_mul(c, a, b);
   return CRYPT_OK;
}

static int divide(void *a, void *b, void *c, void *d)
{
   mpz_t tmp;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   if (c != NULL) {
      mpz_init(tmp);
      mpz_divexact(tmp, a, b);
   }
   if (d != NULL) {
      mpz_mod(d, a, b);
   }
   if (c != NULL) {
      mpz_set(c, tmp);
      mpz_clear(tmp);
   }
   return CRYPT_OK;
}

/* gcd */
static int gcd(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_gcd(c, a, b);
   return CRYPT_OK;
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_lcm(c, a, b);
   return CRYPT_OK;
}

static int mulmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_mul(d, a, b);
   mpz_mod(d, d, c);
   return CRYPT_OK;
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_invert(c, a, b);
   return CRYPT_OK;
}

static int exptmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_powm(d, a, b, c);
   return CRYPT_OK;
}   

static int isprime(void *a, int *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = mpz_probab_prime_p(a, 8) > 0 ? LTC_MP_YES : LTC_MP_NO;
   return CRYPT_OK;
}

const ltc_math_descriptor gmp_desc = {
   "GNU MP",
   sizeof(mp_limb_t) * CHAR_BIT - GMP_NAIL_BITS,

   &init,
   &init_copy,
   &deinit,

   &neg,
   &copy,

   &set_int,
   &get_int,
   &get_digit,
   &get_digit_count,
   &compare,
   &compare_d,
   &count_bits,
   &count_lsb_bits,
   &twoexpt,

   &read_radix,
   &write_radix,
   &unsigned_size,
   &unsigned_write,
   &unsigned_read,

   &add,
   &addi,
   &sub,
   &subi,
   &mul,
   &muli,
   &sqr,
   &divide,
   &div_2,
   &modi,
   &gcd,
   &lcm,

   &mulmod,
   &sqrmod,
   &invmod,

   &montgomery_setup,
   &montgomery_normalization,
   &montgomery_reduce,
   &montgomery_deinit,

   &exptmod,
   &isprime,

#ifdef MECC
#ifdef MECC_FP
   &ltc_ecc_fp_mulmod,
#else
   &ltc_ecc_mulmod,
#endif /* MECC_FP */
   &ltc_ecc_projective_add_point,
   &ltc_ecc_projective_dbl_point,
   &ltc_ecc_map,
#ifdef LTC_ECC_SHAMIR
#ifdef MECC_FP
   &ltc_ecc_fp_mul2add,
#else
   &ltc_ecc_mul2add,
#endif /* MECC_FP */
#else
   NULL,
#endif /* LTC_ECC_SHAMIR */
#else
   NULL, NULL, NULL, NULL, NULL
#endif /* MECC */

#ifdef MRSA
   &rsa_make_key,
   &rsa_exptmod,
#else
   NULL, NULL
#endif
   
};


#endif

/* $Source: /cvs/libtom/libtomcrypt/src/math/gmp_desc.c,v $ */
/* $Revision: 1.14 $ */
/* $Date: 2006/12/03 00:39:56 $ */
