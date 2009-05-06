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

#include <stdio.h>
#include <gmp.h>

   /** initialize a bignum
     @param   a     The number to initialize
     @return  CRYPT_OK on success
   */
int mp_init(void **a)
{ 
   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(__mpz_struct));
   if (*a == NULL) {
      return CRYPT_MEM;
   }
   mpz_init(((__mpz_struct *)*a));
   return CRYPT_OK;
}

   /** deinit 
      @param   a    The number to free
      @return CRYPT_OK on success
   */
void mp_clear(void *a)
{
   LTC_ARGCHKVD(a != NULL);
   mpz_clear(a);
   XFREE(a);
}

   /** copy 
      @param   src   The number to copy from
      @param   dst   The number to write to 
      @return CRYPT_OK on success
   */
int mp_copy(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_set(b, a);
   return CRYPT_OK;
}

   /** set small constant 
      @param a    Number to write to
      @param n    Source upto bits_per_digit (actually meant for very small constants) 
      @return CRYPT_OK on succcess
   */
int mp_set_int(void *a, unsigned long b)
{
   LTC_ARGCHK(a != NULL);
   mpz_set_ui(((__mpz_struct *)a), b);
   return CRYPT_OK;
}

   /** compare two integers
     @param a   The left side integer
     @param b   The right side integer
     @return LTC_MP_LT if a < b, LTC_MP_GT if a > b and LTC_MP_EQ otherwise.  (signed comparison)
   */
int mp_compare(void *a, void *b)
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

   /** compare against int 
     @param a   The left side integer
     @param b   The right side integer (upto bits_per_digit)
     @return LTC_MP_LT if a < b, LTC_MP_GT if a > b and LTC_MP_EQ otherwise.  (signed comparison)
   */
int mp_cmp_d(void *a, unsigned long b)
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

   /** Count the number of bits used to represent the integer
     @param a   The integer to count
     @return The number of bits required to represent the integer
   */
int mp_count_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_sizeinbase(a, 2);
}

   /** Count the number of LSB bits which are zero 
     @param a   The integer to count
     @return The number of contiguous zero LSB bits
   */
int mp_cnt_lsb(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_scan1(a, 0);
}

   /** Compute a power of two
     @param a  The integer to store the power in
     @param n  The power of two you want to store (a = 2^n)
     @return CRYPT_OK on success
   */
int mp_2expt(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   mpz_set_ui(a, 0);
   mpz_setbit(a, n);
   return CRYPT_OK;
}

   /** get size as unsigned char string 
     @param a     The integer to get the size (when stored in array of octets)
     @return The length of the integer
   */
unsigned long mp_unsigned_bin_size(void *a)
{
   unsigned long t;
   LTC_ARGCHK(a != NULL);
   t = mpz_sizeinbase(a, 2);
   if (mpz_cmp_ui(((__mpz_struct *)a), 0) == 0) return 0;
   return (t>>3) + ((t&7)?1:0);
}

   /** store an integer as an array of octets 
     @param src   The integer to store
     @param dst   The buffer to store the integer in
     @return CRYPT_OK on success
   */
int mp_to_unsigned_bin(void *a, unsigned char *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_export(b, NULL, 1, 1, 1, 0, ((__mpz_struct*)a));
   return CRYPT_OK;
}

   /** read an array of octets and store as integer
     @param dst   The integer to load
     @param src   The array of octets 
     @param len   The number of octets 
     @return CRYPT_OK on success
   */
int mp_read_unsigned_bin(void *a, unsigned char *b, unsigned long len)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_import(a, len, 1, 1, 1, 0, b);
   return CRYPT_OK;
}

   /** add two integers 
     @param a   The first source integer
     @param b   The second source integer
     @param c   The destination of "a + b"
     @return CRYPT_OK on success
   */
int mp_add(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_add(c, a, b);
   return CRYPT_OK;
}

   /** subtract two integers 
     @param a   The first source integer
     @param b   The second source integer
     @param c   The destination of "a - b"
     @return CRYPT_OK on success
   */
int mp_sub(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_sub(c, a, b);
   return CRYPT_OK;
}

   /** subtract two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a - b"
     @return CRYPT_OK on success
   */
int mp_sub_d(void *a, unsigned long b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_sub_ui(c, a, b);
   return CRYPT_OK;
}

   /** multiply two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a * b"
     @return CRYPT_OK on success
   */
int mp_mul(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_mul(c, a, b);
   return CRYPT_OK;
}

   /** Divide an integer
     @param a    The dividend
     @param b    The divisor
     @param c    The quotient (can be NULL to signify don't care)
     @param d    The remainder (can be NULL to signify don't care)
     @return CRYPT_OK on success
   */
int mp_div(void *a, void *b, void *c, void *d)
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

int mp_mod(void *a, void *b, void *c)
{
   return mp_div(a, b, NULL, c);
}

   /** gcd 
      @param  a     The first integer
      @param  b     The second integer
      @param  c     The destination for (a, b)
      @return CRYPT_OK on success
   */
int mp_gcd(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_gcd(c, a, b);
   return CRYPT_OK;
}

   /** lcm 
      @param  a     The first integer
      @param  b     The second integer
      @param  c     The destination for [a, b]
      @return CRYPT_OK on success
   */
int mp_lcm(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_lcm(c, a, b);
   return CRYPT_OK;
}

   /** Modular multiplication
      @param  a     The first source
      @param  b     The second source 
      @param  c     The modulus
      @param  d     The destination (a*b mod c)
      @return CRYPT_OK on success
   */
int mp_mulmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_mul(d, a, b);
   mpz_mod(d, d, c);
   return CRYPT_OK;
}

   /** Modular inversion
      @param  a     The value to invert
      @param  b     The modulus 
      @param  c     The destination (1/a mod b)
      @return CRYPT_OK on success
   */
int mp_invmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_invert(c, a, b);
   return CRYPT_OK;
}

   /** Modular exponentiation
       @param a    The base integer
       @param b    The power (can be negative) integer
       @param c    The modulus integer
       @param d    The destination
       @return CRYPT_OK on success
   */
int mp_exptmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_powm(d, a, b, c);
   return CRYPT_OK;
}   

   /** Primality testing
       @param a     The integer to test
       @param b     The destination of the result (FP_YES if prime)
       @return CRYPT_OK on success
   */
int mp_prime_is_prime(void *a, int rounds, int *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = mpz_probab_prime_p(a, rounds) > 0 ? LTC_MP_YES : LTC_MP_NO;
   return CRYPT_OK;
}
