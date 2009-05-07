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

#include <stdarg.h>
#include <stdlib.h>
#include <gmp.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

   /** initialize a bignum
     @param   a     The number to initialize
     @return  CRYPT_OK on success
   */
int mp_init(void **a)
{ 
   *a = malloc(sizeof(__mpz_struct));
   if (*a == NULL) {
      return -1;
   }
   mpz_init(((__mpz_struct *)*a));
   return 0;
}

   /** deinit 
      @param   a    The number to free
      @return CRYPT_OK on success
   */
void mp_clear(void *a)
{
   mpz_clear(a);
   free(a);
}

int mp_init_multi(void **a, ...)
{
   void    **cur = a;
   int       np  = 0;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       if (mp_init(cur)) {
          /* failed */
          va_list clean_list;

          va_start(clean_list, a);
          cur = a;
          while (np--) {
              mp_clear(*cur);
              cur = va_arg(clean_list, void**);
          }
          va_end(clean_list);
          return -1;
       }
       ++np;
       cur = va_arg(args, void**);
   }
   va_end(args);
   return 0;   
}

void mp_clear_multi(void *a, ...)
{
   void     *cur = a;
   va_list   args;

   va_start(args, a);
   while (cur != NULL) {
       mp_clear(cur);
       cur = va_arg(args, void *);
   }
   va_end(args);
}

   /** copy 
      @param   src   The number to copy from
      @param   dst   The number to write to 
   */
void mp_copy(void *a, void *b)
{
   mpz_set(b, a);
}

   /** set small constant 
      @param a    Number to write to
      @param n    Source upto bits_per_digit (actually meant for very small constants) 
   */
void mp_set_int(void *a, unsigned long b)
{
   mpz_set_ui(((__mpz_struct *)a), b);
}

   /** compare two integers
     @param a   The left side integer
     @param b   The right side integer
     @return < 0 if a < b, > 0 if a > b and 0 otherwise.  (signed comparison)
   */
int mp_compare(void *a, void *b)
{
   return mpz_cmp(a, b);
}

   /** compare against int 
     @param a   The left side integer
     @param b   The right side integer (upto bits_per_digit)
     @return < 0 if a < b, > 0 if a > b and 0 otherwise.  (signed comparison)
   */
int mp_cmp_d(void *a, unsigned long b)
{
   return mpz_cmp_ui(((__mpz_struct *)a), b);
}

   /** Count the number of bits used to represent the integer
     @param a   The integer to count
     @return The number of bits required to represent the integer
   */
int mp_count_bits(void *a)
{
   return mpz_sizeinbase(a, 2);
}

   /** Count the number of LSB bits which are zero 
     @param a   The integer to count
     @return The number of contiguous zero LSB bits
   */
int mp_cnt_lsb(void *a)
{
   return mpz_scan1(a, 0);
}

   /** Compute a power of two
     @param a  The integer to store the power in
     @param n  The power of two you want to store (a = 2^n)
   */
void mp_2expt(void *a, int n)
{
   mpz_set_ui(a, 0);
   mpz_setbit(a, n);
}

   /** get size as unsigned char string 
     @param a     The integer to get the size (when stored in array of octets)
     @return The length of the integer
   */
unsigned long mp_unsigned_bin_size(void *a)
{
   unsigned long t;
   t = mpz_sizeinbase(a, 2);
   if (mpz_cmp_ui(((__mpz_struct *)a), 0) == 0) return 0;
   return (t>>3) + ((t&7)?1:0);
}

   /** store an integer as an array of octets 
     @param src   The integer to store
     @param dst   The buffer to store the integer in
   */
void mp_to_unsigned_bin(void *a, unsigned char *b)
{
   mpz_export(b, NULL, 1, 1, 1, 0, ((__mpz_struct*)a));
}

   /** read an array of octets and store as integer
     @param dst   The integer to load
     @param src   The array of octets 
     @param len   The number of octets 
   */
void mp_read_unsigned_bin(void *a, unsigned char *b, unsigned long len)
{
   mpz_import(a, len, 1, 1, 1, 0, b);
}

   /** add two integers 
     @param a   The first source integer
     @param b   The second source integer
     @param c   The destination of "a + b"
   */
void mp_add(void *a, void *b, void *c)
{
   mpz_add(c, a, b);
}

   /** subtract two integers 
     @param a   The first source integer
     @param b   The second source integer
     @param c   The destination of "a - b"
   */
void mp_sub(void *a, void *b, void *c)
{
   mpz_sub(c, a, b);
}

   /** subtract two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a - b"
   */
void mp_sub_d(void *a, unsigned long b, void *c)
{
   mpz_sub_ui(c, a, b);
}

   /** multiply two integers 
     @param a   The first source integer
     @param b   The second source integer (single digit of upto bits_per_digit in length)
     @param c   The destination of "a * b"
   */
void mp_mul(void *a, void *b, void *c)
{
   mpz_mul(c, a, b);
}

   /** Divide an integer
     @param a    The dividend
     @param b    The divisor
     @param c    The quotient (can be NULL to signify don't care)
     @param d    The remainder (can be NULL to signify don't care)
   */
void mp_div(void *a, void *b, void *c, void *d)
{
   mpz_t tmp;
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
}

void mp_mod(void *a, void *b, void *c)
{
   mp_div(a, b, NULL, c);
}

   /** gcd 
      @param  a     The first integer
      @param  b     The second integer
      @param  c     The destination for (a, b)
   */
void mp_gcd(void *a, void *b, void *c)
{
   mpz_gcd(c, a, b);
}

   /** lcm 
      @param  a     The first integer
      @param  b     The second integer
      @param  c     The destination for [a, b]
   */
void mp_lcm(void *a, void *b, void *c)
{
   mpz_lcm(c, a, b);
}

   /** Modular multiplication
      @param  a     The first source
      @param  b     The second source 
      @param  c     The modulus
      @param  d     The destination (a*b mod c)
   */
void mp_mulmod(void *a, void *b, void *c, void *d)
{
   mpz_mul(d, a, b);
   mpz_mod(d, d, c);
}

   /** Modular inversion
      @param  a     The value to invert
      @param  b     The modulus 
      @param  c     The destination (1/a mod b)
      @return 0 on success
   */
int mp_invmod(void *a, void *b, void *c)
{
   return !mpz_invert(c, a, b);
}

   /** Modular exponentiation
       @param a    The base integer
       @param b    The power (can be negative) integer
       @param c    The modulus integer
       @param d    The destination
   */
void mp_exptmod(void *a, void *b, void *c, void *d)
{
   mpz_powm(d, a, b, c);
}   

   /** Primality testing
       @param a     The integer to test
       @param b     The destination of the result (1 if prime)
   */
void mp_prime_is_prime(void *a, int rounds, int *b)
{
   *b = mpz_probab_prime_p(a, rounds) > 0 ? 1 : 0;
}

int rand_prime(void *N, unsigned len, struct isrcry_random_ctx *rctx)
{
   int            res;
   unsigned char *buf;

   /* allow sizes between 2 and 512 bytes for a prime size */
   if (len < 2 || len > 512) { 
      return -1;
   }
   
   /* allocate buffer to work with */
   buf = malloc(len);
   if (buf == NULL) {
       return -1;
   }

   do {
      /* generate value */
      isrcry_random_bytes(rctx, buf, len);

      /* munge bits */
      buf[0]     |= 0x80 | 0x40;
      buf[len-1] |= 0x01;
 
      /* load value */
      mp_read_unsigned_bin(N, buf, len);

      /* test */
      mp_prime_is_prime(N, 8, &res);
   } while (!res);

   free(buf);
   return 0;
}
