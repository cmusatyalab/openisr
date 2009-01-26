#ifndef LIBISRCRYPTO_DEFS_H
#define LIBISRCRYPTO_DEFS_H

#ifndef LIBISRCRYPTO_INTERNAL
#error This header is for internal use by libisrcrypto
#endif

#include <string.h>
#include "config.h"
#include "cipher.h"

#ifdef HAVE_VISIBILITY
#define exported __attribute__ ((visibility ("default")))
#else
#define exported
#endif

typedef enum isrcry_result (cipher_fn)(const unsigned char *in,
			unsigned char *out, void *skey);
typedef enum isrcry_result (mode_fn)(const unsigned char *in,
			unsigned long len, unsigned char *out,
			cipher_fn *encrypt, unsigned blocklen, void *key,
			unsigned char *iv);
typedef enum isrcry_result (pad_fn)(unsigned char *buf, unsigned blocklen,
			unsigned datalen);
typedef enum isrcry_result (unpad_fn)(unsigned char *buf, unsigned blocklen,
			unsigned *datalen);

enum isrcry_result _isrcry_cbc_encrypt(const unsigned char *in,
			unsigned long len, unsigned char *out,
			cipher_fn *encrypt, unsigned blocklen, void *key,
			unsigned char *iv);
enum isrcry_result _isrcry_cbc_decrypt(const unsigned char *in,
			unsigned long len, unsigned char *out,
			cipher_fn *decrypt, unsigned blocklen, void *key,
			unsigned char *iv);

enum isrcry_result _isrcry_pkcs5_pad(unsigned char *buf, unsigned blocklen,
			unsigned datalen);
enum isrcry_result _isrcry_pkcs5_unpad(unsigned char *buf, unsigned blocklen,
			unsigned *datalen);

/* Compression function. @state points to 5 u32 words, and @data points to
   64 bytes of input data, possibly unaligned. */
void _isrcry_sha1_compress(uint32_t *state, const uint8_t *data);

/* libtomcrypt helper defines */

/* Extract a byte portably */
#define byte(x, n) (((x) >> (8 * (n))) & 255)

#if defined(HAVE_X86_32) || defined(HAVE_X86_64)
#define ISRCRY_FAST_TYPE unsigned long
#define STORE32H(x, y)           \
asm __volatile__ (               \
   "bswapl %0     \n\t"          \
   "movl   %0,(%1)\n\t"          \
   "bswapl %0     \n\t"          \
      ::"r"(x), "r"(y));

#define LOAD32H(x, y)          \
asm __volatile__ (             \
   "movl (%1),%0\n\t"          \
   "bswapl %0\n\t"             \
   :"=r"(x): "r"(y));

#define STORE32L(x, y) \
	{ uint32_t __t = (x); memcpy((y), &__t, 4); }

#define LOAD32L(x, y) \
	memcpy(&(x), (y), 4)
#else
#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
           ((unsigned long)((y)[1] & 255)<<16) | \
           ((unsigned long)((y)[2] & 255)<<8)  | \
           ((unsigned long)((y)[3] & 255)); }

#define STORE32L(x, y)                                                                     \
     { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); }

#define LOAD32L(x, y)                            \
     { x = ((unsigned long)((y)[3] & 255)<<24) | \
           ((unsigned long)((y)[2] & 255)<<16) | \
           ((unsigned long)((y)[1] & 255)<<8)  | \
           ((unsigned long)((y)[0] & 255)); }
#endif

#endif
