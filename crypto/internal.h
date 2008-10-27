#ifndef LIBISRCRYPTO_DEFS_H
#define LIBISRCRYPTO_DEFS_H

#ifndef LIBISRCRYPTO_INTERNAL
#error This header is for internal use by libisrcrypto
#endif

int (cipher_fn)(const unsigned char *in, unsigned char *out, void *skey)

#endif
