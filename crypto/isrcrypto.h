#ifndef LIBISRCRYPTO_H
#define LIBISRCRYPTO_H

struct isrcry_aes_key {
   ulong32 eK[60], dK[60];
   int Nr;
};

struct isrcry_blowfish_key {
   ulong32 S[4][256];
   ulong32 K[18];
};

#endif
