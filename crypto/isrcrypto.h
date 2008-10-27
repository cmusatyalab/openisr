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

/** A block cipher CBC structure */
typedef struct {
   /** The index of the cipher chosen */
   int                 cipher, 
   /** The block size of the given cipher */                        
                       blocklen;
   /** The current IV */
   unsigned char       IV[MAXBLOCKSIZE];
   /** The scheduled key */
   symmetric_key       key;
} symmetric_CBC;

#endif
