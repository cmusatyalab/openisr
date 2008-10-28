#ifndef LIBISRCRYPTO_H
#define LIBISRCRYPTO_H

#include <stdint.h>

enum isrcry_result {
	ISRCRY_OK			= 0,
	ISRCRY_INVALID_ARGUMENT		= 1,
};

#define ISRCRY_AES_BLOCKSIZE 16
#define ISRCRY_BLOWFISH_BLOCKSIZE 8

struct isrcry_aes_key {
	uint32_t eK[60], dK[60];
	int Nr;
};

struct isrcry_blowfish_key {
	uint32_t S[4][256];
	uint32_t K[18];
};

#define CIPHER(alg, mode, direction) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## direction ( \
				const unsigned char *in, unsigned long len, \
				unsigned char *out, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv);
CIPHER(aes, cbc, encrypt)
CIPHER(aes, cbc, decrypt)
CIPHER(blowfish, cbc, encrypt)
CIPHER(blowfish, cbc, decrypt)

enum isrcry_result isrcry_aes_init(const unsigned char *key, int keylen,
			struct isrcry_aes_key *skey);
enum isrcry_result isrcry_blowfish_init(const unsigned char *key, int keylen,
			struct isrcry_blowfish_key *skey);

const char *isrcry_strerror(enum isrcry_result result);

#endif
