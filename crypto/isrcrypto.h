#ifndef LIBISRCRYPTO_H
#define LIBISRCRYPTO_H

enum isrcry_result {
	ISRCRY_OK			= 0,
	ISRCRY_INVALID_ARGUMENT		= 1,
};

#define ISRCRY_AES_BLOCKSIZE 16
#define ISRCRY_BLOWFISH_BLOCKSIZE 8

struct isrcry_aes_key {
	ulong32 eK[60], dK[60];
	int Nr;
};

struct isrcry_blowfish_key {
	ulong32 S[4][256];
	ulong32 K[18];
};

#define CIPHER(alg, mode, direction) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## direction ( \
				const unsigned char *in, unsigned long len,
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

#endif
