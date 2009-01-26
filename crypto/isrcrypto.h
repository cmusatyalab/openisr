#ifndef LIBISRCRYPTO_H
#define LIBISRCRYPTO_H

#include <stdint.h>

enum isrcry_result {
	ISRCRY_OK			= 0,
	ISRCRY_INVALID_ARGUMENT		= 1,
	ISRCRY_BAD_PADDING		= 2,
};

#define ISRCRY_AES_BLOCKSIZE 16
#define ISRCRY_BLOWFISH_BLOCKSIZE 8
#define ISRCRY_SHA1_DIGEST_SIZE 20
#define ISRCRY_MD5_DIGEST_SIZE 16

struct isrcry_aes_key {
	uint32_t eK[60], dK[60];
	int Nr;
};

struct isrcry_blowfish_key {
	uint32_t S[4][256];
	uint32_t K[18];
};

struct isrcry_sha1_ctx {
	uint32_t digest[5];
	uint64_t count;
	uint8_t block[64];
	unsigned index;
};

struct isrcry_md5_ctx {
	uint32_t digest[4];
	uint32_t count_l;
	uint32_t count_h;
	uint8_t block[64];
	unsigned index;
};

#define CIPHER(alg, mode, direction) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## direction ( \
				const unsigned char *in, unsigned long len, \
				unsigned char *out, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv);
#define ENCRYPT_PAD(alg, mode, pad) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## pad ## \
				_encrypt (const unsigned char *in, \
				unsigned long inlen, unsigned char *out, \
				unsigned long outlen, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv);
#define DECRYPT_PAD(alg, mode, pad) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## pad ## \
				_decrypt (const unsigned char *in, \
				unsigned long inlen, unsigned char *out, \
				unsigned long *outlen, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv);

CIPHER(aes, cbc, encrypt)
CIPHER(aes, cbc, decrypt)
CIPHER(blowfish, cbc, encrypt)
CIPHER(blowfish, cbc, decrypt)

ENCRYPT_PAD(aes, cbc, pkcs5)
DECRYPT_PAD(aes, cbc, pkcs5)
ENCRYPT_PAD(blowfish, cbc, pkcs5)
DECRYPT_PAD(blowfish, cbc, pkcs5)

#undef CIPHER
#undef ENCRYPT_PAD
#undef DECRYPT_PAD

enum isrcry_result isrcry_aes_init(const unsigned char *key, int keylen,
			struct isrcry_aes_key *skey);
enum isrcry_result isrcry_blowfish_init(const unsigned char *key, int keylen,
			struct isrcry_blowfish_key *skey);

void isrcry_sha1_init(struct isrcry_sha1_ctx *ctx);
void isrcry_sha1_update(struct isrcry_sha1_ctx *ctx,
			const unsigned char *buffer, unsigned length);
void isrcry_sha1_final(struct isrcry_sha1_ctx *ctx, unsigned char *digest);

void isrcry_md5_init(struct isrcry_md5_ctx *ctx);
void isrcry_md5_update(struct isrcry_md5_ctx *ctx, const unsigned char *buffer,
			unsigned length);
void isrcry_md5_final(struct isrcry_md5_ctx *ctx, unsigned char *digest);

const char *isrcry_strerror(enum isrcry_result result);

#endif
