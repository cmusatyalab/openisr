#include <stdio.h>
#include <string.h>
#include "isrcrypto.h"
#include "cipher.h"
#include "vectors.h"
#include "vectors_blowfish.h"
#include "vectors_aes.h"

int failed;

#define fail(fmt, args...) do {\
		printf("%s failed " fmt "\n", __func__, ## args); \
		failed++; \
	} while (0)

typedef enum isrcry_result (init_fn)(const unsigned char *key, int keylen,
			void *skey);
typedef enum isrcry_result (cipher_fn)(const unsigned char *in,
			unsigned char *out, void *skey);
typedef enum isrcry_result (cipher_mode_fn)(const unsigned char *in,
			unsigned long len, unsigned char *out,
			void *skey, unsigned char *iv);
typedef enum isrcry_result (encrypt_mode_pad_fn)(const unsigned char *in,
				unsigned long inlen, unsigned char *out,
				unsigned long outlen, void *skey,
				unsigned char *iv);
typedef enum isrcry_result (decrypt_mode_pad_fn)(const unsigned char *in,
				unsigned long inlen, unsigned char *out,
				unsigned long *outlen, void *skey,
				unsigned char *iv);

void ecb_test(const char *alg, const struct ecb_test *vectors,
			unsigned vec_count, init_fn *init,
			cipher_fn *encrypt, cipher_fn *decrypt,
			void *skey, unsigned blocksize)
{
	const struct ecb_test *test;
	enum isrcry_result ret;
	unsigned char buf[blocksize];
	unsigned n;

	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		ret = init(test->key, test->keylen, skey);
		if (ret) {
			fail("%s %u init %i", alg, n, ret);
			continue;
		}
		ret = encrypt(test->plain, buf, skey);
		if (ret)
			fail("%s %u encrypt %d", alg, n, ret);
		if (memcmp(buf, test->cipher, blocksize))
			fail("%s %u encrypt mismatch", alg, n);
		ret = decrypt(test->cipher, buf, skey);
		if (ret)
			fail("%s %u decrypt %d", alg, n, ret);
		if (memcmp(buf, test->plain, blocksize))
			fail("%s %u decrypt mismatch", alg, n);
	}
}

void chain_pad_test(const char *alg, const struct chain_test *vectors,
			unsigned vec_count, init_fn *init,
			encrypt_mode_pad_fn *encrypt,
			decrypt_mode_pad_fn *decrypt, void *skey,
			unsigned blocksize)
{
	const struct chain_test *test;
	enum isrcry_result ret;
	unsigned char buf[1024];
	unsigned char iv[blocksize];
	unsigned cipherlen;
	unsigned long outlen;
	unsigned n;

	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		ret = init(test->key, test->keylen, skey);
		if (ret) {
			fail("%s %u init %d", alg, n, ret);
			continue;
		}
		memcpy(iv, test->iv, blocksize);
		ret = encrypt(test->plain, test->plainlen, buf, sizeof(buf),
					skey, iv);
		if (ret)
			fail("%s %u encrypt %d", alg, n, ret);
		cipherlen = test->plainlen + (blocksize -
					(test->plainlen % blocksize));
		if (memcmp(buf, test->cipher, cipherlen))
			fail("%s %u encrypt mismatch", alg, n);
		memcpy(iv, test->iv, blocksize);
		ret = decrypt(test->cipher, cipherlen, buf, &outlen,
					skey, iv);
		if (ret)
			fail("%s %u decrypt %d", alg, n, ret);
		if (outlen != test->plainlen)
			fail("%s %u decrypt length mismatch", alg, n);
		if (memcmp(buf, test->plain, test->plainlen))
			fail("%s %u decrypt mismatch", alg, n);
	}
}

void aes_monte_test(void)
{
	unsigned blocksize = ISRCRY_AES_BLOCKSIZE;
	const struct monte_test *test;
	struct isrcry_aes_key akey;
	unsigned n;
	unsigned m;
	unsigned l;
	uint8_t key[32];
	uint8_t buf[2 * blocksize];
	uint8_t *in = buf;
	uint8_t *out = buf + blocksize;
	enum isrcry_result ret;

	for (n = 0; n < MEMBERS(aes_monte_vectors); n++) {
		test = &aes_monte_vectors[n];
		memset(key, 0, test->keylen);
		memset(buf, 0, sizeof(buf));
		for (m = 0; m < test->ngroups; m++) {
			ret = isrcry_aes_init(key, test->keylen, &akey);
			if (ret) {
				fail("%u init %u", n, m);
				break;
			}
			for (l = 0; l < 10000; l++) {
				memcpy(in, out, blocksize);
				if (test->encrypt)
					ret = _isrcry_aes_encrypt(in, out,
								&akey);
				else
					ret = _isrcry_aes_decrypt(in, out,
								&akey);
				if (ret) {
					fail("%u crypt %u %u", n, m, l);
					break;
				}
				/* buf now holds the last two ciphertexts */
			}
			for (l = 0; l < test->keylen; l++)
				key[l] ^= buf[l + 32 - test->keylen];
		}
		if (memcmp(out, test->out, blocksize))
			fail("%u result mismatch", n);
	}
}

void chain_test(const char *alg, const struct chain_test *vectors,
			unsigned vec_count, init_fn *init,
			cipher_mode_fn *encrypt, cipher_mode_fn *decrypt,
			void *skey, unsigned blocksize)
{
	const struct chain_test *test;
	enum isrcry_result ret;
	unsigned char buf[1024];
	unsigned char iv[blocksize];
	unsigned n;

	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		ret = init(test->key, test->keylen, skey);
		if (ret) {
			fail("%s %u init %d", alg, n, ret);
			continue;
		}
		memcpy(iv, test->iv, blocksize);
		ret = encrypt(test->plain, test->plainlen, buf, skey, iv);
		if (ret)
			fail("%s %u encrypt %d", alg, n, ret);
		if (memcmp(buf, test->cipher, test->plainlen))
			fail("%s %u encrypt mismatch", alg, n);
		memcpy(iv, test->iv, blocksize);
		ret = decrypt(test->cipher, test->plainlen, buf, skey, iv);
		if (ret)
			fail("%s %u decrypt %d", alg, n, ret);
		if (memcmp(buf, test->plain, test->plainlen))
			fail("%s %u decrypt mismatch", alg, n);
	}
}

int main(int argc, char **argv)
{
	struct isrcry_aes_key akey;
	struct isrcry_blowfish_key bfkey;

	ecb_test("bf", blowfish_ecb_vectors, MEMBERS(blowfish_ecb_vectors),
				(init_fn *) isrcry_blowfish_init,
				(cipher_fn *) _isrcry_blowfish_encrypt,
				(cipher_fn *) _isrcry_blowfish_decrypt,
				&bfkey, ISRCRY_BLOWFISH_BLOCKSIZE);
	chain_pad_test("bf", blowfish_cbc_vectors,
				MEMBERS(blowfish_cbc_vectors),
				(init_fn *) isrcry_blowfish_init,
				(encrypt_mode_pad_fn *)
				isrcry_blowfish_cbc_pkcs5_encrypt,
				(decrypt_mode_pad_fn *)
				isrcry_blowfish_cbc_pkcs5_decrypt,
				&bfkey, ISRCRY_BLOWFISH_BLOCKSIZE);
	ecb_test("aes", aes_ecb_vectors, MEMBERS(aes_ecb_vectors),
				(init_fn *) isrcry_aes_init,
				(cipher_fn *) _isrcry_aes_encrypt,
				(cipher_fn *) _isrcry_aes_decrypt,
				&akey, ISRCRY_AES_BLOCKSIZE);
	aes_monte_test();
	chain_test("aes", aes_cbc_vectors, MEMBERS(aes_cbc_vectors),
				(init_fn *) isrcry_aes_init,
				(cipher_mode_fn *) isrcry_aes_cbc_encrypt,
				(cipher_mode_fn *) isrcry_aes_cbc_decrypt,
				&akey, ISRCRY_AES_BLOCKSIZE);

	if (failed) {
		printf("%d tests failed\n", failed);
		return 1;
	} else {
		printf("All tests passed\n");
		return 0;
	}
}
