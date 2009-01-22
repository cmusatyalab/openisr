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

void bf_key_test(void)
{
	unsigned blocksize = ISRCRY_BLOWFISH_BLOCKSIZE;
	const struct key_test *test;
	struct isrcry_blowfish_key bfkey;
	enum isrcry_result ret;
	unsigned char buf[blocksize];
	unsigned n;

	for (n = 0; n < blowfish_key_vectors.count; n++) {
		test = &blowfish_key_vectors.tests[n];
		ret = isrcry_blowfish_init(test->key, test->keylen, &bfkey);
		if (ret) {
			fail("%u init %i", n, ret);
			continue;
		}
		ret = _isrcry_blowfish_encrypt(blowfish_key_vectors.plain, buf,
					&bfkey);
		if (ret)
			fail("%u encrypt %d", n, ret);
		if (memcmp(buf, test->cipher, blocksize))
			fail("%u encrypt mismatch", n);
		ret = _isrcry_blowfish_decrypt(test->cipher, buf, &bfkey);
		if (ret)
			fail("%u decrypt %d", n, ret);
		if (memcmp(buf, blowfish_key_vectors.plain, blocksize))
			fail("%u decrypt mismatch", n);
	}
}

void bf_cbc_test(void)
{
	unsigned blocksize = ISRCRY_BLOWFISH_BLOCKSIZE;
	const struct chain_test *test;
	struct isrcry_blowfish_key bfkey;
	enum isrcry_result ret;
	unsigned char buf[1024];
	unsigned char iv[blocksize];
	unsigned cipherlen;
	unsigned long outlen;
	unsigned n;

	for (n = 0; n < MEMBERS(blowfish_cbc_vectors); n++) {
		test = &blowfish_cbc_vectors[n];
		ret = isrcry_blowfish_init(test->key, 16, &bfkey);
		if (ret) {
			fail("%u init %d", n, ret);
			continue;
		}
		memcpy(iv, test->iv, blocksize);
		ret = isrcry_blowfish_cbc_pkcs5_encrypt(test->plain,
					test->plainlen, buf, sizeof(buf),
					&bfkey, iv);
		if (ret)
			fail("%u encrypt %d", n, ret);
		cipherlen = test->plainlen + (blocksize -
					(test->plainlen % blocksize));
		if (memcmp(buf, test->cipher, cipherlen))
			fail("%u encrypt mismatch", n);
		memcpy(iv, test->iv, blocksize);
		ret = isrcry_blowfish_cbc_pkcs5_decrypt(test->cipher,
					cipherlen, buf, &outlen, &bfkey, iv);
		if (ret)
			fail("%u decrypt %d", n, ret);
		if (outlen != test->plainlen)
			fail("%u decrypt length mismatch", n);
		if (memcmp(buf, test->plain, test->plainlen))
			fail("%u decrypt mismatch", n);
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

void aes_cbc_test(void)
{
	unsigned blocksize = ISRCRY_AES_BLOCKSIZE;
	const struct chain_test *test;
	struct isrcry_aes_key akey;
	enum isrcry_result ret;
	unsigned char buf[1024];
	unsigned char iv[blocksize];
	unsigned n;

	for (n = 0; n < MEMBERS(aes_cbc_vectors); n++) {
		test = &aes_cbc_vectors[n];
		ret = isrcry_aes_init(test->key, 16, &akey);
		if (ret) {
			fail("%u init %d", n, ret);
			continue;
		}
		memcpy(iv, test->iv, blocksize);
		ret = isrcry_aes_cbc_encrypt(test->plain, test->plainlen,
					buf, &akey, iv);
		if (ret)
			fail("%u encrypt %d", n, ret);
		if (memcmp(buf, test->cipher, test->plainlen))
			fail("%u encrypt mismatch", n);
		memcpy(iv, test->iv, blocksize);
		ret = isrcry_aes_cbc_decrypt(test->cipher, test->plainlen,
					buf, &akey, iv);
		if (ret)
			fail("%u decrypt %d", n, ret);
		if (memcmp(buf, test->plain, test->plainlen))
			fail("%u decrypt mismatch", n);
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
	bf_key_test();
	bf_cbc_test();
	ecb_test("aes", aes_ecb_vectors, MEMBERS(aes_ecb_vectors),
				(init_fn *) isrcry_aes_init,
				(cipher_fn *) _isrcry_aes_encrypt,
				(cipher_fn *) _isrcry_aes_decrypt,
				&akey, ISRCRY_AES_BLOCKSIZE);
	aes_monte_test();
	aes_cbc_test();

	if (failed) {
		printf("%d tests failed\n", failed);
		return 1;
	} else {
		printf("All tests passed\n");
		return 0;
	}
}
