#include <stdio.h>
#include <string.h>
#include "isrcrypto.h"
#include "cipher.h"
#include "vectors.h"
#include "vectors_blowfish.h"

int failed;

#define fail(fmt, args...) do {\
		printf("%s failed " fmt "\n", __func__, ## args); \
		failed++; \
	} while (0)

void bf_ecb_test(void)
{
	unsigned blocksize = ISRCRY_BLOWFISH_BLOCKSIZE;
	const struct ecb_test *test;
	struct isrcry_blowfish_key bfkey;
	enum isrcry_result ret;
	unsigned char buf[blocksize];
	unsigned n;

	for (n = 0; n < MEMBERS(blowfish_ecb_vectors); n++) {
		test = &blowfish_ecb_vectors[n];
		ret = isrcry_blowfish_init(test->key, blocksize, &bfkey);
		if (ret) {
			fail("%u init %i", n, ret);
			continue;
		}
		ret = _isrcry_blowfish_encrypt(test->plain, buf, &bfkey);
		if (ret)
			fail("%u encrypt %d", n, ret);
		if (memcmp(buf, test->cipher, blocksize))
			fail("%u encrypt mismatch", n);
		ret = _isrcry_blowfish_decrypt(test->cipher, buf, &bfkey);
		if (ret)
			fail("%u decrypt %d", n, ret);
		if (memcmp(buf, test->plain, blocksize))
			fail("%u decrypt mismatch", n);
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

int main(int argc, char **argv)
{
	bf_ecb_test();
	bf_key_test();
	bf_cbc_test();

	if (failed) {
		printf("%d tests failed\n", failed);
		return 1;
	} else {
		printf("All tests passed\n");
		return 0;
	}
}
