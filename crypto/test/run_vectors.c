/*
 * libisrcrypto - cryptographic library for the OpenISR (R) system
 *
 * Copyright (C) 2008-2009 Carnegie Mellon University
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.  A copy of the GNU Lesser General
 * Public License should have been distributed along with this library in the
 * file LICENSE.LGPL.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 */

#include <stdio.h>
#include <string.h>
#include "isrcrypto.h"
#include "cipher.h"
#include "vectors.h"
#include "vectors_blowfish.h"
#include "vectors_aes.h"
#include "vectors_sha1.h"
#include "vectors_md5.h"

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
typedef void (hash_init_fn)(void *ctx);
typedef void (hash_update_fn)(void *ctx, const unsigned char *buffer,
			unsigned length);
typedef void (hash_final_fn)(void *ctx, unsigned char *digest);

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

void monte_test(const char *alg, const struct monte_test *vectors,
			unsigned vec_count, init_fn *init,
			cipher_fn *encrypt, cipher_fn *decrypt,
			void *skey, unsigned blocksize)
{
	const struct monte_test *test;
	unsigned n;
	unsigned m;
	unsigned l;
	uint8_t key[32];
	uint8_t buf[2 * blocksize];
	uint8_t *in = buf;
	uint8_t *out = buf + blocksize;
	enum isrcry_result ret;

	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		memset(key, 0, test->keylen);
		memset(buf, 0, sizeof(buf));
		for (m = 0; m < test->ngroups; m++) {
			ret = init(key, test->keylen, skey);
			if (ret) {
				fail("%s %u init %u", alg, n, m);
				break;
			}
			for (l = 0; l < test->niters; l++) {
				memcpy(in, out, blocksize);
				if (test->encrypt)
					ret = encrypt(in, out, skey);
				else
					ret = decrypt(in, out, skey);
				if (ret) {
					fail("%s %u crypt %u %u", alg, n, m, l);
					break;
				}
				/* buf now holds the last two ciphertexts */
			}
			for (l = 0; l < test->keylen; l++)
				key[l] ^= buf[l + 32 - test->keylen];
		}
		if (memcmp(out, test->out, blocksize))
			fail("%s %u result mismatch", alg, n);
	}
}

void hash_test(const char *alg, enum isrcry_hash type,
			const struct hash_test *vectors, unsigned vec_count)
{
	struct isrcry_hash_ctx *ctx;
	const struct hash_test *test;
	uint8_t out[64];
	unsigned n;
	unsigned hashlen;

	ctx = isrcry_hash_alloc(type);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	hashlen = isrcry_hash_len(type);
	if (hashlen < 16 || hashlen > 64)
		fail("%s invalid hashlen", alg);
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		isrcry_hash_init(ctx);
		isrcry_hash_update(ctx, test->data, test->len);
		isrcry_hash_final(ctx, out);
		if (memcmp(out, test->hash, hashlen))
			fail("%s %u result mismatch", alg, n);
	}
	isrcry_hash_free(ctx);
}

void hash_simple_monte_test(const char *alg, enum isrcry_hash type,
			const struct hash_monte_test *vectors,
			unsigned vec_count)
{
	struct isrcry_hash_ctx *ctx;
	const struct hash_monte_test *test;
	uint8_t buf[64];
	unsigned n;
	unsigned m;
	unsigned hashlen;

	ctx = isrcry_hash_alloc(type);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	hashlen = isrcry_hash_len(type);
	if (hashlen < 16 || hashlen > 64)
		fail("%s invalid hashlen", alg);
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		memcpy(buf, test->seed, hashlen);
		if (test->ngroups != 1)
			fail("%s %u invalid vector", alg, n);
		for (m = 0; m < test->niters; m++) {
			isrcry_hash_init(ctx);
			isrcry_hash_update(ctx, buf, hashlen);
			isrcry_hash_final(ctx, buf);
		}
		if (memcmp(buf, test->hash, hashlen))
			fail("%s %u result mismatch", alg, n);
	}
	isrcry_hash_free(ctx);
}

void hash_monte_test(const char *alg, enum isrcry_hash type,
			const struct hash_monte_test *vectors,
			unsigned vec_count)
{
	struct isrcry_hash_ctx *ctx;
	const struct hash_monte_test *test;
	uint8_t buf[192];
	uint8_t *out;
	unsigned n;
	unsigned m;
	unsigned l;
	unsigned hashlen;

	ctx = isrcry_hash_alloc(type);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	hashlen = isrcry_hash_len(type);
	if (hashlen < 16 || hashlen > 64)
		fail("%s invalid hashlen", alg);
	out = buf + 2 * hashlen;
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		memcpy(out, test->seed, hashlen);
		for (m = 0; m < test->ngroups; m++) {
			for (l = 0; l < 2; l++)
				memcpy(buf + l * hashlen, out, hashlen);
			for (l = 0; l < test->niters; l++) {
				isrcry_hash_init(ctx);
				isrcry_hash_update(ctx, buf, 3 * hashlen);
				memmove(buf, buf + hashlen, 2 * hashlen);
				isrcry_hash_final(ctx, out);
			}
		}
		if (memcmp(out, test->hash, hashlen))
			fail("%s %u result mismatch", alg, n);
	}
	isrcry_hash_free(ctx);
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
	monte_test("aes", aes_monte_vectors, MEMBERS(aes_monte_vectors),
				(init_fn *) isrcry_aes_init,
				(cipher_fn *) _isrcry_aes_encrypt,
				(cipher_fn *) _isrcry_aes_decrypt,
				&akey, ISRCRY_AES_BLOCKSIZE);
	chain_test("aes", aes_cbc_vectors, MEMBERS(aes_cbc_vectors),
				(init_fn *) isrcry_aes_init,
				(cipher_mode_fn *) isrcry_aes_cbc_encrypt,
				(cipher_mode_fn *) isrcry_aes_cbc_decrypt,
				&akey, ISRCRY_AES_BLOCKSIZE);
	hash_test("sha1", ISRCRY_HASH_SHA1, sha1_hash_vectors,
				MEMBERS(sha1_hash_vectors));
	hash_monte_test("sha1", ISRCRY_HASH_SHA1, sha1_monte_vectors,
				MEMBERS(sha1_monte_vectors));
	hash_test("md5", ISRCRY_HASH_MD5, md5_hash_vectors,
				MEMBERS(md5_hash_vectors));
	hash_simple_monte_test("md5", ISRCRY_HASH_MD5, md5_monte_vectors,
				MEMBERS(md5_monte_vectors));

	if (failed) {
		printf("%d tests failed\n", failed);
		return 1;
	} else {
		printf("All tests passed\n");
		return 0;
	}
}
