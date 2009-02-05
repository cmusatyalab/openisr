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

void ecb_test(const char *alg, enum isrcry_cipher type,
			const struct ecb_test *vectors, unsigned vec_count)
{
	struct isrcry_cipher_ctx *ctx;
	const struct ecb_test *test;
	enum isrcry_result ret;
	unsigned char buf[32];
	unsigned n;
	unsigned blocksize;

	ctx = isrcry_cipher_alloc(type, ISRCRY_MODE_ECB);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	blocksize = isrcry_cipher_block(type);
	if (blocksize < 8 || blocksize > 16)
		fail("%s invalid blocksize", alg);
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		ret = isrcry_cipher_init(ctx, ISRCRY_ENCRYPT, test->key,
					test->keylen, NULL);
		if (ret) {
			fail("%s %u encrypt init %i", alg, n, ret);
			continue;
		}
		ret = isrcry_cipher_process(ctx, test->plain, blocksize, buf);
		if (ret)
			fail("%s %u encrypt %d", alg, n, ret);
		if (memcmp(buf, test->cipher, blocksize))
			fail("%s %u encrypt mismatch", alg, n);

		ret = isrcry_cipher_init(ctx, ISRCRY_DECRYPT, test->key,
					test->keylen, NULL);
		if (ret) {
			fail("%s %u decrypt init %i", alg, n, ret);
			continue;
		}
		ret = isrcry_cipher_process(ctx, test->cipher, blocksize, buf);
		if (ret)
			fail("%s %u decrypt %d", alg, n, ret);
		if (memcmp(buf, test->plain, blocksize))
			fail("%s %u decrypt mismatch", alg, n);
	}
	isrcry_cipher_free(ctx);
}

void chain_test(const char *alg, enum isrcry_cipher type,
			enum isrcry_mode mode,
			const struct chain_test *vectors, unsigned vec_count)
{
	struct isrcry_cipher_ctx *ctx;
	const struct chain_test *test;
	enum isrcry_result ret;
	unsigned char buf[1024];
	unsigned n;
	unsigned blocksize;

	ctx = isrcry_cipher_alloc(type, mode);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	blocksize = isrcry_cipher_block(type);
	if (blocksize < 8 || blocksize > 16)
		fail("%s invalid blocksize", alg);
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		ret = isrcry_cipher_init(ctx, ISRCRY_ENCRYPT, test->key,
					test->keylen, test->iv);
		if (ret) {
			fail("%s %u encrypt init %d", alg, n, ret);
			continue;
		}
		ret = isrcry_cipher_process(ctx, test->plain, test->plainlen,
					buf);
		if (ret)
			fail("%s %u encrypt %d", alg, n, ret);
		if (memcmp(buf, test->cipher, test->plainlen))
			fail("%s %u encrypt mismatch", alg, n);

		ret = isrcry_cipher_init(ctx, ISRCRY_DECRYPT, test->key,
					test->keylen, test->iv);
		if (ret) {
			fail("%s %u decrypt init %d", alg, n, ret);
			continue;
		}
		ret = isrcry_cipher_process(ctx, test->cipher, test->plainlen,
					buf);
		if (ret)
			fail("%s %u decrypt %d", alg, n, ret);
		if (memcmp(buf, test->plain, test->plainlen))
			fail("%s %u decrypt mismatch", alg, n);
	}
	isrcry_cipher_free(ctx);
}

void chain_pad_test(const char *alg, enum isrcry_cipher type,
			enum isrcry_mode mode, enum isrcry_padding pad,
			const struct chain_test *vectors, unsigned vec_count)
{
	struct isrcry_cipher_ctx *ctx;
	const struct chain_test *test;
	enum isrcry_result ret;
	unsigned char buf[1024];
	unsigned long outlen;
	unsigned n;
	unsigned blocksize;

	ctx = isrcry_cipher_alloc(type, mode);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	blocksize = isrcry_cipher_block(type);
	if (blocksize < 8 || blocksize > 16)
		fail("%s invalid blocksize", alg);
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		ret = isrcry_cipher_init(ctx, ISRCRY_ENCRYPT, test->key,
					test->keylen, test->iv);
		if (ret) {
			fail("%s %u encrypt init %d", alg, n, ret);
			continue;
		}
		outlen = sizeof(buf);
		ret = isrcry_cipher_final(ctx, pad, test->plain,
					test->plainlen, buf, &outlen);
		if (ret)
			fail("%s %u encrypt %d", alg, n, ret);
		if (outlen != test->plainlen + (blocksize -
					(test->plainlen % blocksize)))
			fail("%s %u encrypt invalid len %lu", alg, n, outlen);
		if (memcmp(buf, test->cipher, outlen))
			fail("%s %u encrypt mismatch", alg, n);

		ret = isrcry_cipher_init(ctx, ISRCRY_DECRYPT, test->key,
					test->keylen, test->iv);
		if (ret) {
			fail("%s %u decrypt init %d", alg, n, ret);
			continue;
		}
		ret = isrcry_cipher_final(ctx, pad, test->cipher, outlen,
					buf, &outlen);
		if (ret)
			fail("%s %u decrypt %d", alg, n, ret);
		if (outlen != test->plainlen)
			fail("%s %u decrypt length mismatch", alg, n);
		if (memcmp(buf, test->plain, test->plainlen))
			fail("%s %u decrypt mismatch", alg, n);
	}
	isrcry_cipher_free(ctx);
}

void monte_test(const char *alg, enum isrcry_cipher type,
			const struct monte_test *vectors, unsigned vec_count)
{
	struct isrcry_cipher_ctx *ctx;
	const struct monte_test *test;
	unsigned n;
	unsigned m;
	unsigned l;
	uint8_t key[32];
	uint8_t buf[64];
	uint8_t *in;
	uint8_t *out;
	enum isrcry_result ret;
	unsigned blocksize;

	ctx = isrcry_cipher_alloc(type, ISRCRY_MODE_ECB);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	blocksize = isrcry_cipher_block(type);
	if (blocksize < 8 || blocksize > 16)
		fail("%s invalid blocksize", alg);
	in = buf;
	out = buf + blocksize;
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		memset(key, 0, test->keylen);
		memset(buf, 0, sizeof(buf));
		for (m = 0; m < test->ngroups; m++) {
			ret = isrcry_cipher_init(ctx, test->encrypt ?
						ISRCRY_ENCRYPT : ISRCRY_DECRYPT,
						key, test->keylen, NULL);
			if (ret) {
				fail("%s %u init %u", alg, n, m);
				break;
			}
			for (l = 0; l < test->niters; l++) {
				memcpy(in, out, blocksize);
				ret = isrcry_cipher_process(ctx, in,
							blocksize, out);
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
	isrcry_cipher_free(ctx);
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
	ecb_test("bf", ISRCRY_CIPHER_BLOWFISH, blowfish_ecb_vectors,
				MEMBERS(blowfish_ecb_vectors));
	chain_pad_test("bf", ISRCRY_CIPHER_BLOWFISH, ISRCRY_MODE_CBC,
				ISRCRY_PADDING_PKCS5, blowfish_cbc_vectors,
				MEMBERS(blowfish_cbc_vectors));
	ecb_test("aes", ISRCRY_CIPHER_AES, aes_ecb_vectors,
				MEMBERS(aes_ecb_vectors));
	monte_test("aes", ISRCRY_CIPHER_AES, aes_monte_vectors,
				MEMBERS(aes_monte_vectors));
	chain_test("aes", ISRCRY_CIPHER_AES, ISRCRY_MODE_CBC,
				aes_cbc_vectors, MEMBERS(aes_cbc_vectors));
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
