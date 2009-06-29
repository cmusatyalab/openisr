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
#include <libtasn1.h>
#include "isrcrypto.h"
#include "vectors.h"
#include "vectors_blowfish.h"
#include "vectors_aes.h"
#include "vectors_sha1.h"
#include "vectors_md5.h"
#include "vectors_hmac.h"
#include "vectors_rsa.h"

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

void mac_test(const char *alg, enum isrcry_mac type,
			const struct mac_test *vectors, unsigned vec_count)
{
	struct isrcry_mac_ctx *ctx;
	const struct mac_test *test;
	uint8_t mac[64 + 1];
	unsigned n;
	unsigned m;

	ctx = isrcry_mac_alloc(type);
	if (ctx == NULL) {
		fail("%s alloc", alg);
		return;
	}
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		if (isrcry_mac_init(ctx, test->key, test->keylen)) {
			fail("%s init %u", alg, n);
			continue;
		}
		for (m = 0; m < 2; m++) {
			if (isrcry_mac_update(ctx, test->data, test->datalen)) {
				fail("%s update %u %u", alg, n, m);
				continue;
			}
			mac[test->maclen] = 0xc1;
			if (isrcry_mac_final(ctx, mac, test->maclen)) {
				fail("%s final %u %u", alg, n, m);
				continue;
			}
			if (memcmp(mac, test->mac, test->maclen)) {
				fail("%s result %u %u", alg, n, m);
				continue;
			}
			if (mac[test->maclen] != 0xc1)
				fail("%s overrun %u %u", alg, n, m);
		}
	}
	isrcry_mac_free(ctx);
}

void sign_genkey_test(const char *alg, enum isrcry_sign type,
			const unsigned *lengths, unsigned length_count)
{
	struct isrcry_sign_ctx *sctx;
	struct isrcry_random_ctx *rctx;
	char buf[1024];
	char sig[1024];
	unsigned siglen;
	unsigned n;

	rctx = isrcry_random_alloc();
	if (rctx == NULL) {
		fail("%s random alloc", alg);
		return;
	}
	sctx = isrcry_sign_alloc(type, rctx);
	if (sctx == NULL) {
		fail("%s sign alloc", alg);
		isrcry_random_free(rctx);
		return;
	}
	isrcry_random_bytes(rctx, buf, sizeof(buf));
	for (n = 0; n < length_count; n++) {
		if (isrcry_sign_make_keys(sctx, lengths[n])) {
			fail("%s make_keys %u", alg, n);
			continue;
		}
		isrcry_sign_update(sctx, buf, sizeof(buf));
		siglen = sizeof(sig);
		if (isrcry_sign_sign(sctx, sig, &siglen)) {
			fail("%s sign %u", alg, n);
			continue;
		}
		isrcry_sign_update(sctx, buf, sizeof(buf));
		if (isrcry_sign_verify(sctx, sig, siglen)) {
			fail("%s verify %u", alg, n);
			continue;
		}
		buf[0]++;
		isrcry_sign_update(sctx, buf, sizeof(buf));
		if (isrcry_sign_verify(sctx, sig, siglen) !=
					ISRCRY_BAD_SIGNATURE) {
			fail("%s verify xfail %u", alg, n);
			continue;
		}
	}
	isrcry_sign_free(sctx);
	isrcry_random_free(rctx);
}

#define _write_value(dst, namestr, data, len) do { \
		if (asn1_write_value((dst), (namestr), (data), (len))) {\
			fail("asn1_write_value %s", (namestr)); \
			asn1_delete_structure(&dst); \
			return; \
		} \
	} while (0)
#define write_value(dst, src, name) \
	_write_value(dst, #name, (src)->name, (src)->name ## _len)

void rsa_set_key(struct isrcry_sign_ctx *sctx, const struct rsa_test_key *key,
			ASN1_TYPE defs)
{
	ASN1_TYPE akey = ASN1_TYPE_EMPTY;
	char skeybuf[4096];
	int skeylen;
	char errbuf[MAX_ERROR_DESCRIPTION_SIZE] = {0};
	unsigned zero = 0;

	if (asn1_create_element(defs, "PKCS-1.RSAPrivateKey", &akey)) {
		fail("asn1_create_element");
		return;
	}
	_write_value(akey, "version", &zero, sizeof(zero));
	/* All of these fields must have a leading zero byte if the first
	   data byte is >= 0x80, since otherwise they will be recorded as
	   negative numbers. */
	write_value(akey, key, modulus);
	write_value(akey, key, publicExponent);
	write_value(akey, key, privateExponent);
	write_value(akey, key, prime1);
	write_value(akey, key, prime2);
	write_value(akey, key, exponent1);
	write_value(akey, key, exponent2);
	write_value(akey, key, coefficient);
	skeylen = sizeof(skeybuf);
	if (asn1_der_coding(akey, "", skeybuf, &skeylen, errbuf)) {
		fail("asn1_der_coding: %s", errbuf);
		asn1_delete_structure(&akey);
		return;
	}
	if (asn1_delete_structure(&akey)) {
		fail("asn1_delete_structure");
		return;
	}
	if (isrcry_sign_set_key(sctx, ISRCRY_KEY_PRIVATE,
				ISRCRY_KEY_FORMAT_RAW, skeybuf, skeylen))
		fail("isrcry_sign_set_key");
}

#undef _write_value
#undef write_value

void rsa_sign_test(const struct rsa_sign_test *vectors, unsigned vec_count)
{
	extern const ASN1_ARRAY_TYPE rsa_key_asn1_tab[];
	struct isrcry_sign_ctx *ctx;
	const struct rsa_sign_test *test;
	const struct rsa_test_key *key = NULL;
	ASN1_TYPE defs = ASN1_TYPE_EMPTY;
	char sig[4096];
	unsigned siglen;
	char errbuf[MAX_ERROR_DESCRIPTION_SIZE];
	unsigned n;

	if (asn1_array2tree(rsa_key_asn1_tab, &defs, errbuf)) {
		fail("asn1_array2tree: %s", errbuf);
		return;
	}
	ctx = isrcry_sign_alloc(ISRCRY_SIGN_RSA_PSS_SHA1, NULL);
	if (ctx == NULL) {
		fail("alloc");
		asn1_delete_structure(&defs);
		return;
	}
	for (n = 0; n < vec_count; n++) {
		test = &vectors[n];
		if (test->key != key) {
			rsa_set_key(ctx, test->key, defs);
			key = test->key;
		}
		isrcry_sign_update(ctx, test->data, test->datalen);
		if (isrcry_sign_set_salt(ctx, test->salt, test->saltlen)) {
			fail("set_salt %u", n);
			continue;
		}
		siglen = sizeof(sig);
		if (isrcry_sign_sign(ctx, sig, &siglen)) {
			fail("sign %u", n);
			continue;
		}
		if (siglen != test->siglen) {
			fail("signature length %u", n);
			continue;
		}
		if (memcmp(sig, test->sig, test->siglen)) {
			fail("signature mismatch %u", n);
			continue;
		}
		isrcry_sign_update(ctx, test->data, test->datalen);
		if (isrcry_sign_verify(ctx, test->sig, test->siglen)) {
			fail("verify %u", n);
			continue;
		}
		isrcry_sign_update(ctx, test->data, test->datalen - 1);
		if (isrcry_sign_verify(ctx, test->sig, test->siglen) !=
					ISRCRY_BAD_SIGNATURE) {
			fail("verify xfail %u", n);
			continue;
		}
	}
	isrcry_sign_free(ctx);
	asn1_delete_structure(&defs);
}

void dh_test(const char *alg, enum isrcry_dh type, unsigned reps)
{
	struct isrcry_random_ctx *rctx;
	struct isrcry_dh_ctx *a;
	struct isrcry_dh_ctx *b;
	unsigned keylen = isrcry_dh_key_len(type);
	char pub_a[keylen];
	char pub_b[keylen];
	char shared_a[keylen];
	char shared_b[keylen];
	unsigned n;

	rctx = isrcry_random_alloc();
	if (rctx == NULL) {
		fail("alloc random");
		return;
	}
	a = isrcry_dh_alloc(type, rctx);
	if (a == NULL) {
		fail("alloc %s", alg);
		isrcry_random_free(rctx);
		return;
	}
	b = isrcry_dh_alloc(type, rctx);
	if (b == NULL) {
		fail("alloc %s", alg);
		isrcry_dh_free(a);
		isrcry_random_free(rctx);
		return;
	}
	for (n = 0; n < reps; n++) {
		if (isrcry_dh_init(a, 16) || isrcry_dh_init(b, 16)) {
			fail("init %s %u", alg, n);
			continue;
		}
		if (isrcry_dh_get_public(a, pub_a) ||
					isrcry_dh_get_public(b, pub_b)) {
			fail("get_public %s %u", alg, n);
			continue;
		}
		if (isrcry_dh_run(a, pub_b, shared_a) ||
					isrcry_dh_run(b, pub_a, shared_b)) {
			fail("run %s %u", alg, n);
			continue;
		}
		if (memcmp(shared_a, shared_b, keylen)) {
			fail("shared %s %u", alg, n);
			continue;
		}
		pub_b[1]++;
		if (isrcry_dh_run(a, pub_b, shared_a)) {
			fail("run %s %u", alg, n);
			continue;
		}
		if (!memcmp(shared_a, shared_b, keylen)) {
			fail("shared xfail %s %u", alg, n);
			continue;
		}
	}
	isrcry_dh_free(a);
	isrcry_dh_free(b);
	isrcry_random_free(rctx);
}

/* Statistical random number generator tests defined in
 * FIPS 140-1 - 4.11.1 Power-Up Tests.  Originally from RPC2.
 *
 * A single bit stream of 20,000 consecutive bits of output from the
 * generator is subjected to each of the following tests. If any of the
 * tests fail, then the module shall enter an error state.
 *
 * The Monobit Test
 *  1. Count the number of ones in the 20,000 bit stream. Denote this
 *     quantity by X.
 *  2. The test is passed if 9,654 < X < 10,346
 *
 * The Poker Test
 *  1. Divide the 20,000 bit stream into 5,000 contiguous 4 bit
 *     segments. Count and store the number of occurrences of each of
 *     the 16 possible 4 bit values. Denote f(i) as the number of each 4
 *     bit value i where 0 < i < 15.
 *  2. Evaluate the following: X = (16/5000) * (Sum[f(i)]^2)-5000
 *  3. The test is passed if 1.03 < X < 57.4
 *
 * The Runs Test
 *  1. A run is defined as a maximal sequence of consecutive bits of
 *     either all ones or all zeros, which is part of the 20,000 bit
 *     sample stream. The incidences of runs (for both consecutive zeros
 *     and consecutive ones) of all lengths ( 1) in the sample stream
 *     should be counted and stored.
 *  2. The test is passed if the number of runs that occur (of lengths 1
 *     through 6) is each within the corresponding interval specified
 *     below. This must hold for both the zeros and ones; that is, all
 *     12 counts must lie in the specified interval. For the purpose of
 *     this test, runs of greater than 6 are considered to be of length 6.
 *       Length of Run			    Required Interval
 *	     1					2,267-2,733
 *	     2					1,079-1,421
 *	     3					502-748
 *	     4					223-402
 *	     5					90-223
 *	     6+					90-223
 *
 * The Long Run Test
 *  1. A long run is defined to be a run of length 34 or more (of either
 *     zeros or ones).
 *  2. On the sample of 20,000 bits, the test is passed if there are NO
 *     long runs.
 */
void random_fips_test(void)
{
	struct isrcry_random_ctx *ctx;
	uint32_t data[20000 / (sizeof(uint32_t) * 8)];
	uint32_t val;
	unsigned i, j, idx;
	int ones, f[16], run, odd, longrun;

	ctx = isrcry_random_alloc();
	if (ctx == NULL) {
		fail("random alloc");
		return;
	}
	isrcry_random_bytes(ctx, data, sizeof(data));
	isrcry_random_free(ctx);

	/* Monobit Test */
	for (ones = 0, i = 0 ; i < sizeof(data)/sizeof(data[0]); i++) {
		val = data[i];
		while (val) {
			if (val & 1)
				ones++;
			val >>= 1;
		}
	}
	if (ones <= 9654 || ones >= 10346)
		fail("random monobit");

	/* Poker Test */
	memset(f, 0, sizeof(f));
	for (i = 0; i < sizeof(data)/sizeof(data[0]); i++) {
		for (j = 0; j < 32; j += 4) {
			idx = (data[i] >> j) & 0xf;
			f[idx]++;
		}
	}
	for (val = 0, i = 0; i < 16; i++)
		val += f[i] * f[i];
	if ((val & 0xf0000000) || (val << 4) <= 25005150 ||
				(val << 4) >= 25287000)
		fail("random poker");

	/* Runs Test */
	memset(f, 0, sizeof(f));
	odd = run = longrun = 0;
	for (i = 0 ; i < sizeof(data)/sizeof(data[0]); i++) {
		val = data[i];
		for (j = 0; j < 32; j++) {
			if (odd ^ (val & 1)) {
				if (run) {
					if (run > longrun)
						longrun = run;
					if (run > 6)
						run = 6;
					idx = run - 1 + (odd ? 6 : 0);
					f[idx]++;
				}
				odd = val & 1;
				run = 0;
			}
			run++;
			val >>= 1;
		}
	}
	if (run > longrun)
		longrun = run;
	if (run > 6)
		run = 6;
	idx = run - 1 + (odd ? 6 : 0);
	f[idx]++;

	if (f[0] <= 2267 || f[0] >= 2733 || f[6] <= 2267 || f[6] >= 2733 ||
		 f[1] <= 1079 || f[1] >= 1421 || f[7] <= 1079 || f[7] >= 1421 ||
		 f[2] <= 502  || f[2] >= 748  || f[8] <= 502  || f[8] >= 748 ||
		 f[3] <= 223  || f[3] >= 402  || f[9] <= 223  || f[9] >= 402 ||
		 f[4] <= 90   || f[4] >= 223  || f[10] <= 90  || f[10] >= 223 ||
		 f[5] <= 90   || f[5] >= 223  || f[11] <= 90  || f[11] >= 223)
		fail("random runs");
	if (longrun >= 34)
		fail("random long runs");
}

int main(void)
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
	mac_test("hmac-sha1", ISRCRY_MAC_HMAC_SHA1, hmac_sha1_vectors,
				MEMBERS(hmac_sha1_vectors));
	sign_genkey_test("rsa-pss-sha1", ISRCRY_SIGN_RSA_PSS_SHA1,
				rsa_sign_genkey_lengths,
				MEMBERS(rsa_sign_genkey_lengths));
	rsa_sign_test(rsa_sign_vectors, MEMBERS(rsa_sign_vectors));
	dh_test("ike-2048", ISRCRY_DH_IKE_2048, 8);
	random_fips_test();

	if (failed) {
		printf("%d tests failed\n", failed);
		return 1;
	} else {
		printf("All tests passed\n");
		return 0;
	}
}
