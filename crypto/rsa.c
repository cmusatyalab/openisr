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

/* This file is adapted from libtomcrypt, whose license block follows. */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.com
 */

#include <stdlib.h>
#include <libtasn1.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

/* Min and Max RSA key sizes (in bits) */
#define MIN_RSA_SIZE 1024
#define MAX_RSA_SIZE 4096
#define RSA_E 65537

extern const ASN1_ARRAY_TYPE rsa_key_asn1_tab[];

struct isrcry_rsa_key {
	/** The public exponent */
	mpz_t e;
	/** The private exponent */
	mpz_t d;
	/** The modulus */
	mpz_t N;
	/** The p factor of N */
	mpz_t p;
	/** The q factor of N */
	mpz_t q;
	/** The 1/q mod p CRT param */
	mpz_t qP;
	/** The d mod (p - 1) CRT param */
	mpz_t dP;
	/** The d mod (q - 1) CRT param */
	mpz_t dQ;
};

static struct isrcry_rsa_key *alloc_key(void)
{
	struct isrcry_rsa_key *key;
	
	key = malloc(sizeof(*key));
	if (key == NULL)
		return NULL;
	mpz_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP,
				&key->p, &key->q, NULL);
	return key;
}

static void free_key(struct isrcry_rsa_key *key)
{
	mpz_clear_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP,
				&key->qP, &key->p, &key->q, NULL);
	free(key);
}

static void set_key(struct isrcry_sign_ctx *sctx, enum isrcry_key_type type,
			struct isrcry_rsa_key *key)
{
	switch (type) {
	case ISRCRY_KEY_PUBLIC:
		if (sctx->pubkey != NULL)
			free_key(sctx->pubkey);
		sctx->pubkey = key;
		break;
	case ISRCRY_KEY_PRIVATE:
		if (sctx->privkey != NULL)
			free_key(sctx->privkey);
		sctx->privkey = key;
		break;
	}
}

/**
   Perform PKCS #1 MGF1 (internal)
   @param seed        The seed for MGF1
   @param seedlen     The length of the seed
   @param mask        [out] The destination
   @param masklen     The length of the mask desired
   @return ISRCRY_OK if successful
*/
static void pkcs_1_mgf1(struct isrcry_sign_ctx *sctx,
			const unsigned char *seed, unsigned seedlen,
			unsigned char *mask, unsigned masklen)
{
	unsigned hLen = isrcry_hash_len(sctx->desc->hash);
	unsigned char buf[hLen];
	unsigned x;
	uint32_t counter = 0;

	while (masklen > 0) {
		/* handle counter */
		STORE32H(counter, buf);
		++counter;

		/* get hash of seed || counter */
		isrcry_hash_update(sctx->hctx, seed, seedlen);
		isrcry_hash_update(sctx->hctx, buf, 4);
		isrcry_hash_final(sctx->hctx, buf);

		/* store it */
		for (x = 0; x < hLen && masklen > 0; x++, masklen--)
			*mask++ = buf[x];
	}
}

/**
   PKCS #1 v2.00 Signature Encoding
   @param msghash          The hash to encode
   @param msghashlen       The length of the hash (octets)
   @param rctx             An active PRNG context
   @param hashtype         The index of the hash desired
   @param emBits           The desired bit length of the encoded data
   @param out              [out] The destination of the encoding
   @param outlen           [in/out] The max size and resulting size of the encoded data
   @return ISRCRY_OK if successful
*/
static enum isrcry_result pkcs_1_pss_encode(struct isrcry_sign_ctx *sctx,
			const unsigned char *msghash, unsigned msghashlen,
			unsigned emBits, unsigned char *out, unsigned *outlen)
{
	unsigned char *DB, *mask, *salt, *hash;
	unsigned x, y, hLen, emLen, saltlen;
	int err;

	saltlen = sctx->desc->saltlen;
	hLen = isrcry_hash_len(sctx->desc->hash);
	emLen = (emBits >> 3) + (emBits & 7 ? 1 : 0);

	/* check sizes */
	if (saltlen > emLen || emLen < hLen + saltlen + 2)
		return ISRCRY_INVALID_ARGUMENT;

	/* allocate ram for DB/mask/salt/hash of size emLen */
	DB = malloc(emLen);
	mask = malloc(emLen);
	salt = malloc(emLen);
	hash = malloc(emLen);
	if (DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
		if (DB != NULL)
			free(DB);
		if (mask != NULL)
			free(mask);
		if (salt != NULL)
			free(salt);
		if (hash != NULL)
			free(hash);
		return -1;
	}

	/* generate random salt */
	if (saltlen > 0) {
		if (sctx->salt != NULL)
			memcpy(salt, sctx->salt, saltlen);
		else
			isrcry_random_bytes(sctx->rctx, salt, saltlen);
	}

	/* M = (eight) 0x00 || msghash || salt, hash = H(M) */
	memset(DB, 0, 8);
	isrcry_hash_update(sctx->hctx, DB, 8);
	isrcry_hash_update(sctx->hctx, msghash, msghashlen);
	isrcry_hash_update(sctx->hctx, salt, saltlen);
	isrcry_hash_final(sctx->hctx, hash);

	/* generate DB = PS || 0x01 || salt, PS == emLen - saltlen -
	   hLen - 2 zero bytes */
	x = 0;
	memset(DB + x, 0, emLen - saltlen - hLen - 2);
	x += emLen - saltlen - hLen - 2;
	DB[x++] = 0x01;
	memcpy(DB + x, salt, saltlen);
	x += saltlen;

	/* generate mask of length emLen - hLen - 1 from hash */
	pkcs_1_mgf1(sctx, hash, hLen, mask, emLen - hLen - 1);

	/* xor against DB */
	for (y = 0; y < (emLen - hLen - 1); y++)
		DB[y] ^= mask[y];

	/* output is DB || hash || 0xBC */
	if (*outlen < emLen) {
		*outlen = emLen;
		err = ISRCRY_BUFFER_OVERFLOW;
		goto LBL_ERR;
	}

	/* DB len = emLen - hLen - 1 */
	y = 0;
	memcpy(out + y, DB, emLen - hLen - 1);
	y += emLen - hLen - 1;

	/* hash */
	memcpy(out + y, hash, hLen);
	y += hLen;

	/* 0xBC */
	out[y] = 0xBC;

	/* now clear the 8*emLen - emBits most significant bits */
	out[0] &= 0xFF >> ((emLen << 3) - emBits);

	/* store output size */
	*outlen = emLen;
	err = ISRCRY_OK;
LBL_ERR:

	free(hash);
	free(salt);
	free(mask);
	free(DB);

	return err;
}

/**
   PKCS #1 v2.00 PSS decode
   @param  msghash         The hash to verify
   @param  msghashlen      The length of the hash (octets)
   @param  sig             The signature data (encoded data)
   @param  siglen          The length of the signature data (octets)
   @param  emBits          The desired bit length of the encoded data
   @return ISRCRY_OK if successful (even if the comparison failed)
*/
static enum isrcry_result pkcs_1_pss_decode(struct isrcry_sign_ctx *sctx,
			unsigned char *msghash, unsigned msghashlen,
			const unsigned char *sig, unsigned siglen,
			unsigned emBits)
{
	unsigned char *DB, *mask, *salt, *hash;
	unsigned x, y, hLen, emLen, saltlen;
	int err;

	saltlen = sctx->desc->saltlen;
	hLen = isrcry_hash_len(sctx->desc->hash);
	emLen = (emBits >> 3) + (emBits & 7 ? 1 : 0);

	/* check sizes */
	if (saltlen > emLen || emLen < hLen + saltlen + 2)
		return ISRCRY_INVALID_ARGUMENT;

	/* allocate ram for DB/mask/salt/hash of size emLen */
	DB = malloc(emLen);
	mask = malloc(emLen);
	salt = malloc(emLen);
	hash = malloc(emLen);
	if (DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
		if (DB != NULL)
			free(DB);
		if (mask != NULL)
			free(mask);
		if (salt != NULL)
			free(salt);
		if (hash != NULL)
			free(hash);
		return -1;
	}

	/* ensure the 0xBC byte */
	if (sig[siglen - 1] != 0xBC) {
		err = ISRCRY_BAD_FORMAT;
		goto LBL_ERR;
	}

	/* copy out the DB */
	x = 0;
	memcpy(DB, sig + x, emLen - hLen - 1);
	x += emLen - hLen - 1;

	/* copy out the hash */
	memcpy(hash, sig + x, hLen);
	x += hLen;

	/* check the MSB */
	if ((sig[0] & ~(0xFF >> ((emLen << 3) - emBits))) != 0) {
		err = ISRCRY_BAD_FORMAT;
		goto LBL_ERR;
	}

	/* generate mask of length emLen - hLen - 1 from hash */
	pkcs_1_mgf1(sctx, hash, hLen, mask, emLen - hLen - 1);

	/* xor against DB */
	for (y = 0; y < emLen - hLen - 1; y++)
		DB[y] ^= mask[y];

	/* now clear the first byte [make sure smaller than modulus] */
	DB[0] &= 0xFF >> ((emLen << 3) - (emBits - 1));

	/* DB = PS || 0x01 || salt, PS == emLen - saltlen - hLen
	   - 2 zero bytes */

	/* check for zeroes and 0x01 */
	for (x = 0; x < emLen - saltlen - hLen - 2; x++) {
		if (DB[x] != 0x00) {
			err = ISRCRY_BAD_FORMAT;
			goto LBL_ERR;
		}
	}

	/* check for the 0x01 */
	if (DB[x++] != 0x01) {
		err = ISRCRY_BAD_FORMAT;
		goto LBL_ERR;
	}

	/* M = (eight) 0x00 || msghash || salt, mask = H(M) */
	memset(mask, 0, 8);
	isrcry_hash_update(sctx->hctx, mask, 8);
	isrcry_hash_update(sctx->hctx, msghash, msghashlen);
	isrcry_hash_update(sctx->hctx, DB + x, saltlen);
	isrcry_hash_final(sctx->hctx, mask);

	/* mask == hash means valid signature */
	if (memcmp(mask, hash, hLen) == 0)
		err = ISRCRY_OK;
	else
		err = ISRCRY_BAD_SIGNATURE;

LBL_ERR:
	free(hash);
	free(salt);
	free(mask);
	free(DB);
	return err;
}

static enum isrcry_result rsa_make_keys(struct isrcry_sign_ctx *sctx,
			unsigned length)
{
	struct isrcry_rsa_key *key;
	mpz_t p, q, tmp1, tmp2, tmp3;
	enum isrcry_result err;

	if (length < (MIN_RSA_SIZE / 8) || length > (MAX_RSA_SIZE / 8))
		return ISRCRY_INVALID_ARGUMENT;
	if (sctx->rctx == NULL)
		return ISRCRY_NEED_RANDOM;

	mpz_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL);
	key = alloc_key();
	if (key == NULL)
		return -1;

	/* make primes p and q (optimization provided by Wayne Scott) */
	mpz_set_ui(tmp3, RSA_E);		/* tmp3 = e */

	/* make prime "p" */
	do {
		if ((err = isrcry_gen_prime(p, sctx->rctx, length / 2)))
			goto errkey;
		mpz_sub_ui(tmp1, p, 1);		/* tmp1 = p-1 */
		mpz_gcd(tmp2, tmp1, tmp3);	/* tmp2 = gcd(p-1, e) */
	} while (mpz_cmp_ui(tmp2, 1));		/* while e divides p-1 */

	/* make prime "q" */
	do {
		if ((err = isrcry_gen_prime(q, sctx->rctx, length / 2)))
			goto errkey;
		mpz_sub_ui(tmp1, q, 1);		/* tmp1 = q-1 */
		mpz_gcd(tmp2, tmp1, tmp3);	/* tmp2 = gcd(q-1, e) */
	} while (mpz_cmp_ui(tmp2, 1));		/* while e divides q-1 */

	/* tmp1 = lcm(p-1, q-1) */
	mpz_sub_ui(tmp2, p, 1);			/* tmp2 = p-1 */
	/* tmp1 = q-1 (previous do/while loop) */
	mpz_lcm(tmp1, tmp1, tmp2);		/* tmp1 = lcm(p-1, q-1) */

	/* make key */
	mpz_set_ui(key->e, RSA_E);		/* key->e =  e */
	/* key->d = 1/e mod lcm(p-1,q-1) */
	if (!mpz_invert(key->d, key->e, tmp1)) {
		err = ISRCRY_BAD_FORMAT;
		goto errkey;
	}
	mpz_mul(key->N, p, q);			/* key->N = pq */

	/* optimize for CRT now */
	/* find d mod q-1 and d mod p-1 */
	mpz_sub_ui(tmp1, p, 1);			/* tmp1 = q-1 */
	mpz_sub_ui(tmp2, q, 1);			/* tmp2 = p-1 */
	mpz_mod(key->dP, key->d, tmp1);		/* dP = d mod p-1 */
	mpz_mod(key->dQ, key->d, tmp2);		/* dQ = d mod q-1 */
	if (!mpz_invert(key->qP, q, p)) {
		err = ISRCRY_BAD_FORMAT;
		goto errkey;
	}
	/* qP = 1/q mod p */
	mpz_set(key->p, p);
	mpz_set(key->q, q);

	set_key(sctx, ISRCRY_KEY_PUBLIC, NULL);
	set_key(sctx, ISRCRY_KEY_PRIVATE, key);

	/* return ok and free temps */
	err = ISRCRY_OK;
	goto cleanup;
errkey:
	free_key(key);
cleanup:
	mpz_clear_multi(&tmp3, &tmp2, &tmp1, &p, &q, NULL);
	return err;
}

static enum isrcry_result asn1_get_int(mpz_t dest, ASN1_TYPE obj,
			const char *field)
{
	void *buf;
	int len = 0;
	
	if (asn1_read_value(obj, field, NULL, &len) != ASN1_MEM_ERROR)
		return ISRCRY_INVALID_ARGUMENT;
	buf = malloc(len);
	if (buf == NULL)
		return -1;
	if (asn1_read_value(obj, field, buf, &len)) {
		free(buf);
		return ISRCRY_BUFFER_OVERFLOW;
	}
	mpz_from_unsigned_bin(dest, buf, len);
	free(buf);
	return ISRCRY_OK;
}

static enum isrcry_result asn1_set_int(ASN1_TYPE obj, const char *field,
			mpz_t val)
{
	unsigned len = mpz_unsigned_bin_size(val);
	unsigned char buf[len + 1];

	buf[0] = 0;
	mpz_to_unsigned_bin(buf + 1, val);
	if (asn1_write_value(obj, field, buf, sizeof(buf)))
		return ISRCRY_INVALID_ARGUMENT;
	return ISRCRY_OK;
}

/**
  Import an RSAPublicKey or RSAPrivateKey
  [two-prime only, only support >= 1024-bit keys, defined in PKCS #1 v2.1]
*/
static enum isrcry_result rsa_set_key(struct isrcry_sign_ctx *sctx,
			enum isrcry_key_type type,
			enum isrcry_key_format format,
			const unsigned char *in, unsigned inlen)
{
	struct isrcry_rsa_key *key;
	ASN1_TYPE defs = ASN1_TYPE_EMPTY;
	ASN1_TYPE akey = ASN1_TYPE_EMPTY;
	uint8_t ver;
	int len;
	enum isrcry_result ret = ISRCRY_BAD_FORMAT;

	key = alloc_key();
	if (key == NULL)
		return -1;

	if (asn1_array2tree(rsa_key_asn1_tab, &defs, NULL))
		goto out;

	if (type == ISRCRY_KEY_PRIVATE) {
		if (asn1_create_element(defs, "PKCS-1.RSAPrivateKey", &akey))
			goto out;
		if (asn1_der_decoding(&akey, in, inlen, NULL))
			goto out;
		len = sizeof(ver);
		if (asn1_read_value(akey, "version", &ver, &len))
			goto out;
		if (ver != 0)
			goto out;
		if (asn1_get_int(key->N, akey, "modulus"))
			goto out;
		if (asn1_get_int(key->e, akey, "publicExponent"))
			goto out;
		if (asn1_get_int(key->d, akey, "privateExponent"))
			goto out;
		if (asn1_get_int(key->p, akey, "prime1"))
			goto out;
		if (asn1_get_int(key->q, akey, "prime2"))
			goto out;
		if (asn1_get_int(key->dP, akey, "exponent1"))
			goto out;
		if (asn1_get_int(key->dQ, akey, "exponent2"))
			goto out;
		if (asn1_get_int(key->qP, akey, "coefficient"))
			goto out;
	} else {
		if (asn1_create_element(defs, "PKCS-1.RSAPublicKey", &akey))
			goto out;
		if (asn1_der_decoding(&akey, in, inlen, NULL))
			goto out;
		if (asn1_get_int(key->N, akey, "modulus"))
			goto out;
		if (asn1_get_int(key->e, akey, "publicExponent"))
			goto out;
	}
	set_key(sctx, type, key);
	ret = ISRCRY_OK;
out:
	asn1_delete_structure(&akey);
	asn1_delete_structure(&defs);
	if (ret)
		free_key(key);
	return ret;
}

/**
    This will export either an RSAPublicKey or RSAPrivateKey
    [defined in PKCS #1 v2.1] 
*/
static enum isrcry_result rsa_get_key(struct isrcry_sign_ctx *sctx,
				enum isrcry_key_type type,
				enum isrcry_key_format format,
				unsigned char *out, unsigned *outlen)
{
	struct isrcry_rsa_key *key = NULL;
	ASN1_TYPE defs = ASN1_TYPE_EMPTY;
	ASN1_TYPE akey = ASN1_TYPE_EMPTY;
	unsigned zero = 0;
	enum isrcry_result ret = ISRCRY_BAD_FORMAT;
	int err;

	switch (type) {
	case ISRCRY_KEY_PUBLIC:
		key = sctx->pubkey;
		if (key == NULL)
			key = sctx->privkey;
		break;
	case ISRCRY_KEY_PRIVATE:
		key = sctx->privkey;
		break;
	}
	if (key == NULL)
		return ISRCRY_INVALID_ARGUMENT;

	if (asn1_array2tree(rsa_key_asn1_tab, &defs, NULL))
		return ISRCRY_BAD_FORMAT;

	if (type == ISRCRY_KEY_PRIVATE) {
		if (asn1_create_element(defs, "PKCS-1.RSAPrivateKey", &akey))
			goto out;
		if (asn1_write_value(akey, "version", &zero, sizeof(zero)))
			goto out;
		if (asn1_set_int(akey, "modulus", key->N))
			goto out;
		if (asn1_set_int(akey, "publicExponent", key->e))
			goto out;
		if (asn1_set_int(akey, "privateExponent", key->d))
			goto out;
		if (asn1_set_int(akey, "prime1", key->p))
			goto out;
		if (asn1_set_int(akey, "prime2", key->q))
			goto out;
		if (asn1_set_int(akey, "exponent1", key->dP))
			goto out;
		if (asn1_set_int(akey, "exponent2", key->dQ))
			goto out;
		if (asn1_set_int(akey, "coefficient", key->qP))
			goto out;
	} else {
		if (asn1_create_element(defs, "PKCS-1.RSAPublicKey", &akey))
			goto out;
		if (asn1_set_int(akey, "modulus", key->N))
			goto out;
		if (asn1_set_int(akey, "publicExponent", key->e))
			goto out;
	}
	err = asn1_der_coding(akey, "", out, (int *) outlen, NULL);
	if (err == ASN1_MEM_ERROR)
		ret = ISRCRY_BUFFER_OVERFLOW;
	if (err)
		goto out;
	ret = ISRCRY_OK;

out:
	asn1_delete_structure(&akey);
	asn1_delete_structure(&defs);
	return ret;
}

/** 
   Compute an RSA modular exponentiation 
   @param in         The input data to send into RSA
   @param inlen      The length of the input (octets)
   @param out        [out] The destination 
   @param outlen     [in/out] The max size and resulting size of the output
   @param which      Which exponent to use, e.g. ISRCRY_KEY_PRIVATE or ISRCRY_KEY_PUBLIC
   @param key        The RSA key to use 
   @return ISRCRY_OK if successful
*/
static int rsa_exptmod(const unsigned char *in, unsigned inlen,
			unsigned char *out, unsigned *outlen,
			enum isrcry_key_type which, struct isrcry_rsa_key *key)
{
	mpz_t tmp, tmpa, tmpb;
	unsigned long x;
	int err;

	/* init and copy into tmp */
	mpz_init_multi(&tmp, &tmpa, &tmpb, NULL);
	mpz_from_unsigned_bin(tmp, in, inlen);

	/* sanity check on the input */
	if (mpz_cmp(key->N, tmp) < 0) {
		err = ISRCRY_BAD_FORMAT;
		goto error;
	}

	/* are we using the private exponent and is the key optimized? */
	if (which == ISRCRY_KEY_PRIVATE) {
		/* tmpa = tmp^dP mod p */
		mpz_powm(tmpa, tmp, key->dP, key->p);

		/* tmpb = tmp^dQ mod q */
		mpz_powm(tmpb, tmp, key->dQ, key->q);

		/* tmp = (tmpa - tmpb) * qInv (mod p) */
		mpz_sub(tmp, tmpa, tmpb);
		mpz_mul(tmp, tmp, key->qP);
		mpz_mod(tmp, tmp, key->p);

		/* tmp = tmpb + q * tmp */
		mpz_mul(tmp, tmp, key->q);
		mpz_add(tmp, tmp, tmpb);
	} else {
		/* exptmod it */
		mpz_powm(tmp, tmp, key->e, key->N);
	}

	/* read it back */
	x = mpz_unsigned_bin_size(key->N);
	if (x > *outlen) {
		*outlen = x;
		err = ISRCRY_BUFFER_OVERFLOW;
		goto error;
	}

	/* this should never happen ... */
	if (mpz_unsigned_bin_size(tmp) > mpz_unsigned_bin_size(key->N)) {
		err = -1;
		goto error;
	}
	*outlen = x;

	/* convert it */
	memset(out, 0, x);
	mpz_to_unsigned_bin(out + (x - mpz_unsigned_bin_size(tmp)), tmp);

	/* clean up and return */
	err = ISRCRY_OK;
error:
	mpz_clear_multi(&tmp, &tmpa, &tmpb, NULL);
	return err;
}

static enum isrcry_result rsa_sign(struct isrcry_sign_ctx *sctx,
			unsigned char *out, unsigned *outlen)
{
	struct isrcry_rsa_key *key = sctx->privkey;
	unsigned hashlen = isrcry_hash_len(sctx->desc->hash);
	unsigned char hash[hashlen];
	unsigned modulus_bitlen, modulus_bytelen, x, y;
	int err;

	if (sctx->rctx == NULL && sctx->desc->saltlen > 0 &&
				sctx->salt == NULL)
		return ISRCRY_NEED_RANDOM;
	if (key == NULL)
		return ISRCRY_NEED_KEY;

	/* get modulus len in bits */
	modulus_bitlen = mpz_sizeinbase(key->N, 2);

	/* outlen must be at least the size of the modulus */
	modulus_bytelen = mpz_unsigned_bin_size(key->N);
	if (modulus_bytelen > *outlen) {
		*outlen = modulus_bytelen;
		return ISRCRY_BUFFER_OVERFLOW;
	}
	
	/* get hash of data */
	isrcry_hash_final(sctx->hctx, hash);

	/* PSS pad the key */
	x = *outlen;
	if ((err = pkcs_1_pss_encode(sctx, hash, hashlen, modulus_bitlen - 1,
				out, &x)))
		return err;

	/* RSA encode it */
	y = *outlen;
	err = rsa_exptmod(out, x, out, &y, ISRCRY_KEY_PRIVATE, sctx->privkey);
	*outlen = y;
	return err;
}

static enum isrcry_result rsa_verify(struct isrcry_sign_ctx *sctx,
			const unsigned char *sig, unsigned siglen)
{
	unsigned hashlen = isrcry_hash_len(sctx->desc->hash);
	unsigned char hash[hashlen];
	struct isrcry_rsa_key *key;
	unsigned modulus_bitlen, modulus_bytelen, x;
	int err;
	unsigned char sigbuf[siglen];
	int sig_is_short;

	if (sctx->pubkey != NULL)
		key = sctx->pubkey;
	else if (sctx->privkey != NULL)
		key = sctx->privkey;
	else
		return ISRCRY_NEED_KEY;

	/* get hash of data */
	isrcry_hash_final(sctx->hctx, hash);

	/* get modulus len in bits */
	modulus_bitlen = mpz_sizeinbase(key->N, 2);

	/* siglen must be equal to the size of the modulus */
	modulus_bytelen = mpz_unsigned_bin_size(key->N);
	if (modulus_bytelen != siglen)
		return ISRCRY_BAD_FORMAT;

	/* RSA decode it  */
	x = siglen;
	if ((err = rsa_exptmod(sig, siglen, sigbuf, &x, ISRCRY_KEY_PUBLIC,
				key)))
		return err;

	/* make sure the output is the right size */
	if (x != siglen)
		return ISRCRY_BAD_FORMAT;
	sig_is_short = !((modulus_bitlen - 1) % 8);

	/* PSS decode and verify it */
	err = pkcs_1_pss_decode(sctx, hash, hashlen,
				sig_is_short ? sigbuf + 1 : sigbuf,
				sig_is_short ? x - 1 : x, modulus_bitlen - 1);

	return err;
}

static void rsa_free(struct isrcry_sign_ctx *sctx)
{
	if (sctx->pubkey != NULL)
		free_key(sctx->pubkey);
	if (sctx->privkey != NULL)
		free_key(sctx->privkey);
}

const struct isrcry_sign_desc _isrcry_rsa_pss_sha1_desc = {
	.make_keys = rsa_make_keys,
	.get_key = rsa_get_key,
	.set_key = rsa_set_key,
	.sign = rsa_sign,
	.verify = rsa_verify,
	.free = rsa_free,
	.hash = ISRCRY_HASH_SHA1,
	.saltlen = 20
};
