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
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

/* Min and Max RSA key sizes (in bits) */
#define MIN_RSA_SIZE 1024
#define MAX_RSA_SIZE 4096
#define RSA_E 65537

struct isrcry_rsa_key {
	/** The public exponent */
	void *e;
	/** The private exponent */
	void *d;
	/** The modulus */
	void *N;
	/** The p factor of N */
	void *p;
	/** The q factor of N */
	void *q;
	/** The 1/q mod p CRT param */
	void *qP;
	/** The d mod (p - 1) CRT param */
	void *dP;
	/** The d mod (q - 1) CRT param */
	void *dQ;
};

/**
  Free an RSA key from memory
  @param key   The RSA key to free
*/
static void free_key(struct isrcry_rsa_key *key)
{
	mp_clear_multi(key->e, key->d, key->N, key->dQ, key->dP, key->qP,
				key->p, key->q, NULL);
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

/* always stores the same # of bytes, pads with leading zero bytes
   as required
 */
/**
   PKCS #1 Integer to binary
   @param n             The integer to store
   @param modulus_len   The length of the RSA modulus
   @param out           [out] The destination for the integer
   @return ISRCRY_OK if successful
*/
static int pkcs_1_i2osp(void *n, unsigned long modulus_len,
			unsigned char *out)
{
	unsigned long size;

	size = mp_unsigned_bin_size(n);

	if (size > modulus_len)
		return ISRCRY_BUFFER_OVERFLOW;

	/* store it */
	memset(out, 0, modulus_len);
	mp_to_unsigned_bin(n, out + (modulus_len - size));
	return ISRCRY_OK;
}

/**
  Read a binary string into an mp_int
  @param n          [out] The mp_int destination
  @param in         The binary string to read
  @param inlen      The length of the binary string
*/
static void pkcs_1_os2ip(void *n, unsigned char *in, unsigned long inlen)
{
	mp_read_unsigned_bin(n, in, inlen);
}

/**
   Perform PKCS #1 MGF1 (internal)
   @param seed        The seed for MGF1
   @param seedlen     The length of the seed
   @param mask        [out] The destination
   @param masklen     The length of the mask desired
   @return ISRCRY_OK if successful
*/
static enum isrcry_result pkcs_1_mgf1(struct isrcry_sign_ctx *sctx,
			const unsigned char *seed, unsigned long seedlen,
			unsigned char *mask, unsigned long masklen)
{
	unsigned long hLen, x;
	uint32_t counter;
	int err;
	unsigned char *buf;

	/* get hash output size */
	hLen = isrcry_hash_len(sctx->desc->hash);

	/* allocate memory */
	buf = malloc(hLen);
	if (buf == NULL)
		return -1;

	/* start counter */
	counter = 0;

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
	err = ISRCRY_OK;
	free(buf);
	return err;
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
			const unsigned char *msghash,
			unsigned long msghashlen,
			unsigned long emBits, unsigned char *out,
			unsigned long *outlen)
{
	unsigned char *DB, *mask, *salt, *hash;
	unsigned long x, y, hLen, emLen, saltlen;
	int err;

	saltlen = sctx->desc->saltlen;
	hLen = isrcry_hash_len(sctx->desc->hash);
	emLen = (emBits >> 3) + (emBits & 7 ? 1 : 0);

	/* check sizes */
	if ((saltlen > emLen) || (emLen < hLen + saltlen + 2))
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
	if ((err = pkcs_1_mgf1(sctx, hash, hLen, mask, emLen - hLen - 1)))
		goto LBL_ERR;

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
			unsigned char *msghash, unsigned long msghashlen,
			const unsigned char *sig, unsigned long siglen,
			unsigned long emBits)
{
	unsigned char *DB, *mask, *salt, *hash;
	unsigned long x, y, hLen, emLen, saltlen;
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
	if ((err = pkcs_1_mgf1(sctx, hash, hLen, mask, emLen -
				hLen - 1)))
		goto LBL_ERR;

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
	void *p, *q, *tmp1, *tmp2, *tmp3;
	enum isrcry_result err;

	if (length < (MIN_RSA_SIZE / 8) || length > (MAX_RSA_SIZE / 8))
		return ISRCRY_INVALID_ARGUMENT;
	if (sctx->rctx == NULL)
		return ISRCRY_NEED_RANDOM;

	if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)))
		return err;
	key = malloc(sizeof(*key));
	if (key == NULL)
		return -1;

	/* make primes p and q (optimization provided by Wayne Scott) */
	mp_set_int(tmp3, RSA_E);		/* tmp3 = e */

	/* make prime "p" */
	do {
		if ((err = rand_prime(p, length / 2, sctx->rctx)))
			goto errkey;
		mp_sub_d(p, 1, tmp1);		/* tmp1 = p-1 */
		mp_gcd(tmp1, tmp3, tmp2);	/* tmp2 = gcd(p-1, e) */
	} while (mp_cmp_d(tmp2, 1));		/* while e divides p-1 */

	/* make prime "q" */
	do {
		if ((err = rand_prime(q, length / 2, sctx->rctx)))
			goto errkey;
		mp_sub_d(q, 1, tmp1);		/* tmp1 = q-1 */
		mp_gcd(tmp1, tmp3, tmp2);	/* tmp2 = gcd(q-1, e) */
	} while (mp_cmp_d(tmp2, 1));		/* while e divides q-1 */

	/* tmp1 = lcm(p-1, q-1) */
	mp_sub_d(p, 1, tmp2);			/* tmp2 = p-1 */
	/* tmp1 = q-1 (previous do/while loop) */
	mp_lcm(tmp1, tmp2, tmp1);		/* tmp1 = lcm(p-1, q-1) */

	/* make key */
	if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ,
				&key->dP, &key->qP, &key->p, &key->q,
				NULL)))
		goto errkey;

	mp_set_int(key->e, RSA_E);		/* key->e =  e */
	/* key->d = 1/e mod lcm(p-1,q-1) */
	if ((err = mp_invmod(key->e, tmp1, key->d)))
		goto errkey;
	mp_mul(p, q, key->N);			/* key->N = pq */

	/* optimize for CRT now */
	/* find d mod q-1 and d mod p-1 */
	mp_sub_d(p, 1, tmp1);			/* tmp1 = q-1 */
	mp_sub_d(q, 1, tmp2);			/* tmp2 = p-1 */
	mp_mod(key->d, tmp1, key->dP);		/* dP = d mod p-1 */
	mp_mod(key->d, tmp2, key->dQ);		/* dQ = d mod q-1 */
	if ((err = mp_invmod(q, p, key->qP)))
		goto errkey;
	/* qP = 1/q mod p */
	mp_copy(p, key->p);
	mp_copy(q, key->q);

	set_key(sctx, ISRCRY_KEY_PUBLIC, NULL);
	set_key(sctx, ISRCRY_KEY_PRIVATE, key);

	/* return ok and free temps */
	err = ISRCRY_OK;
	goto cleanup;
errkey:
	free_key(key);
cleanup:
	mp_clear_multi(tmp3, tmp2, tmp1, p, q, NULL);
	return err;
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
	enum isrcry_key_type found_type;
	int err;
	void *zero;
	unsigned char tmpbuf[MAX_RSA_SIZE * 8];
	unsigned long t, x, y, z, tmpoid[16];
	ltc_asn1_list ssl_pubkey_hashoid[2];
	ltc_asn1_list ssl_pubkey[2];

	/* init key */
	key = malloc(sizeof(*key));
	if (key == NULL)
		return -1;
	if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ,
				&key->dP, &key->qP, &key->p, &key->q,
				NULL))) {
		free(key);
		return err;
	}

	/* see if the OpenSSL DER format RSA public key will work */
	/* this includes the internal hash ID and optional params (NULL in
	   this case) */
	LTC_SET_ASN1(ssl_pubkey_hashoid, 0, LTC_ASN1_OBJECT_IDENTIFIER,
				tmpoid, sizeof(tmpoid) / sizeof(tmpoid[0]));
	LTC_SET_ASN1(ssl_pubkey_hashoid, 1, LTC_ASN1_NULL, NULL, 0);

	/* the actual format of the SSL DER key is odd, it stores a
	   RSAPublicKey in a **BIT** string ... so we have to extract it
	   then proceed to convert bit to octet 
	 */
	LTC_SET_ASN1(ssl_pubkey, 0, LTC_ASN1_SEQUENCE, &ssl_pubkey_hashoid,
				2);
	LTC_SET_ASN1(ssl_pubkey, 1, LTC_ASN1_BIT_STRING, tmpbuf,
				sizeof(tmpbuf));

	if (der_decode_sequence(in, inlen, ssl_pubkey, 2UL) == ISRCRY_OK) {
		/* ok now we have to reassemble the BIT STRING to an
		   OCTET STRING.  Thanks OpenSSL... */
		for (t = y = z = x = 0; x < ssl_pubkey[1].size; x++) {
			y = (y << 1) | tmpbuf[x];
			if (++z == 8) {
				tmpbuf[t++] = (unsigned char) y;
				y = 0;
				z = 0;
			}
		}
		/* continue... */
		in = tmpbuf;
		inlen = t;
	}

	/* try to match against PKCS #1 standards */
	if ((err = der_decode_sequence_multi(in, inlen,
				LTC_ASN1_INTEGER, 1UL, key->N,
				LTC_ASN1_EOL, 0UL, NULL)))
		goto LBL_ERR;

	if (mp_cmp_d(key->N, 0) == 0) {
		if ((err = mp_init(&zero)))
			goto LBL_ERR;
		/* it's a private key */
		if ((err = der_decode_sequence_multi(in, inlen,
					LTC_ASN1_INTEGER, 1UL, zero,
					LTC_ASN1_INTEGER, 1UL, key->N,
					LTC_ASN1_INTEGER, 1UL, key->e,
					LTC_ASN1_INTEGER, 1UL, key->d,
					LTC_ASN1_INTEGER, 1UL, key->p,
					LTC_ASN1_INTEGER, 1UL, key->q,
					LTC_ASN1_INTEGER, 1UL, key->dP,
					LTC_ASN1_INTEGER, 1UL, key->dQ,
					LTC_ASN1_INTEGER, 1UL, key->qP,
					LTC_ASN1_EOL, 0UL, NULL))) {
			mp_clear(zero);
			goto LBL_ERR;
		}
		mp_clear(zero);
		found_type = ISRCRY_KEY_PRIVATE;
	} else if (mp_cmp_d(key->N, 1) == 0) {
		/* we don't support multi-prime RSA */
		err = ISRCRY_BAD_FORMAT;
		goto LBL_ERR;
	} else {
		/* it's a public key and we lack e */
		if ((err = der_decode_sequence_multi(in, inlen,
					LTC_ASN1_INTEGER, 1UL, key->N,
					LTC_ASN1_INTEGER, 1UL, key->e,
					LTC_ASN1_EOL, 0UL, NULL))) {
			goto LBL_ERR;
		}
		found_type = ISRCRY_KEY_PUBLIC;
	}

	if (found_type != type) {
		err = ISRCRY_BAD_FORMAT;
		goto LBL_ERR;
	}
	set_key(sctx, type, key);
	return ISRCRY_OK;
LBL_ERR:
	free_key(key);
	return err;
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
	unsigned long zero=0;
	unsigned long outlen_l = *outlen;
	enum isrcry_result ret;

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

	if (type == ISRCRY_KEY_PRIVATE) {
		/* private key */
		/* output is 
		   Version, n, e, d, p, q, d mod (p-1), d mod (q - 1), 1/q mod p
		 */
		ret=der_encode_sequence_multi(out, &outlen_l,
					LTC_ASN1_SHORT_INTEGER, 1UL, &zero,
					LTC_ASN1_INTEGER, 1UL, key->N,
					LTC_ASN1_INTEGER, 1UL, key->e,
					LTC_ASN1_INTEGER, 1UL, key->d,
					LTC_ASN1_INTEGER, 1UL, key->p,
					LTC_ASN1_INTEGER, 1UL, key->q,
					LTC_ASN1_INTEGER, 1UL, key->dP,
					LTC_ASN1_INTEGER, 1UL, key->dQ,
					LTC_ASN1_INTEGER, 1UL, key->qP,
					LTC_ASN1_EOL, 0UL, NULL);
	} else {
		/* public key */
		ret=der_encode_sequence_multi(out, &outlen_l,
					LTC_ASN1_INTEGER, 1UL, key->N,
					LTC_ASN1_INTEGER, 1UL, key->e,
					LTC_ASN1_EOL, 0UL, NULL);
	}
	*outlen = outlen_l;
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
static int rsa_exptmod(const unsigned char *in, unsigned long inlen,
			unsigned char *out, unsigned long *outlen, int which,
			struct isrcry_rsa_key *key)
{
	void *tmp, *tmpa, *tmpb;
	unsigned long x;
	int err;

	/* init and copy into tmp */
	if ((err = mp_init_multi(&tmp, &tmpa, &tmpb, NULL)) != ISRCRY_OK)
		return err;
	mp_read_unsigned_bin(tmp, (unsigned char *) in, (int) inlen);

	/* sanity check on the input */
	if (mp_cmp(key->N, tmp) < 0) {
		err = ISRCRY_BAD_FORMAT;
		goto error;
	}

	/* are we using the private exponent and is the key optimized? */
	if (which == ISRCRY_KEY_PRIVATE) {
		/* tmpa = tmp^dP mod p */
		mp_exptmod(tmp, key->dP, key->p, tmpa);

		/* tmpb = tmp^dQ mod q */
		mp_exptmod(tmp, key->dQ, key->q, tmpb);

		/* tmp = (tmpa - tmpb) * qInv (mod p) */
		mp_sub(tmpa, tmpb, tmp);
		mp_mulmod(tmp, key->qP, key->p, tmp);

		/* tmp = tmpb + q * tmp */
		mp_mul(tmp, key->q, tmp);
		mp_add(tmp, tmpb, tmp);
	} else {
		/* exptmod it */
		mp_exptmod(tmp, key->e, key->N, tmp);
	}

	/* read it back */
	x = (unsigned long) mp_unsigned_bin_size(key->N);
	if (x > *outlen) {
		*outlen = x;
		err = ISRCRY_BUFFER_OVERFLOW;
		goto error;
	}

	/* this should never happen ... */
	if (mp_unsigned_bin_size(tmp) > mp_unsigned_bin_size(key->N)) {
		err = -1;
		goto error;
	}
	*outlen = x;

	/* convert it */
	memset(out, 0, x);
	mp_to_unsigned_bin(tmp, out + (x - mp_unsigned_bin_size(tmp)));

	/* clean up and return */
	err = ISRCRY_OK;
error:
	mp_clear_multi(tmp, tmpa, tmpb, NULL);
	return err;
}

static enum isrcry_result rsa_sign(struct isrcry_sign_ctx *sctx,
			unsigned char *out, unsigned *outlen)
{
	struct isrcry_rsa_key *key = sctx->privkey;
	unsigned hashlen = isrcry_hash_len(sctx->desc->hash);
	unsigned char hash[hashlen];
	unsigned long modulus_bitlen, modulus_bytelen, x, y;
	int err;

	if (sctx->rctx == NULL && sctx->desc->saltlen > 0 &&
				sctx->salt == NULL)
		return ISRCRY_NEED_RANDOM;
	if (key == NULL)
		return ISRCRY_NEED_KEY;

	/* get modulus len in bits */
	modulus_bitlen = mp_count_bits((key->N));

	/* outlen must be at least the size of the modulus */
	modulus_bytelen = mp_unsigned_bin_size((key->N));
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
	unsigned long modulus_bitlen, modulus_bytelen, x;
	int err;
	unsigned char *tmpbuf;
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
	modulus_bitlen = mp_count_bits((key->N));

	/* siglen must be equal to the size of the modulus */
	modulus_bytelen = mp_unsigned_bin_size((key->N));
	if (modulus_bytelen != siglen)
		return ISRCRY_BAD_FORMAT;

	/* allocate temp buffer for decoded sig */
	tmpbuf = malloc(siglen);
	if (tmpbuf == NULL)
		return -1;

	/* RSA decode it  */
	x = siglen;
	if ((err = rsa_exptmod(sig, siglen, tmpbuf, &x, ISRCRY_KEY_PUBLIC,
				key))) {
		free(tmpbuf);
		return err;
	}

	/* make sure the output is the right size */
	if (x != siglen) {
		free(tmpbuf);
		return ISRCRY_BAD_FORMAT;
	}
	sig_is_short = !((modulus_bitlen - 1) % 8);

	/* PSS decode and verify it */
	err = pkcs_1_pss_decode(sctx, hash, hashlen,
				sig_is_short ? tmpbuf + 1 : tmpbuf,
				sig_is_short ? x - 1 : x, modulus_bitlen - 1);

	free(tmpbuf);
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
