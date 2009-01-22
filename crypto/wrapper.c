#include <string.h>
#include <unistd.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

static enum isrcry_result _isrcry_encrypt(const unsigned char *in,
			unsigned long inlen, unsigned char *out,
			unsigned long outlen, mode_fn *mode, cipher_fn *cipher,
			pad_fn *pad, unsigned blocklen, void *key,
			unsigned char *iv)
{
	enum isrcry_result ret;
	unsigned char lblock[blocklen];
	unsigned lblock_offset;
	unsigned lblock_len;

	if (in == NULL || out == NULL || key == NULL || iv == NULL)
		return ISRCRY_INVALID_ARGUMENT;
	lblock_len = inlen % blocklen;
	lblock_offset = inlen - lblock_len;
	if (outlen < lblock_offset + blocklen)
		return ISRCRY_INVALID_ARGUMENT;
	memcpy(lblock, in + lblock_offset, lblock_len);
	ret = pad(lblock, blocklen, lblock_len);
	if (ret)
		return ret;
	ret = mode(in, lblock_offset, out, cipher, blocklen, key, iv);
	if (ret)
		return ret;
	return mode(lblock, blocklen, out + lblock_offset, cipher, blocklen,
				key, iv);
}

static enum isrcry_result _isrcry_decrypt(const unsigned char *in,
			unsigned long inlen, unsigned char *out,
			unsigned long *outlen, mode_fn *mode,
			cipher_fn *cipher, unpad_fn *unpad, unsigned blocklen,
			void *key, unsigned char *iv)
{
	enum isrcry_result ret;
	unsigned char lblock[blocklen];
	unsigned lblock_offset;
	unsigned lblock_len;

	if (in == NULL || out == NULL || key == NULL || iv == NULL)
		return ISRCRY_INVALID_ARGUMENT;
	if (inlen == 0 || inlen % blocklen)
		return ISRCRY_INVALID_ARGUMENT;
	lblock_offset = inlen - blocklen;
	ret = mode(in, lblock_offset, out, cipher, blocklen, key, iv);
	if (ret)
		return ret;
	ret = mode(in + lblock_offset, blocklen, lblock, cipher, blocklen,
				key, iv);
	if (ret)
		return ret;
	ret = unpad(lblock, blocklen, &lblock_len);
	if (ret)
		return ret;
	memcpy(out + lblock_offset, lblock, lblock_len);
	*outlen = lblock_offset + lblock_len;
	return ISRCRY_OK;
}

#define NOPAD_WRAPPER(alg, mode, direction, blocksize) \
	exported enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## \
				direction (const unsigned char *in, \
				unsigned long len, unsigned char *out, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv) { \
		return _isrcry_ ## mode ## _ ## direction(in, len, out, \
					(cipher_fn *) _isrcry_ ## alg ## _ \
					## direction, blocksize, skey, iv); \
	}

#define ENCRYPT_WRAPPER(alg, mode, pad, blocksize) \
	exported enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## \
				pad ## _encrypt (const unsigned char *in, \
				unsigned long inlen, unsigned char *out, \
				unsigned long outlen, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv) { \
		return _isrcry_ ## encrypt(in, inlen, out, outlen, \
					_isrcry_ ## mode ## _encrypt, \
					(cipher_fn *) _isrcry_ ## alg ## _ ## \
					encrypt, _isrcry_ ## pad ## _pad, \
					blocksize, skey, iv); \
	}

#define DECRYPT_WRAPPER(alg, mode, pad, blocksize) \
	exported enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## \
				pad ## _decrypt (const unsigned char *in, \
				unsigned long inlen, unsigned char *out, \
				unsigned long *outlen, \
				struct isrcry_ ## alg ## _key *skey, \
				unsigned char *iv) { \
		return _isrcry_ ## decrypt(in, inlen, out, outlen, \
					_isrcry_ ## mode ## _decrypt, \
					(cipher_fn *) _isrcry_ ## alg ## _ ## \
					decrypt, _isrcry_ ## pad ## _unpad, \
					blocksize, skey, iv); \
	}

NOPAD_WRAPPER(aes, cbc, encrypt, ISRCRY_AES_BLOCKSIZE)
NOPAD_WRAPPER(aes, cbc, decrypt, ISRCRY_AES_BLOCKSIZE)
NOPAD_WRAPPER(blowfish, cbc, encrypt, ISRCRY_BLOWFISH_BLOCKSIZE)
NOPAD_WRAPPER(blowfish, cbc, decrypt, ISRCRY_BLOWFISH_BLOCKSIZE)

ENCRYPT_WRAPPER(aes, cbc, pkcs5, ISRCRY_AES_BLOCKSIZE)
DECRYPT_WRAPPER(aes, cbc, pkcs5, ISRCRY_AES_BLOCKSIZE)
ENCRYPT_WRAPPER(blowfish, cbc, pkcs5, ISRCRY_BLOWFISH_BLOCKSIZE)
DECRYPT_WRAPPER(blowfish, cbc, pkcs5, ISRCRY_BLOWFISH_BLOCKSIZE)
