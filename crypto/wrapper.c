#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

#define WRAPPER(alg, mode, direction, blocksize) \
	enum isrcry_result isrcry_ ## alg ## _ ## mode ## _ ## direction ( \
				const unsigned char *in, unsigned long len,
				unsigned char *out, \
				struct isrcry_ ## mode ## _key *skey, \
				unsigned char *iv) { \
		return _isrcry_cbc_encrypt(in, len, out, \
					_isrcry_ ## alg ## _ ## direction, \
					blocksize, skey, iv); \
	}
}

WRAPPER(aes, cbc, encrypt, ISRCRY_AES_BLOCKSIZE)
WRAPPER(aes, cbc, decrypt, ISRCRY_AES_BLOCKSIZE)
WRAPPER(blowfish, cbc, encrypt, ISRCRY_BLOWFISH_BLOCKSIZE)
WRAPPER(blowfish, cbc, decrypt, ISRCRY_BLOWFISH_BLOCKSIZE)
