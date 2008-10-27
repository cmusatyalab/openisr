#ifndef LIBISRCRYPTO_DEFS_H
#define LIBISRCRYPTO_DEFS_H

#ifndef LIBISRCRYPTO_INTERNAL
#error This header is for internal use by libisrcrypto
#endif

int (cipher_fn)(const unsigned char *in, unsigned char *out, void *skey)

enum isrcry_result _isrcry_cbc_encrypt(const unsigned char *in,
			unsigned long len, unsigned char *out,
			cipher_fn *encrypt, unsigned blocklen, void *key,
			unsigned char *iv);
enum isrcry_result _isrcry_cbc_decrypt(const unsigned char *in,
			unsigned long len, unsigned char *out,
			cipher_fn *decrypt, unsigned blocklen, void *key,
			unsigned char *iv);


enum isrcry_result _isrcry_aes_encrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_aes_key *skey);
enum isrcry_result _isrcry_aes_decrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_aes_key *skey);

enum isrcry_result _isrcry_blowfish_encrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_blowfish_key *skey);
enum isrcry_result _isrcry_blowfish_decrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_blowfish_key *skey);

#endif
