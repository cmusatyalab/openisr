#ifndef LIBISRCRYPTO_CIPHER_H
#define LIBISRCRYPTO_CIPHER_H

enum isrcry_result _isrcry_aes_encrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_aes_key *skey);
enum isrcry_result _isrcry_aes_decrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_aes_key *skey);

enum isrcry_result _isrcry_blowfish_encrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_blowfish_key *skey);
enum isrcry_result _isrcry_blowfish_decrypt(const unsigned char *in,
			unsigned char *out, struct isrcry_blowfish_key *skey);

#endif
