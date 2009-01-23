#ifndef ISRCRY_TEST_VECTORS_H
#define ISRCRY_TEST_VECTORS_H

#include <stdint.h>

#define MEMBERS(a) (sizeof(a)/sizeof((a)[0]))

struct ecb_test {
	uint8_t key[32];
	uint8_t plain[16];
	uint8_t cipher[16];
	unsigned keylen;
};

struct chain_test {
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t plain[128];
	uint8_t cipher[128];
	unsigned plainlen;
	unsigned keylen;
};

struct monte_test {
	uint8_t out[16];
	unsigned keylen;
	unsigned ngroups;
	unsigned niters;
	int encrypt;
};

struct hash_test {
	uint8_t data[512];
	unsigned len;
	uint8_t hash[64];
};

struct hash_monte_test {
	uint8_t seed[64];
	unsigned ngroups;
	unsigned niters;
	uint8_t hash[64];
};

#endif
