#ifndef ISRCRY_TEST_VECTORS_H
#define ISRCRY_TEST_VECTORS_H

#include <stdint.h>

#define MEMBERS(a) (sizeof(a)/sizeof((a)[0]))

struct ecb_test {
	uint8_t key[16];
	uint8_t plain[16];
	uint8_t cipher[16];
};

struct key_test {
	int keylen;
	uint8_t cipher[16];
	uint8_t key[24];
};

struct key_tests {
	uint8_t plain[16];
	const struct key_test *tests;
	unsigned count;
};

struct chain_test {
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t plain[128];
	uint8_t cipher[128];
	unsigned plainlen;
};

#endif
