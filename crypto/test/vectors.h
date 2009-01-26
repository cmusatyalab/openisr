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
