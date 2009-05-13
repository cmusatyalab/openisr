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

#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

exported const char *isrcry_strerror(enum isrcry_result result)
{
	switch (result) {
	case ISRCRY_OK:
		return "Success";
	case ISRCRY_INVALID_ARGUMENT:
		return "Invalid argument";
	case ISRCRY_BAD_PADDING:
		return "Bad padding";
	case ISRCRY_BAD_FORMAT:
		return "Invalid data format";
	case ISRCRY_BAD_SIGNATURE:
		return "Invalid signature";
	case ISRCRY_BUFFER_OVERFLOW:
		return "Buffer too short";
	case ISRCRY_NEED_RANDOM:
		return "Need random bytes but no randomness source specified";
	case ISRCRY_NEED_KEY:
		return "Required key has not been provided";
	}
	return "Unknown error";
}

enum isrcry_result isrcry_gen_prime(mpz_t out, struct isrcry_random_ctx *rctx,
			unsigned len)
{
	unsigned char buf[len];

	if (len < 2 || len > 512)
		return ISRCRY_INVALID_ARGUMENT;

	do {
		isrcry_random_bytes(rctx, buf, len);
		/* 0x80 makes sure the number is the specified number of bits.
		   What does 0x40 do? */
		buf[0]     |= 0x80 | 0x40;
		/* Make sure the number is odd */
		buf[len-1] |= 0x01;
		mpz_from_unsigned_bin(out, buf, len);
	} while (!mpz_probab_prime_p(out, 8));

	return ISRCRY_OK;
}
