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
