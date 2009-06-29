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

/* This file is adapted from Coda RPC2, whose license block follows. */

/* BLURB lgpl
			Coda File System
			    Release 6

	    Copyright (c) 2006 Carnegie Mellon University
		  Additional copyrights listed below

This  code  is  distributed "AS IS" without warranty of any kind under
the  terms of the  GNU  Library General Public Licence  Version 2,  as
shown in the file LICENSE. The technical and financial contributors to
Coda are listed in the file CREDITS.

			Additional copyrights
#*/

#include <sys/types.h>
#include <sys/times.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include "isrcrypto.h"
#define LIBISRCRYPTO_INTERNAL
#include "internal.h"

/*
 * Strong pseudo random number generator using AES as a mixing function.
 *
 * Based on,
 * - Digital Signatures Using Revisible Public Key Cryptography for the
 *   Financial Services Industry (rDSA), ANSI X9.31-1988, September 1998.
 * - NIST-Recommended Random Number Generator Based on ANSI X9.31 Appendix
 *   A.2.4 Using the 3-Key Triple DES and AES Algorithms, 31 January 2005.
 *
 * There is a 16-byte pool of random data that we use as the IV. Then when
 * we want to get random data we generate an initial seed based on the
 * current timestamp, some uninitialized data from the stack, and a counter.
 * 
 * This block is then encrypted using AES-CBC where the pool is used as the
 * IV. This results in a block of 16-bytes of random data. The random block
 * is then xor-ed with the original seed to get the next block of seed
 * data. We then refresh the pool of random data by encrypting the seed
 * block. These steps are repeated until we've returned the number of
 * random bytes that were requested.
 * 
 * To initialize the pool of random data and the AES128 encryption key, we
 * get the current timestamp, and read random data from /dev/random (or
 * /dev/urandom). When /dev/random is unavailable we fall back on several
 * lower entropy sources such as times(), getpid(), and libc's random().
 * 
 * The first block of random data is discarded, and we run a couple of
 * statistical tests to see if the resulting random data actually looks
 * reasonable. Passing these tests does not guarantee that the generated
 * random numbers are cryptographically strong, but it should detect
 * serious breakage.
 */

#define AES_BLOCK_SIZE 16
#define RND_KEY_LEN 16 /* or 24, 32 */
#define INITIAL_SEED_LENGTH (AES_BLOCK_SIZE + RND_KEY_LEN)
#define RANDOM_DEVICE "/dev/urandom"

struct isrcry_random_ctx {
	pthread_mutex_t lock;
	struct isrcry_cipher_ctx *aes;
	uint8_t pool[16];
	uint8_t last[16];
	uint32_t counter;
};

/* we need to find between 32 and 48 bytes of entropy to seed our PRNG
 * depending on the value of RNG_KEY_BITS */
static void get_initial_seed(uint8_t *ptr, size_t len)
{
    int fd;

    /* about 8 bytes from the current time */
    if (len >= sizeof(struct timeval)) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	memcpy(ptr, &tv, sizeof(struct timeval));
	ptr += sizeof(struct timeval);
	len -= sizeof(struct timeval);
    }

    /* try to get the rest from /dev/random */
    fd = open(RANDOM_DEVICE, O_RDONLY);
    if (fd != -1) {
	ssize_t n = read(fd, ptr, len);
	if (n > 0) {
	    ptr += n;
	    len -= n;
	}
	close(fd);
	/* we should be done now, but fall through just in case... */
    }

    /* we can get about 20 bytes from times(). I assume these would be rather
     * non-random since we probably just started, on the other hand, the
     * returned ticks value should be clock ticks since system boot, which
     * might be more random depending on whether we just rebooted or not. */
    if (len >= sizeof(clock_t) + sizeof(struct tms)) {
	struct tms tms;
	clock_t ticks = times(&tms);
	memcpy(ptr, &ticks, sizeof(clock_t));
	ptr += sizeof(clock_t);
	memcpy(ptr, &tms, sizeof(struct tms));
	ptr += sizeof(struct tms);
	len -= sizeof(struct tms) + sizeof(clock_t);
    }

    /* mix in the process id, probably not so random right after boot either */
    if (len >= sizeof(pid_t)) {
	pid_t pid = getpid();
	memcpy(ptr, &pid, sizeof(pid_t));
	ptr += sizeof(pid_t);
	len -= sizeof(pid_t);
    }

    /* we _really_ should be done by now, but just in case someone changed
     * RND_KEY_LEN.. Supposedly the top-8 bits in the random() result are
     * 'more random', which is why we use (random()*255)/RAND_MAX */
    if (len) {
	srandom(time(NULL));
	while (len--)
	    *(ptr++) = (uint8_t)(((double)random() * 255) / (double)RAND_MAX);
    }

    /* /dev/random is probably the most randomized source, but just in case
     * it is malfunctioning still get the gettimeofday value first. If
     * /dev/random doesn't exist we fall back on several more predictable
     * sources. The first 16 bytes are used to seed the pool, the remaining
     * RND_KEY_LEN initialize the AES-key for the mixing function. */

    /* other possible sources? getrusage(), system memory usage? checksum of
     * /proc/{interrupts,meminfo,slabinfo,vmstat}?
     * Windows might want to use CryptGenRandom() and GlobalMemoryStatus()
     */
}

exported struct isrcry_random_ctx *isrcry_random_alloc(void)
{
    struct isrcry_random_ctx *rctx;
    uint8_t initial_seed[INITIAL_SEED_LENGTH];
    uint8_t tmp[AES_BLOCK_SIZE];

    rctx = g_slice_new0(struct isrcry_random_ctx);

    rctx->aes = isrcry_cipher_alloc(ISRCRY_CIPHER_AES, ISRCRY_MODE_ECB);
    if (rctx->aes == NULL) {
	g_slice_free(struct isrcry_random_ctx, rctx);
	return NULL;
    }
    get_initial_seed(initial_seed, INITIAL_SEED_LENGTH);

    memcpy(rctx->pool, initial_seed, AES_BLOCK_SIZE);
    isrcry_cipher_init(rctx->aes, ISRCRY_ENCRYPT,
                       initial_seed + AES_BLOCK_SIZE, RND_KEY_LEN, NULL);
    pthread_mutex_init(&rctx->lock, NULL);

    /* discard the first block of random data per FIPS 140-2 */
    isrcry_random_bytes(rctx, tmp, sizeof(tmp));

    return rctx;
}

exported void isrcry_random_bytes(struct isrcry_random_ctx *rctx, void *buffer,
	                   unsigned length)
{
    uint8_t *random = buffer;
    uint8_t tmp[AES_BLOCK_SIZE], *I, *prev = rctx->last;
    struct {
	struct timeval tv;
	uint32_t uninitialized_stack_value;
	uint32_t counter;
    } init;
    int nblocks = (length + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int i;
    
    pthread_mutex_lock(&rctx->lock);
    
    /* Mix some entropy into the pool */
    gettimeofday(&init.tv, NULL);
    init.counter = rctx->counter++;
    I = (uint8_t *)&init;
    isrcry_cipher_process(rctx->aes, I, AES_BLOCK_SIZE, I);

    while (nblocks--) {
	for (i = 0; i < 4; i++)
	    ((uint32_t *)rctx->pool)[i] ^= ((uint32_t *)I)[i];

	if (!nblocks && length != AES_BLOCK_SIZE) {
	    isrcry_cipher_process(rctx->aes, rctx->pool, AES_BLOCK_SIZE, tmp);
	    memcpy(random, tmp, length);
	    random = tmp;
	} else
	    isrcry_cipher_process(rctx->aes, rctx->pool, AES_BLOCK_SIZE, random);

	/* reseed the pool, mix in the random value */
	for (i = 0; i < 4; i++)
	    ((uint32_t *)I)[i] ^= ((uint32_t *)random)[i];
	isrcry_cipher_process(rctx->aes, I, AES_BLOCK_SIZE, rctx->pool);

	/* we must never return consecutive identical blocks per FIPS 140-2 */
	g_assert(memcmp(prev, random, AES_BLOCK_SIZE) != 0);

	prev = random;
	random += AES_BLOCK_SIZE;
	length -= AES_BLOCK_SIZE;
    }
    if (prev != rctx->last)
	memcpy(rctx->last, prev, AES_BLOCK_SIZE);
    
    pthread_mutex_unlock(&rctx->lock);
}

exported void isrcry_random_free(struct isrcry_random_ctx *rctx)
{
    pthread_mutex_destroy(&rctx->lock);
    isrcry_cipher_free(rctx->aes);
    g_slice_free(struct isrcry_random_ctx, rctx);
}
