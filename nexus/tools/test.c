/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (TM)
 *         system
 * 
 * Copyright (C) 2006-2007 Carnegie Mellon University
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <openssl/evp.h>
#include "nexus.h"

#define CONTROL_DEV "/dev/openisrctl"
#define MESSAGE_BATCH 64

#define ONDISK_NONE 0x01
#define ONDISK_ZLIB 0x02
#define ONDISK_LZF  0x04

#define ONDISK_BF        0
#define ONDISK_BF_COMPAT 1
#define ONDISK_NOCRYPT   2
#define ONDISK_AES       3

struct params {
	char chunk_device[NEXUS_MAX_DEVICE_LEN];
	unsigned chunksize;
	unsigned cachesize;
	unsigned suite;
	unsigned long long offset;
	unsigned long long chunks;
};

struct chunk {
	unsigned char key[NEXUS_MAX_HASH_LEN];
	unsigned char tag[NEXUS_MAX_HASH_LEN];
	unsigned length;
	unsigned compression;
};

static unsigned received_size;
static unsigned received;
static int dirty;
static int pipefds[2];
static int verbosity=1;
static char *progname;

void printkey(unsigned char *key, int len)
{
	int i;
	
	for (i=0; i<len; i++)
		printf("%.2hhx", key[i]);
}

void sighandler(int signal)
{
	if (signal == SIGUSR1) {
		printf("Average compressed size: %.0f bytes\n",
					received_size * 1.0 / received);
	} else {
		/* Race-free method of catching signals */
		write(pipefds[1], "a", 1);
	}
}

enum nexus_compress comp_to_nexus(unsigned ondisk)
{
	switch (ondisk) {
	case ONDISK_NONE:
		return NEXUS_COMPRESS_NONE;
	case ONDISK_ZLIB:
		return NEXUS_COMPRESS_ZLIB;
	case ONDISK_LZF:
		return NEXUS_COMPRESS_LZF;
	default:
		printf("Invalid compression type\n");
		return -1;
	}
}

unsigned comp_to_ondisk(enum nexus_compress compress)
{
	switch (compress) {
	case NEXUS_COMPRESS_NONE:
		return ONDISK_NONE;
	case NEXUS_COMPRESS_ZLIB:
		return ONDISK_ZLIB;
	case NEXUS_COMPRESS_LZF:
		return ONDISK_LZF;
	case NEXUS_NR_COMPRESS:
		printf("Invalid compression type\n");
	}
	return -1;
}

enum nexus_crypto suite_to_nexus(unsigned ondisk)
{
	switch (ondisk) {
	case ONDISK_BF:
		return NEXUS_CRYPTO_BLOWFISH_SHA1;
	case ONDISK_BF_COMPAT:
		return NEXUS_CRYPTO_BLOWFISH_SHA1_COMPAT;
	case ONDISK_AES:
		return NEXUS_CRYPTO_AES_SHA1;
	case ONDISK_NOCRYPT:
		return NEXUS_CRYPTO_NONE_SHA1;
	default:
		printf("Invalid compression type\n");
		return -1;
	}
}

int setup(struct params *params, char *storefile)
{
	int storefd, chunkfd;
	unsigned long long tmp;
	unsigned char *data;
	unsigned char *crypted;
	EVP_CIPHER_CTX cipher;
	EVP_MD_CTX hash;
	unsigned char iv[16];
	unsigned keylen;
	struct chunk chunk;
	
	storefd=open(storefile, O_CREAT|O_WRONLY|O_TRUNC, 0600);
	if (storefd < 0) {
		perror("Opening store file");
		return 1;
	}
	chunkfd=open(params->chunk_device, O_WRONLY);
	if (chunkfd < 0) {
		perror("Opening chunk device");
		return 1;
	}
	
	if (ioctl(chunkfd, BLKGETSIZE64, &tmp)) {
		perror("Getting chunk device size");
		return 1;
	}
	if (params->offset * 512 >= tmp) {
		printf("Offset beyond end of device\n");
		return 1;
	}
	params->chunks = ((tmp - (params->offset * 512)) &
				~((unsigned long long)params->chunksize - 1))
				/ params->chunksize;
	
	if (write(storefd, params, sizeof(*params)) != sizeof(*params)) {
		perror("Writing to store file");
		return 1;
	}
	
	data=malloc(params->chunksize);
	crypted=malloc(params->chunksize);
	if (data == NULL || crypted == NULL) {
		printf("Couldn't allocate buffer\n");
		return 1;
	}
	memset(data, 0, params->chunksize);
	if (params->suite != ONDISK_NOCRYPT) {
		EVP_DigestInit(&hash, EVP_sha1());
		EVP_DigestUpdate(&hash, data, params->chunksize);
		EVP_DigestFinal(&hash, chunk.key, &keylen);
		memset(iv, 0, sizeof(iv));
		if (params->suite == ONDISK_BF_COMPAT ||
					params->suite == ONDISK_AES)
			keylen=16;
		EVP_CIPHER_CTX_init(&cipher);
		if (params->suite == ONDISK_AES)
			EVP_EncryptInit_ex(&cipher, EVP_aes_128_cbc(), NULL,
						NULL, NULL);
		else
			EVP_EncryptInit_ex(&cipher, EVP_bf_cbc(), NULL, NULL,
						NULL);
		EVP_CIPHER_CTX_set_key_length(&cipher, keylen);
		EVP_CIPHER_CTX_set_padding(&cipher, 0);
		EVP_EncryptInit_ex(&cipher, NULL, NULL, chunk.key, iv);
		EVP_EncryptUpdate(&cipher, crypted, (int*)&chunk.length,
					data, params->chunksize);
		/* second and third arguments are irrelevant but must exist */
		EVP_EncryptFinal(&cipher, data, (int*)data);
	} else {
		memset(chunk.key, 0, sizeof(chunk.key));
		chunk.length=params->chunksize;
		crypted=data;
	}
	EVP_DigestInit(&hash, EVP_sha1());
	EVP_DigestUpdate(&hash, crypted, params->chunksize);
	EVP_DigestFinal(&hash, chunk.tag, &keylen);
	
	chunk.compression=ONDISK_NONE;
	fprintf(stderr, "Initializing %llu chunks", params->chunks);
	for (tmp=0; tmp<params->chunks; tmp++) {
		if (!(tmp % (params->chunks / 20)))
			fprintf(stderr, ".");
		if (write(chunkfd, crypted, params->chunksize)
					!= (int)params->chunksize) {
			perror("Writing to chunk device");
			return 1;
		}
		if (write(storefd, &chunk, sizeof(chunk)) != sizeof(chunk)) {
			perror("Writing to store file");
			return 1;
		}
	}
	fsync(chunkfd);
	fprintf(stderr, "done\n");
	
	return 0;
}

/* Returns true if a reply needs to be sent */
int handle_message(struct chunk *chunk, struct nexus_message *message,
				struct nexus_message *message_out,
				unsigned hash_len)
{
	enum nexus_compress comp;
	
	switch (message->type) {
	case NEXUS_MSGTYPE_GET_META:
		comp=comp_to_nexus(chunk->compression);
		if (verbosity > 1) {
			printf("Sending   chunk %8llu key ", message->chunk);
			printkey(chunk->key, hash_len);
			printf(" tag ");
			printkey(chunk->tag, hash_len);
			printf(" size %6u comp %u\n", chunk->length, comp);
		}
		memcpy(message_out->key, chunk->key, hash_len);
		memcpy(message_out->tag, chunk->tag, hash_len);
		message_out->chunk=message->chunk;
		message_out->length=chunk->length;
		message_out->compression=comp;
		message_out->type=NEXUS_MSGTYPE_SET_META;
		return 1;
	case NEXUS_MSGTYPE_UPDATE_META:
		if (verbosity > 1) {
			printf("Receiving chunk %8llu key ", message->chunk);
			printkey(message->key, hash_len);
			printf(" tag ");
			printkey(message->tag, hash_len);
			printf(" size %6u comp %u\n", message->length,
						message->compression);
		}
		memcpy(chunk->key, message->key, hash_len);
		memcpy(chunk->tag, message->tag, hash_len);
		chunk->length=message->length;
		chunk->compression=comp_to_ondisk(message->compression);
		received++;
		received_size += message->length;
		dirty=1;
		return 0;
	default:
		printf("Unknown message type %x\n", message->type);
		return 0;
	}
}

int run(char *storefile, enum nexus_compress compress)
{
	int storefd, ctlfd, ret, count, in, out;
	struct nexus_setup setup;
	struct nexus_message message_in[MESSAGE_BATCH];
	struct nexus_message message_out[MESSAGE_BATCH];
	struct params params;
	struct chunk *chunks;
	struct pollfd pollfds[2];
	void *mapped;
	unsigned storefilelen;
	
	storefd=open(storefile, O_RDWR);
	if (storefd < 0) {
		perror("Opening store file");
		return 1;
	}
	if (read(storefd, &params, sizeof(params)) != sizeof(params)) {
		perror("Reading store file header");
		return 1;
	}
	if (!strcmp(params.chunk_device, "/dev/openisrctl")) {
		printf("Old-format store file detected; aborting\n");
		return 1;
	}
	ctlfd=open(CONTROL_DEV, O_RDWR);
	if (ctlfd < 0) {
		perror("Opening device");
		return 1;
	}
	memcpy(setup.chunk_device, params.chunk_device, NEXUS_MAX_DEVICE_LEN);
	setup.chunksize=params.chunksize;
	setup.cachesize=params.cachesize;
	setup.offset=params.offset;
	setup.crypto=suite_to_nexus(params.suite);
	setup.compress_default=compress;
	setup.compress_required=(1 << NEXUS_COMPRESS_NONE) |
				(1 << NEXUS_COMPRESS_ZLIB) |
				(1 << NEXUS_COMPRESS_LZF);
	ret=ioctl(ctlfd, NEXUS_IOC_REGISTER, &setup);
	if (ret) {
		perror("Registering device");
		return 1;
	}
	if (setup.chunks != params.chunks) {
		printf("Chunk count conflict: we say %llu, kernel says %llu\n",
					params.chunks, setup.chunks);
		return 1;
	}
	printf("Bound to /dev/openisr%c\n", 'a' + setup.index);
	storefilelen=sizeof(struct params) +
				setup.chunks * sizeof(struct chunk);
	printf("Mapping %u KB\n", storefilelen >> 10);
	mapped=mmap(NULL, storefilelen, PROT_READ|PROT_WRITE,
				MAP_SHARED|MAP_POPULATE, storefd, 0);
	if (mapped == MAP_FAILED) {
		perror("mmap failed");
		return 1;
	}
	chunks=mapped + sizeof(params);
	if (pipe(pipefds)) {
		perror("Creating pipe");
		return 1;
	}
	signal(SIGUSR1, &sighandler);
	signal(SIGINT, &sighandler);
	signal(SIGTERM, &sighandler);
	pollfds[0].fd=ctlfd;
	pollfds[1].fd=pipefds[0];
	pollfds[0].events=pollfds[1].events=POLLIN;
	printf("Starting\n");
	while (1) {
		ret=poll(pollfds, 2, 1000);
		if (ret == -1 && errno == EINTR) {
			continue;
		} else if (ret == -1) {
			perror("poll");
		} else if (ret == 0 && dirty) {
			printf("Sync\n");
			if (msync(mapped, storefilelen, MS_ASYNC))
				perror("Writing store file");
			dirty=0;
		} else if (ret == 0) {
			continue;
		}
		if (pollfds[1].revents) {
			pollfds[1].events=0;
			pollfds[0].events |= POLLPRI;
			printf("Shutdown requested\n");
		}
		if (pollfds[0].revents & POLLPRI)
			if (!ioctl(ctlfd, NEXUS_IOC_UNREGISTER))
				break;
		if (pollfds[0].revents & POLLERR) {
			printf("Device no longer exists\n");
			break;
		}
		if (!(pollfds[0].revents & POLLIN))
			continue;
		
		count=read(ctlfd, &message_in, sizeof(message_in));
		if (count < 0 || (count % sizeof(message_in[0]))) {
			printf("read() returned %d, message size %d\n", ret,
						(int)sizeof(message_in[0]));
			continue;
		}
		count /= sizeof(message_in[0]);
		if (verbosity > 0)
			printf("Read %d\n", count);
		for (in=0, out=0; in<count; in++) {
			if (handle_message(&chunks[message_in[in].chunk],
						&message_in[in],
						&message_out[out],
						setup.hash_len))
				out++;
		}
		if (out) {
			if (verbosity > 0)
				printf("Write %d\n", out);
			out *= sizeof(message_out[0]);
			if (write(ctlfd, &message_out, out) != out)
				printf("Error on write\n");
		}
	}
	printf("Shutdown complete; Ctrl-C again to exit\n");
	/* Statistics still available from sysfs */
	pause();
	printf("Exiting\n");
	return 0;
}

int usage(void)
{
	printf("Usage: %s -s storefile chunkdev chunksize cachesize offset "
				"{bf|bf-compat|aes|none}\n", progname);
	printf("Usage: %s [-v|-q] storefile {none|zlib|lzf}\n", progname);
	return 1;
}

int main(int argc, char **argv)
{
	struct params params;
	enum nexus_compress compress;
	int opt;
	int do_setup=0;
	
	progname=argv[0];
	while ((opt=getopt(argc, argv, "vqs")) != -1) {
		switch (opt) {
		case 'v':
			verbosity++;
			break;
		case 'q':
			verbosity--;
			break;
		case 's':
			do_setup=1;
			break;
		case '?':
			return usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (do_setup) {
		if (argc != 6)
			return usage();
		memset(params.chunk_device, 0, NEXUS_MAX_DEVICE_LEN);
		snprintf(params.chunk_device, NEXUS_MAX_DEVICE_LEN, "%s",
					argv[1]);
		params.chunksize=atoi(argv[2]);
		params.cachesize=atoi(argv[3]);
		params.offset=atoi(argv[4]);
		if (!strcmp(argv[5], "bf"))
			params.suite=ONDISK_BF;
		else if (!strcmp(argv[5], "bf-compat"))
			params.suite=ONDISK_BF_COMPAT;
		else if (!strcmp(argv[5], "aes"))
			params.suite=ONDISK_AES;
		else if (!strcmp(argv[5], "none"))
			params.suite=ONDISK_NOCRYPT;
		else
			return usage();
		return setup(&params, argv[0]);
	} else {
		if (argc != 2)
			return usage();
		if (!strcmp(argv[1], "none"))
			compress=NEXUS_COMPRESS_NONE;
		else if (!strcmp(argv[1], "zlib"))
			compress=NEXUS_COMPRESS_ZLIB;
		else if (!strcmp(argv[1], "lzf"))
			compress=NEXUS_COMPRESS_LZF;
		else
			return usage();
		return run(argv[0], compress);
	}
}
