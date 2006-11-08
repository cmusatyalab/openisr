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
#include "convergent-user.h"

#define MESSAGE_BATCH 64

struct params {
	char control_device[ISR_MAX_DEVICE_LEN];
	char chunk_device[ISR_MAX_DEVICE_LEN];
	unsigned chunksize;
	unsigned cachesize;
	unsigned long long offset;
	unsigned long long chunks;
};

struct chunk {
	char key[ISR_MAX_HASH_LEN];
	char tag[ISR_MAX_HASH_LEN];
	unsigned length;
	unsigned compression;
};

static unsigned received_size;
static unsigned received;
static int dirty;
static int pipefds[2];
static int verbose=1;

void printkey(char *key, int len)
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

int setup(struct params *params, char *storefile)
{
	int storefd, chunkfd;
	unsigned long long tmp;
	char *data;
	char *crypted;
	EVP_CIPHER_CTX cipher;
	EVP_MD_CTX hash;
	char iv[8];
	int keylen;
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
	EVP_DigestInit(&hash, EVP_sha1());
	EVP_DigestUpdate(&hash, data, params->chunksize);
	EVP_DigestFinal(&hash, chunk.key, &keylen);
	memset(iv, 0, sizeof(iv));
	EVP_CIPHER_CTX_init(&cipher);
	EVP_EncryptInit_ex(&cipher, EVP_bf_cbc(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_set_key_length(&cipher, keylen);
	EVP_CIPHER_CTX_set_padding(&cipher, 0);
	EVP_EncryptInit_ex(&cipher, NULL, NULL, chunk.key, iv);
	EVP_EncryptUpdate(&cipher, crypted, &chunk.length,
				data, params->chunksize);
	/* second and third arguments are irrelevant but must exist */
	EVP_EncryptFinal(&cipher, data, (int*)data);
	EVP_DigestInit(&hash, EVP_sha1());
	EVP_DigestUpdate(&hash, crypted, params->chunksize);
	EVP_DigestFinal(&hash, chunk.tag, &keylen);
	
	chunk.compression=ISR_COMPRESS_NONE;
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
int handle_message(struct chunk *chunk, struct isr_message *message,
				struct isr_message *message_out,
				unsigned hash_len)
{
	switch (message->type) {
	case ISR_MSGTYPE_GET_META:
		if (verbose) {
			printf("Sending   chunk %8llu key ", message->chunk);
			printkey(chunk->key, hash_len);
			printf(" tag ");
			printkey(chunk->tag, hash_len);
			printf(" size %6u comp %u\n", chunk->length,
						chunk->compression);
		}
		memcpy(message_out->key, chunk->key, hash_len);
		memcpy(message_out->tag, chunk->tag, hash_len);
		message_out->chunk=message->chunk;
		message_out->length=chunk->length;
		message_out->compression=chunk->compression;
		message_out->type=ISR_MSGTYPE_SET_META;
		return 1;
	case ISR_MSGTYPE_UPDATE_META:
		if (verbose) {
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
		chunk->compression=message->compression;
		received++;
		received_size += message->length;
		dirty=1;
		return 0;
	default:
		printf("Unknown message type %x\n", message->type);
		return 0;
	}
}

int run(char *storefile, compress_t compress)
{
	int storefd, ctlfd, ret, count, in, out;
	struct isr_setup setup;
	struct isr_message message_in[MESSAGE_BATCH];
	struct isr_message message_out[MESSAGE_BATCH];
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
	ctlfd=open(params.control_device, O_RDWR);
	if (ctlfd < 0) {
		perror("Opening device");
		return 1;
	}
	memcpy(setup.chunk_device, params.chunk_device, ISR_MAX_DEVICE_LEN);
	setup.chunksize=params.chunksize;
	setup.cachesize=params.cachesize;
	setup.offset=params.offset;
	setup.cipher=ISR_CIPHER_BLOWFISH;
	setup.hash=ISR_HASH_SHA1;
	setup.compress_default=compress;
	setup.compress_required=ISR_COMPRESS_NONE | ISR_COMPRESS_ZLIB |
				ISR_COMPRESS_LZF;
	ret=ioctl(ctlfd, ISR_IOC_REGISTER, &setup);
	if (ret) {
		perror("Registering device");
		return 1;
	}
	if (setup.chunks != params.chunks) {
		printf("Chunk count conflict: we say %llu, kernel says %llu\n",
					params.chunks, setup.chunks);
		return 1;
	}
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
			if (!ioctl(ctlfd, ISR_IOC_UNREGISTER))
				break;
		if (!(pollfds[0].revents & POLLIN))
			continue;
		
		count=read(ctlfd, &message_in, sizeof(message_in));
		if (count < 0 || (count % sizeof(message_in[0]))) {
			printf("read() returned %d, message size %d\n", ret,
						sizeof(message_in[0]));
			continue;
		}
		count /= sizeof(message_in[0]);
		printf("Read %d\n", count);
		for (in=0, out=0; in<count; in++) {
			if (handle_message(&chunks[message_in[in].chunk],
						&message_in[in],
						&message_out[out],
						setup.hash_len))
				out++;
		}
		if (out) {
			printf("Write %d\n", out);
			out *= sizeof(message_out[0]);
			if (write(ctlfd, &message_out, out) != out)
				printf("Error on write\n");
		}
	}
	printf("Exiting\n");
	return 0;
}

int usage(char *prog)
{
	printf("Usage: %s storefile ctldev chunkdev chunksize "
				"cachesize offset\n", prog);
	printf("Usage: %s storefile {none|zlib|lzf}\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	struct params params;
	compress_t compress;
	
	if (argc == 7) {
		memset(params.control_device, 0, ISR_MAX_DEVICE_LEN);
		memset(params.chunk_device, 0, ISR_MAX_DEVICE_LEN);
		snprintf(params.control_device, ISR_MAX_DEVICE_LEN, "%s",
					argv[2]);
		snprintf(params.chunk_device, ISR_MAX_DEVICE_LEN, "%s",
					argv[3]);
		params.chunksize=atoi(argv[4]);
		params.cachesize=atoi(argv[5]);
		params.offset=atoi(argv[6]);
		return setup(&params, argv[1]);
	} else if (argc == 3) {
		if (!strcmp(argv[2], "none"))
			compress=ISR_COMPRESS_NONE;
		else if (!strcmp(argv[2], "zlib"))
			compress=ISR_COMPRESS_ZLIB;
		else if (!strcmp(argv[2], "lzf"))
			compress=ISR_COMPRESS_LZF;
		else
			return usage(argv[0]);
		return run(argv[1], compress);
	} else {
		return usage(argv[0]);
	}
}
