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

struct params {
	char control_device[MAX_DEVICE_LEN];
	char chunk_device[MAX_DEVICE_LEN];
	unsigned chunksize;
	unsigned cachesize;
	unsigned long long offset;
	unsigned long long chunks;
};

struct chunk {
	char key[MAX_HASH_LEN];
	unsigned length;
	unsigned compression;
};

static unsigned received_size;
static unsigned received;
static int pipefds[2];

void printkey(char *key, int len)
{
	int i;
	
	for (i=0; i<len; i++)
		printf("%.2hhx", key[i]);
}

void sighandler(int signal)
{
	if (signal == SIGQUIT) {
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
	
	chunk.compression=ISR_COMPRESS_NONE;
	fprintf(stderr, "Initializing %llu chunks", params->chunks);
	for (tmp=0; tmp<params->chunks; tmp++) {
		if (!(tmp % 1000))
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

int run(char *storefile)
{
	int storefd, ctlfd, ret, dirty=0;
	struct isr_setup setup;
	struct isr_message message;
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
	memcpy(setup.chunk_device, params.chunk_device, MAX_DEVICE_LEN);
	setup.chunksize=params.chunksize;
	setup.cachesize=params.cachesize;
	setup.offset=params.offset;
	setup.cipher=ISR_CIPHER_BLOWFISH;
	setup.hash=ISR_HASH_SHA1;
	setup.compress_default=ISR_COMPRESS_ZLIB;
	setup.compress_required=ISR_COMPRESS_NONE | ISR_COMPRESS_ZLIB;
	ret=ioctl(ctlfd, ISR_REGISTER, &setup);
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
	signal(SIGQUIT, &sighandler);
	signal(SIGINT, &sighandler);
	signal(SIGTERM, &sighandler);
	pollfds[0].fd=ctlfd;
	pollfds[1].fd=pipefds[0];
	pollfds[0].events=pollfds[1].events=POLLIN;
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
			if (!ioctl(ctlfd, ISR_UNREGISTER))
				break;
		if (!(pollfds[0].revents & POLLIN))
			continue;
		
		ret=read(ctlfd, &message, sizeof(message));
		if (ret != sizeof(message)) {
			printf("read() returned %d, expected %d\n", ret,
						sizeof(message));
			continue;
		}
		switch (message.type) {
		case ISR_MSGTYPE_GET_META:
			printf("Sending   chunk %8llu key ", message.chunk);
			printkey(chunks[message.chunk].key, setup.hash_len);
			printf(" size %6u comp %u\n",
					chunks[message.chunk].length,
					chunks[message.chunk].compression);
			memcpy(message.key, chunks[message.chunk].key,
						setup.hash_len);
			message.length=chunks[message.chunk].length;
			message.compression=chunks[message.chunk].compression;
			message.type=ISR_MSGTYPE_SET_META;
			if (write(ctlfd, &message, sizeof(message)) !=
						sizeof(message))
				printf("Error on write\n");
			break;
		case ISR_MSGTYPE_UPDATE_META:
			printf("Receiving chunk %8llu key ", message.chunk);
			printkey(message.key, setup.hash_len);
			printf(" size %6u comp %u\n",
						message.length,
						message.compression);
			memcpy(chunks[message.chunk].key, message.key,
						setup.hash_len);
			chunks[message.chunk].length=message.length;
			chunks[message.chunk].compression=message.compression;
			received++;
			received_size += message.length;
			dirty=1;
			break;
		default:
			printf("Unknown message type\n");
			continue;
		}
	}
	printf("Exiting\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct params params;
	
	if (argc == 7) {
		memset(params.control_device, 0, MAX_DEVICE_LEN);
		memset(params.chunk_device, 0, MAX_DEVICE_LEN);
		snprintf(params.control_device, MAX_DEVICE_LEN, "%s", argv[2]);
		snprintf(params.chunk_device, MAX_DEVICE_LEN, "%s", argv[3]);
		params.chunksize=atoi(argv[4]);
		params.cachesize=atoi(argv[5]);
		params.offset=atoi(argv[6]);
		return setup(&params, argv[1]);
	} else if (argc == 2) {
		return run(argv[1]);
	} else {
		printf("Usage: %s storefile ctldev chunkdev chunksize "
					"cachesize offset\n", argv[0]);
		printf("Usage: %s storefile\n", argv[0]);
		return 1;
	}
}
