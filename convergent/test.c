#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "convergent-user.h"

struct chunk {
	char key[MAX_HASH_LEN];
	unsigned length;
	unsigned compression;
};

static struct chunk *chunks;
static unsigned received_size;
static unsigned received;
static int pipefds[2];
static struct pollfd pollfds[2];

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

int main(int argc, char **argv)
{
	int fd, ret;
	unsigned u;
	struct isr_setup setup;
	struct isr_message message;
	
	if (argc != 6) {
		printf("Usage: %s ctldev chunkdev chunksize cachesize offset\n",
					argv[0]);
		return 1;
	}
	
	fd=open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("Opening file");
		return 1;
	}
	snprintf(setup.chunk_device, MAX_DEVICE_LEN, "%s", argv[2]);
	setup.chunksize=atoi(argv[3]);
	setup.cachesize=atoi(argv[4]);
	setup.offset=atoi(argv[5]);
	setup.cipher=ISR_CIPHER_BLOWFISH;
	setup.hash=ISR_HASH_SHA1;
	setup.compress_default=ISR_COMPRESS_ZLIB;
	setup.compress_required=ISR_COMPRESS_NONE | ISR_COMPRESS_ZLIB;
	ret=ioctl(fd, ISR_REGISTER, &setup);
	if (ret) {
		perror("Registering device");
		return 1;
	}
	printf("Allocating %llu KB\n",
				(setup.chunks * sizeof(struct chunk)) >> 10);
	chunks=malloc(setup.chunks * sizeof(struct chunk));
	if (chunks == NULL) {
		printf("malloc failed\n");
		return 1;
	}
	memset(chunks, 0, setup.chunks * sizeof(struct chunk));
	for (u=0; u<setup.chunks; u++) {
		chunks[u].length=setup.chunksize;
		chunks[u].compression=ISR_COMPRESS_NONE;
	}
	if (pipe(pipefds)) {
		perror("Creating pipe");
		return 1;
	}
	signal(SIGQUIT, &sighandler);
	signal(SIGINT, &sighandler);
	signal(SIGTERM, &sighandler);
	pollfds[0].fd=fd;
	pollfds[1].fd=pipefds[0];
	pollfds[0].events=pollfds[1].events=POLLIN;
	while (1) {
		ret=poll(pollfds, 2, -1);
		if (ret == -1 && errno == EINTR)
			continue;
		else if (ret == -1)
			perror("poll");
		if (pollfds[1].revents)
			break;
		if (!pollfds[0].revents)
			continue;
		ret=read(fd, &message, sizeof(message));
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
			if (write(fd, &message, sizeof(message)) !=
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
			break;
		default:
			printf("Unknown message type\n");
			continue;
		}
	}
	printf("Exiting\n");
	return 0;
}
