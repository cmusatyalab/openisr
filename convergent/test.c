#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "convergent-user.h"

int main(int argc, char **argv)
{
	int fd, ret, keyval;
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
	ret=ioctl(fd, ISR_REGISTER, &setup);
	if (ret) {
		perror("Registering device");
		return 1;
	}
	while (1) {
		ret=read(fd, &message, sizeof(message));
		if (ret != sizeof(message)) {
			printf("read() returned %d, expected %d", ret,
						sizeof(message));
			continue;
		}
		keyval=message.chunk % 256;
		printf("Chunk %llu key %d\n", message.chunk, keyval);
		memset(message.key, keyval, KEY_LEN);
		if (write(fd, &message, sizeof(message)) != sizeof(message))
			printf("Error on write\n");
	}
	printf("Exiting\n");
	return 0;
}
