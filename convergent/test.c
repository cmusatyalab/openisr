#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "convergent-user.h"

int main(int argc, char **argv)
{
	int fd, ret;
	struct isr_setup setup;
	
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
	pause();
	return 0;
}
