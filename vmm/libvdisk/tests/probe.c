#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int fd, ret;
	struct hd_driveid id;
	struct hd_geometry geo;
	
	if (argc != 2) {
		printf("Usage: %s <whole-disk-device>\n", argv[0]);
		return 1;
	}
	fd=open(argv[1], O_RDONLY|O_NONBLOCK);
	if (fd == -1) {
		perror("Opening disk device");
		return 1;
	}
	memset(&id, 0, sizeof(id));
	ret=ioctl(fd, HDIO_GETGEO, &geo);
	printf("%d\n", ret);
	ret=ioctl(fd, HDIO_GET_IDENTITY, &id);
	printf("%d\n", ret);
	close(fd);
	return 0;
}
