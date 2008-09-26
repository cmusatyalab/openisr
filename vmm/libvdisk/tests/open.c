#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

char* str="asdf\n";

int main(int argc, char **argv) {
	int fd;
	
	fd=open(argv[1], O_CREAT|O_WRONLY, 0644);
	if (fd == -1) {
		perror("Opening file");
		return 1;
	}
	write(fd, str, strlen(str));
	close(fd);
	return 0;
}
