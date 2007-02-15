#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char pairToBin(char hexpair[])
{
	char buf[3];
	unsigned i;
	buf[0]=hexpair[0];
	buf[1]=hexpair[1];
	buf[2]=0;
	sscanf(buf, "%x", &i);
	return (char)i;
}

void toBin(char arr[], char *out)
{
	int i;
	for (i=0; i<20; i++)
		out[i]=pairToBin(arr + 2 * i);
}

void get(int fd, char *out)
{
	char buf[41];
	
	if (read(fd, buf, 41) != 41) {
		fprintf(stderr, "Short read from char device\n");
		exit(1);
	}
	toBin(buf, out);
}

int main(int argc, char **argv)
{
	int fd;
	int i;
	unsigned char buf1[20], buf2[20], buf3[20];
	unsigned char *p0, *p1=buf1, *p2=buf2, *p3=buf3;
	char msg[60];
	
	if (argc != 3) {
		fprintf(stderr, "Usage: %s device seed\n", argv[0]);
		return 1;
	}
	fd=open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("Couldn't open device node");
		return 1;
	}
	toBin(argv[2], p1);
	toBin(argv[2], p2);
	toBin(argv[2], p3);
	for (i=3; i<1003; i++) {
		memcpy(msg, p3, 20);
		memcpy(msg+20, p2, 20);
		memcpy(msg+40, p1, 20);
		write(fd, msg, 60);
		p0=p3;
		p3=p2;
		p2=p1;
		p1=p0;
		get(fd, p0);
	}
	for (i=0; i<20; i++)
		printf("%.2x", p0[i]);
	printf("\n");
	return 0;
}
