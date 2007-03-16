#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include "splice.h"

#define SRVPORT 52501
#define BACKLOG 16
#define DEBUG

extern const char *rcs_revision;

/* XXX copied from libvdisk */
#define warn(s, args...) fprintf(stderr, s ": %s\n", ## args, strerror(errno))
#define ndebug(s, args...) do {} while (0)
#define die(s, args...) do { warn(s, ## args); exit(1); } while (0)
#ifdef DEBUG
#define debug(s, args...) warn(s, ## args)
#else
#define debug(s, args...) do {} while (0)
#endif

void setsockoptval(int fd, int level, int optname, int value)
{
	if (setsockopt(fd, level, optname, &value, sizeof(value)))
		warn("Couldn't setsockopt");
}

void process(int fd)
{
	char buf[512];
	FILE *fp;
	int filefd;
	int count;
	off_t off;
	int ret;
	int ret2;
	int pipefd[2];
	const char notfound[]="Not found\n";
	
	setsockoptval(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
	setsockoptval(fd, SOL_TCP, TCP_CORK, 1);
	if (pipe(pipefd))
		die("Couldn't create pipe");
	fp=fdopen(fd, "r");
	if (fp == NULL)
		die("Couldn't fdopen");
	while (1) {
		if (fgets(buf, sizeof(buf), fp) == NULL) {
			warn("Closed");
			break;
		}
		count=strlen(buf);
		if (buf[count-1] == '\n')
			buf[count-1]=0;
		printf("%s\n", buf);
		filefd=open(basename(buf), O_RDONLY);
		if (filefd == -1) {
			write(fd, notfound, sizeof(notfound));
			continue;
		}
		count=lseek(filefd, 0, SEEK_END);
		if (count == -1)
			die("Couldn't get file length");
		for (off=0; off < count; ) {
			ret=splice(filefd, &off, pipefd[1], NULL, count - off,
						0);
			if (ret == -1)
				die("Couldn't splice input");
			printf("Spliced %d input bytes\n", ret);
			off += ret;
			while (ret > 0) {
				ret2=splice(pipefd[0], NULL, fd, NULL, ret, 0);
				if (ret2 == -1)
					die("Couldn't splice output");
				ret -= ret2;
			}
		}
		close(filefd);
	}
	fclose(fp);
	close(pipefd[0]);
	close(pipefd[1]);
}

int main(int argc, char **argv)
{
	int listenfd;
	int fd;
	struct sockaddr_in addr;
	
	printf("isrserv revision %s\n", rcs_revision);
	listenfd=socket(PF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
		die("Couldn't create socket");
	setsockoptval(listenfd, SOL_SOCKET, SO_REUSEADDR, 1);
	addr.sin_family=AF_INET;
	addr.sin_addr.s_addr=htonl(INADDR_ANY);
	addr.sin_port=htons(SRVPORT);
	if (bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)))
		die("Couldn't bind socket to port %d", SRVPORT);
	if (listen(listenfd, BACKLOG))
		die("Couldn't listen on socket");
	
	while (1) {
		fd=accept(listenfd, NULL, 0);
		if (fd < 0) {
			warn("Error accepting connection");
			continue;
		}
		process(fd);
	}
	return 0;
}
