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

#define SRVPORT 52501
#define BACKLOG 16
#define DEBUG

extern const char *rcs_revision;

/* XXX copied from libvdisk */
#define warn(s, args...) fprintf(stderr, s "\n", ## args)
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
	int count;
	
	setsockoptval(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
	setsockoptval(fd, SOL_TCP, TCP_CORK, 1);
	while (1) {
		count=read(fd, buf, sizeof(buf) - 1);
		if (count <= 0) {
			warn("Closed");
			break;
		}
		buf[count]=0;
		printf("%s", buf);
	}
	close(fd);
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
