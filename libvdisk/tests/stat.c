#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
	struct stat s;
	struct stat64 s64;
	
	printf("stat %d\n", stat(argv[1], &s));
	printf("lstat %d\n", lstat(argv[1], &s));
	printf("stat64 %d\n", stat64(argv[1], &s64));
	printf("lstat64 %d\n", lstat64(argv[1], &s64));
	return 0;
}
