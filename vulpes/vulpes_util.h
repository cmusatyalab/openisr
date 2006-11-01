#ifndef VULPES_UTIL_H_
#define VULPES_UTIL_H_

#include "vulpes.h"

int is_dir(const char *name);
int is_file(const char *name);
off_t get_filesize(int fd);
vulpes_err_t read_file(int fd, char *buf, int *bufsize);
char *vulpes_strerror(vulpes_err_t err);
void charToHex(unsigned char* bin, unsigned char hex[2]);
unsigned char hexToChar(unsigned char* hex);
void binToHex(unsigned char *bin, unsigned char *hex, int binBytes);
void hexToBin(unsigned char *hex, unsigned char *bin, int binBytes);

#endif
