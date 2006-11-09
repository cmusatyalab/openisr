#ifndef VULPES_UTIL_H_
#define VULPES_UTIL_H_

#include "vulpes.h"

int is_dir(const char *name);
int is_file(const char *name);
off_t get_filesize(int fd);
int at_eof(int fd);
vulpes_err_t read_file(int fd, char *buf, int *bufsize);
char *vulpes_strerror(vulpes_err_t err);
void charToHex(const unsigned char* bin, unsigned char hex[2]);
unsigned char hexToChar(const unsigned char* hex);
void binToHex(const unsigned char *bin, unsigned char *hex, int binBytes);
void hexToBin(const unsigned char *hex, unsigned char *bin, int binBytes);
int set_signal_handler(int sig, void (*handler)(int sig));

#endif
