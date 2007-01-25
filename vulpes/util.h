#ifndef VULPES_UTIL_H_
#define VULPES_UTIL_H_

#include "vulpes.h"

int is_dir(const char *name);
int is_file(const char *name);
off_t get_filesize(int fd);
int at_eof(int fd);
vulpes_err_t read_file(const char *path, char *buf, int *bufsize);
vulpes_err_t read_sysfs_file(const char *path, char *buf, int bufsize);
char *vulpes_strerror(vulpes_err_t err);
void charToHex(const char* bin, char hex[2]);
char hexToChar(const char hex[2]);
void binToHex(const char *bin, char *hex, int binBytes);
void hexToBin(const char *hex, char *bin, int binBytes);
int set_signal_handler(int sig, void (*handler)(int sig));
void print_progress(unsigned chunks, unsigned maxchunks);
vulpes_err_t fork_and_wait(int *status_fd);
vulpes_err_t form_lockdir_file_name(char *buf, int len,
			const char *suffix);
vulpes_err_t acquire_lock(void);
void release_lock(void);
vulpes_err_t create_pidfile(void);
void remove_pidfile(void);

#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))

#endif
