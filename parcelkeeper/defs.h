/*
 * Parcelkeeper - support daemon for the OpenISR (TM) system virtual disk
 *
 * Copyright (C) 2006-2007 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#ifndef PK_DEFS_H
#define PK_DEFS_H

#include <stdio.h>

struct pk_config {
	/* cache directory and its contents */
	char *cache_dir;
	char *parcel_cfg;
	char *keyring;
	char *cache_file;
	char *cache_index;
	char *devfile;
	char *lockfile;
	char *pidfile;

	/* last directory and its contents */
	char *last_dir;
	char *last_keyring;

	/* hoard cache and its contents */
	char *hoard_dir;
	char *hoard_file;
	char *hoard_index;

	/* log parameters */
	char *log_file;
	char *log_info_str;
	unsigned log_file_mask;
	unsigned log_stderr_mask;

	/* miscellaneous parameters */
	char *master;
	char *destdir;
	int foreground;
};

struct pk_state {
	FILE *log_fp;
	int lock_fd;
	int cache_fd;
	char *loopdev_name;
	int loopdev_fd;
	int chardev_fd;
	int signal_fds[2];

	int bdev_index;

	unsigned long long chunks;  /* XXX */
	unsigned chunksize;  /* XXX */
	unsigned offset;  /* XXX */

	unsigned request_count;  /* XXX */
};

extern const char *rcs_revision;
extern struct pk_config config;
extern struct pk_state state;

typedef enum pk_err {
	PK_SUCCESS=0,
	PK_OVERFLOW,
	PK_IOERR,
	PK_NOTFOUND,
	PK_INVALID,
	PK_NOMEM,
	PK_NOKEY,
	PK_TAGFAIL,
	PK_BADFORMAT,
	PK_CALLFAIL,
	PK_PROTOFAIL,
	PK_NETFAIL,  /* Used instead of IOERR if a retry might fix it */
	PK_BUSY,
} pk_err_t;

enum pk_log_type {
	LOG_INFO,
	LOG_ERROR,
	LOG_STATS
};

/* cmdline.c */
void parse_cmdline(int argc, char **argv);

/* log.c */
void log_start(void);
void log_shutdown(void);
void pk_log(enum pk_log_type type, char *fmt, ...);

/* util.c */
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))

int is_dir(const char *path);
int is_file(const char *path);
pk_err_t read_file(const char *path, char *buf, int *bufsize);
pk_err_t read_sysfs_file(const char *path, char *buf, int bufsize);
char *pk_strerror(pk_err_t err);
int set_signal_handler(int sig, void (*handler)(int sig));
void print_progress(unsigned chunks, unsigned maxchunks);
pk_err_t fork_and_wait(int *status_fd);
pk_err_t acquire_lock(void);
void release_lock(void);
pk_err_t create_pidfile(void);
void remove_pidfile(void);

#endif
