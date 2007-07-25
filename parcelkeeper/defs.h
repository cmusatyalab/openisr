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

#ifndef VULPES_DEFS_H
#define VULPES_DEFS_H

#include <stdint.h>

extern const char *rcs_revision;

typedef enum vulpes_err {
	VULPES_SUCCESS=0,
	VULPES_OVERFLOW,
	VULPES_IOERR,
	VULPES_NOTFOUND,
	VULPES_INVALID,
	VULPES_NOMEM,
	VULPES_NOKEY,
	VULPES_TAGFAIL,
	VULPES_BADFORMAT,
	VULPES_CALLFAIL,
	VULPES_PROTOFAIL,
	VULPES_NETFAIL,  /* Used instead of IOERR if a retry might fix it */
	VULPES_BUSY,
} vulpes_err_t;

/*** Cache state ***/

#define CA_MAGIC 0x51528038
#define CA_VERSION 0

/* All u32's in network byte order */
struct ca_header {
	uint32_t magic;
	uint32_t entries;
	uint32_t offset;  /* beginning of data, in 512-byte blocks */
	uint32_t valid_chunks;
	uint32_t flags;
	uint8_t version;
	uint8_t reserved[491];
};

#define CA_VALID 0x01

struct ca_entry {
	uint32_t length;
	uint8_t flags;  /* XXX not packed */
};

/* util.c */
#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))

vulpes_err_t read_file(const char *path, char *buf, int *bufsize);
vulpes_err_t read_sysfs_file(const char *path, char *buf, int bufsize);
char *vulpes_strerror(vulpes_err_t err);
int set_signal_handler(int sig, void (*handler)(int sig));
void print_progress(unsigned chunks, unsigned maxchunks);
vulpes_err_t fork_and_wait(int *status_fd);
vulpes_err_t form_lockdir_file_name(char *buf, int len, const char *suffix);
vulpes_err_t acquire_lock(void);
void release_lock(void);
vulpes_err_t create_pidfile(void);
void remove_pidfile(void);

#endif
