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
#include <unistd.h>
#include <sqlite3.h>

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

enum cryptotype {
	CRY_UNKNOWN=0,
	CRY_BLOWFISH_SHA1=1,
	CRY_AES_SHA1=2
};

enum compresstype {
	COMP_UNKNOWN=0,
	COMP_NONE=1,
	COMP_ZLIB=2,
	COMP_LZF=3
};

enum mode {
	MODE_RUN,
	MODE_UPLOAD,
	MODE_HOARD,
	MODE_EXAMINE,
	MODE_VALIDATE,
	MODE_LISTHOARD,
	MODE_CHECKHOARD,
	MODE_RMHOARD,
	MODE_REFRESH,
	MODE_HELP,
	MODE_VERSION,
};

enum mode_flags {
	WANT_LOCK	= 0x0001,
	WANT_CACHE	= 0x0002,
	WANT_PREV	= 0x0004,
	WANT_BACKGROUND = 0x0008,
	WANT_TRANSPORT	= 0x0010,
	WANT_CHECK	= 0x0020,
};

struct pk_connection;
struct query;

struct pk_config {
	/* mode flags */
	unsigned flags;

	/* top-level parcel directory and its contents */
	char *parcel_dir;
	char *parcel_cfg;
	char *keyring;
	char *prev_keyring;
	char *cache_file;
	char *cache_index;
	char *lockfile;
	char *pidfile;

	/* hoard cache and its contents */
	char *hoard_dir;
	char *hoard_file;
	char *hoard_index;

	/* upload directory and its contents */
	char *dest_dir;
	char *dest_stats;

	/* log parameters */
	char *log_file;
	char *log_info_str;
	unsigned log_file_mask;
	unsigned log_stderr_mask;

	/* miscellaneous parameters */
	enum compresstype compress;
	unsigned minsize;  /* MB */
	char *uuid;
};

struct pk_parcel {
	enum cryptotype crypto;
	unsigned required_compress;
	unsigned chunks;
	unsigned chunksize;
	unsigned chunks_per_dir;
	unsigned hashlen;
	char *uuid;
	char *server;
	char *user;
	char *parcel;
	char *master;
};

struct pk_state {
	FILE *log_fp;
	int lock_fd;
	int cache_fd;
	int hoard_fd;
	char *loopdev_name;
	int loopdev_fd;
	int chardev_fd;
	int signal_fds[2];
	struct pk_connection *conn;
	sqlite3 *db;
	sqlite3 *hoard;

	int bdev_index;
	int hoard_ident;

	unsigned offset;

	unsigned request_count;  /* XXX */
};

extern struct pk_config config;
extern struct pk_parcel parcel;
extern struct pk_state state;
extern const char *isr_release;
extern const char *rcs_revision;

#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))
#define _stringify(str) #str
/* the first expansion stringifies; the second expands cpp constants */
#define stringify(str) _stringify(str)

/* cmdline.c */
enum mode parse_cmdline(int argc, char **argv);

/* log.c */
void log_start(void);
void log_shutdown(void);
void _pk_log(enum pk_log_type type, char *fmt, const char *func, ...);
#define pk_log(type, fmt, args...) _pk_log(type, fmt, __func__, ## args)

/* parcelcfg.c */
pk_err_t parse_parcel_cfg(void);

/* cache.c */
pk_err_t cache_init(void);
void cache_shutdown(void);
pk_err_t cache_get(unsigned chunk, void *tag, void *key,
			enum compresstype *compress, unsigned *length);
pk_err_t cache_update(unsigned chunk, const void *tag, const void *key,
			enum compresstype compress, unsigned length);
off64_t cache_chunk_to_offset(unsigned chunk);

/* cache_modes.c */
int copy_for_upload(void);
int validate_cache(void);
int examine_cache(void);

/* hoard.c */
pk_err_t hoard_init(void);
void hoard_shutdown(void);
pk_err_t hoard_get_chunk(const void *tag, void *buf, unsigned *len);
pk_err_t hoard_put_chunk(const void *tag, const void *buf, unsigned len);
pk_err_t hoard_sync_refs(int from_cache);

/* hoard_modes.c */
int hoard(void);
int examine_hoard(void);
int list_hoard(void);
int rmhoard(void);
int check_hoard(void);
int hoard_refresh(void);

/* nexus.c */
pk_err_t nexus_init(void);
void nexus_run(void);
void nexus_shutdown(void);

/* transport.c */
pk_err_t transport_init(void);
void transport_shutdown(void);
pk_err_t transport_fetch_chunk(void *buf, unsigned chunk, const void *tag,
			unsigned *length);

/* sql.c */
int query(struct query **result, sqlite3 *db, char *query, char *fmt, ...);
int query_next(struct query *qry);
void query_row(struct query *qry, char *fmt, ...);
void query_free(struct query *qry);
void query_flush(void);
pk_err_t attach(sqlite3 *db, const char *handle, const char *file);
pk_err_t _begin(sqlite3 *db, int immediate, const char *caller);
#define begin(db) _begin(db, 0, __func__)
#define begin_immediate(db) _begin(db, 1, __func__)
pk_err_t _commit(sqlite3 *db, const char *caller);
#define commit(db) _commit(db, __func__)
pk_err_t _rollback(sqlite3 *db, const char *caller);
#define rollback(db) _rollback(db, __func__)
pk_err_t set_busy_handler(sqlite3 *db);
pk_err_t validate_db(sqlite3 *db);
pk_err_t cleanup_action(sqlite3 *db, char *sql, char *desc);

/* util.c */
#define FILE_LOCK_READ     0
#define FILE_LOCK_WRITE 0x01
#define FILE_LOCK_WAIT  0x02
int is_dir(const char *path);
int is_file(const char *path);
int at_eof(int fd);
pk_err_t parseuint(unsigned *out, char *in, int base);
enum cryptotype parse_crypto(char *desc);
enum compresstype parse_compress(char *desc);
unsigned crypto_hashlen(enum cryptotype type);
int compress_is_valid(enum compresstype type);
pk_err_t read_file(const char *path, char *buf, int *bufsize);
pk_err_t read_sysfs_file(const char *path, char *buf, int bufsize);
char *pk_strerror(pk_err_t err);
int set_signal_handler(int sig, void (*handler)(int sig));
void print_progress(unsigned chunks, unsigned maxchunks);
pk_err_t fork_and_wait(int *status_fd);
pk_err_t get_file_lock(int fd, int flags);
pk_err_t put_file_lock(int fd);
pk_err_t acquire_lockfile(void);
void release_lockfile(void);
pk_err_t create_pidfile(void);
void remove_pidfile(void);
char *form_chunk_path(char *prefix, unsigned chunk);
pk_err_t digest(void *out, const void *in, unsigned len);
char *format_tag(const void *tag);
void log_tag_mismatch(const void *expected, const void *found);
pk_err_t canonicalize_uuid(const char *in, char **out);

#endif
