/*
 * disktool - import VM disk image as OpenISR parcel
 *
 * Copyright (C) 2009 Carnegie Mellon University
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <zlib.h>
#include "isrcrypto.h"
#include "sql.h"

/* should probably be defined in a header */
enum compressiontype {
	COMP_UNKNOWN=0,
	COMP_NONE=1,
	COMP_ZLIB=2,
	COMP_LZF=3,
};

/* command line parameters */
static const char *destpath = ".";
static const char *keyring = "keyring";
static int chunksize = 128; /* chunk size in KiB */
static int chunksperdir = 512;
static int64_t maxchunks = -1; /* infinite for all intents and purposes */
static int compress_level = Z_DEFAULT_COMPRESSION;
static gboolean want_progress;

static GOptionEntry options[] = {
	{"out", 'o', 0, G_OPTION_ARG_FILENAME, &destpath, "Output path (default: .)", "PATH"},
	{"keyring", 'k', 0, G_OPTION_ARG_FILENAME, &keyring, "Keyring (default: keyring)", "PATH"},
	{"chunksize", 's', 0, G_OPTION_ARG_INT, &chunksize, "Chunksize (default: 128)", "KiB"},
	{"chunksperdir", 'd', 0, G_OPTION_ARG_INT, &chunksperdir, "Chunks per directory (default: 512)", "N"},
	{"nchunks", 'n', 0, G_OPTION_ARG_INT64, &maxchunks, "Number of chunks", "N"},
	{"compress", 'z', 0, G_OPTION_ARG_INT, &compress_level, "Compression level (default: 6)", "1-9"},
	{"progress", 'p', 0, G_OPTION_ARG_NONE, &want_progress, "Show progress bar", NULL},
	{NULL}
};

static void clear_progress(void);
#define die(str, args...) do { \
		clear_progress(); \
		g_printerr(str "\n", ## args); \
		exit(1); \
	} while(0)

/* crypto parameters */
static enum isrcry_cipher cipher = ISRCRY_CIPHER_AES;
static enum isrcry_mode mode = ISRCRY_MODE_CBC;
static enum isrcry_padding padding = ISRCRY_PADDING_PKCS5;
static struct isrcry_cipher_ctx *cipher_ctx;
static unsigned int cipher_keylen = 16;
static unsigned int cipher_block;

static enum isrcry_hash hash = ISRCRY_HASH_SHA1;
static struct isrcry_hash_ctx *hash_ctx;
static unsigned int hash_len;
#define HASH_LEN 20

static z_stream zstrm;
static struct db *sqlitedb;

/** Progress bar *************************************************************/

static FILE *tty;
static off_t progress_bytes;
static off_t progress_max_bytes;
static time_t progress_start;
static gboolean progress_redraw;
static struct winsize window_size;
#define TTYFILE "/dev/tty"

static void set_signal_handler(int sig, void (*handler)(int))
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = handler;
	act.sa_flags = SA_RESTART;
	if (sigaction(sig, &act, NULL))
		die("Couldn't set signal handler for signal %d", sig);
}

static void sigwinch_handler(int ignored)
{
	(void)ignored;

	if (tty == NULL)
		return;
	ioctl(fileno(tty), TIOCGWINSZ, &window_size);
	progress_redraw = TRUE;
}

static unsigned ndigits(unsigned val)
{
	unsigned n;

	for (n=0; val; val /= 10, n++);
	return n;
}

static char *seconds_to_str(unsigned seconds)
{
	if (seconds < 3600)
		return g_strdup_printf("%u:%.2u", seconds / 60,
					seconds % 60);
	else
		return g_strdup_printf("%u:%.2u:%.2u", seconds / 3600,
					(seconds / 60) % 60, seconds % 60);
}

static char *progress_bar(unsigned cols_used, unsigned percent)
{
	char *str;
	int availchars;
	unsigned fillchars;

	availchars = window_size.ws_col - cols_used - 2;
	if (availchars < 2)
		return g_strdup_printf("%*s", availchars + 2, "");
	fillchars = availchars * percent / 100;
	str = g_strdup_printf("[%*s]", availchars, "");
	memset(str + 1, '=', fillchars);
	if (percent < 100)
		str[fillchars + 1] = '>';
	return str;
}

static void print_progress(gboolean final)
{
	static time_t last_timestamp;
	time_t cur_timestamp;
	unsigned long long bytes = progress_bytes;
	unsigned long long max_bytes = progress_max_bytes;
	unsigned percent = 0;
	char *estimate = NULL;
	char *bar;
	int count;

	if (max_bytes == 0)
		return;  /* Progress bar disabled */
	if (final)
		percent = 100;
	else
		percent = MIN(bytes * 100 / max_bytes, 99);

	cur_timestamp = time(NULL);
	if (!final && !progress_redraw && last_timestamp == cur_timestamp)
		return;
	last_timestamp = cur_timestamp;
	progress_redraw = FALSE;

	if (bytes && !final)
		estimate = seconds_to_str((max_bytes - bytes) *
					(cur_timestamp - progress_start)
					/ bytes);

	count = fprintf(tty, " %3u%% (%*llu/%llu MB) %s%s", percent,
				ndigits(max_bytes >> 20), bytes >> 20,
				max_bytes >> 20, estimate ?: "",
				estimate ? " " : "");
	bar = progress_bar(count, percent);
	fprintf(tty, "%s\r", bar);
	if (final)
		fprintf(tty, "\n");
	fflush(tty);
	g_free(estimate);
	g_free(bar);
}

static void init_progress(off_t max_bytes)
{
	progress_max_bytes = 0;
	if (!want_progress || max_bytes == 0)
		return;
	set_signal_handler(SIGWINCH, sigwinch_handler);
	if (tty == NULL) {
		tty = fopen(TTYFILE, "w");
		if (tty == NULL)
			return;
		sigwinch_handler(0);
	}
	progress_bytes = 0;
	progress_max_bytes = max_bytes;
	progress_start = time(NULL);
	print_progress(FALSE);
}

static void progress(off_t count)
{
	progress_bytes += count;
	print_progress(FALSE);
}

static void finish_progress(void)
{
	print_progress(TRUE);
}

static void clear_progress(void)
{
	if (tty != NULL) {
		fprintf(tty, "%*s\r", window_size.ws_col, "");
		fflush(tty);
		progress_redraw = TRUE;
	}
}

static void init_progress_fd(int fd)
{
	off_t imagelen;
	int64_t nchunks, chunklen = chunksize * 1024;

	imagelen = lseek(fd, 0, SEEK_END);
	if (imagelen == -1)
		imagelen = 0;

	else if (lseek(fd, 0, SEEK_SET))
		die("Couldn't reset position of input stream: %s",
		    strerror(errno));

	nchunks = ((int64_t)imagelen + chunklen - 1) / chunklen;
	if (maxchunks != -1 && (nchunks == 0 || nchunks > maxchunks))
		nchunks = maxchunks;

	init_progress(nchunks * chunklen);
}

/** Initialization *******************************************************/

static void handle_log_message(const gchar *domain, GLogLevelFlags level,
			       const gchar *message, gpointer data)
{
    (void)domain;
    (void)level;
    (void)message;
    (void)data;
}

static void init(void)
{
	if (deflateInit(&zstrm, compress_level) != Z_OK)
		die("Failed to initialize zlib: %s", zstrm.msg);

	hash_ctx = isrcry_hash_alloc(hash);
	if (hash_ctx == NULL)
		die("Couldn't allocate hash");
	hash_len = isrcry_hash_len(hash);
	if (hash_len > HASH_LEN)
		die("Unexpected hash size");

	cipher_ctx = isrcry_cipher_alloc(cipher, mode);
	if (cipher_ctx == NULL)
		die("Couldn't allocate cipher");
	cipher_block = isrcry_cipher_block(cipher);

	/* initialize sqlite wrappers */
	g_log_set_handler("isrsql", G_LOG_LEVEL_INFO | SQL_LOG_LEVEL_QUERY |
			  SQL_LOG_LEVEL_SLOW_QUERY, handle_log_message, NULL);
	sql_init();
	sql_conn_open(keyring, &sqlitedb);

	/* In case the db wasn't created, initialize a basic keyring schema */
	begin(sqlitedb);
	query(NULL, sqlitedb,
	      "CREATE TABLE IF NOT EXISTS keys ( "
	      "chunk INTEGER PRIMARY KEY NOT NULL, "
	      "tag BLOB NOT NULL, "
	      "key BLOB NOT NULL, "
	      "compression INTEGER NOT NULL)", NULL);
	query(NULL, sqlitedb,
	      "CREATE INDEX IF NOT EXISTS keys_tags ON keys (tag)", NULL);
	commit(sqlitedb);

	begin(sqlitedb);
}

static void fini(void)
{
	commit(sqlitedb);
	sql_conn_close(sqlitedb);

	isrcry_cipher_free(cipher_ctx);
	isrcry_hash_free(hash_ctx);

	deflateEnd(&zstrm);
}

struct chunk_desc {
    guchar tag[HASH_LEN];
    guchar key[HASH_LEN];
    gpointer data;
    gulong len;
    unsigned int compression;
};

static void encrypt_chunk(struct chunk_desc *chunk, gpointer tmp, gulong len)
{
	int rc;

	/* compress chunk */
	zstrm.next_in = chunk->data;
	zstrm.avail_in = chunk->len;
	zstrm.next_out = tmp;
	zstrm.avail_out = len;

	rc = deflate(&zstrm, Z_FINISH);
	if (rc == Z_STREAM_END && zstrm.avail_out > (cipher_block + 1)) {
		chunk->len = len - zstrm.avail_out;
		chunk->compression = COMP_ZLIB;
	} else { /* no room in output buffer / compression failed */
		memcpy(chunk->data, tmp, chunk->len);
		chunk->compression = COMP_NONE;
	}
	deflateReset(&zstrm);

	/* calculate key */
	isrcry_hash_update(hash_ctx, tmp, chunk->len);
	isrcry_hash_final(hash_ctx, chunk->key);

	/* encrypt chunk */
	rc = isrcry_cipher_init(cipher_ctx, ISRCRY_ENCRYPT, chunk->key,
				cipher_keylen, NULL);
	if (rc)
		die("Couldn't initialize cipher: %s", isrcry_strerror(rc));

	if (chunk->compression == COMP_NONE) {
		isrcry_cipher_process(cipher_ctx, tmp, chunk->len, chunk->data);
		len = chunk->len;
	} else {
		isrcry_cipher_final(cipher_ctx, padding, tmp,
				    chunk->len, chunk->data, &len);
	}
	chunk->len = len;

	/* calculate tag */
	isrcry_hash_update(hash_ctx, chunk->data, chunk->len);
	isrcry_hash_final(hash_ctx, chunk->tag);
}

static void write_chunk(unsigned int idx, struct chunk_desc *chunk)
{
	GString *dest;
	int fd;

	dest = g_string_new(destpath);

	g_string_append_printf(dest, "/%04d", idx / chunksperdir);
	g_mkdir_with_parents(dest->str, 0755);

	g_string_append_printf(dest, "/%04d", idx % chunksperdir);

	fd = g_creat(dest->str, 0444);
	if (fd == -1)
		die("Failed to create chunk #%d: %s", idx, strerror(errno));
	if (write(fd, chunk->data, chunk->len) != (ssize_t)chunk->len)
		die("Failed to write chunk #%d: %s", idx, strerror(errno));
	close(fd);

	/* update keyring */
	if (!query(NULL, sqlitedb,
		    "INSERT INTO keys (chunk, tag, key, compression) "
		    "VALUES (?, ?, ?, ?)", "dbbd", idx, chunk->tag,
		    hash_len, chunk->key, hash_len, chunk->compression))
	{
		sql_log_err(sqlitedb, "Couldn't update keyring");
		exit(1);
	}
	g_string_free(dest, TRUE);
}

static void import_image(const gchar *img)
{
	int fd;
	unsigned int idx;
	ssize_t n;
	struct chunk_desc chunk, zerochunk;
	gpointer tmp, zerodata;
	gulong chunklen;

	fd = g_open(img, O_RDONLY, 0);
	if (fd == -1)
		die("unable to open image: %s", strerror(errno));

	chunklen = chunksize * 1024;
	tmp = g_malloc(chunklen);
	chunk.data = g_malloc(chunklen);

	zerochunk.len = chunklen;
	zerochunk.data = g_malloc0(chunklen);
	zerodata = g_malloc0(chunklen);
	encrypt_chunk(&zerochunk, tmp, chunklen);

	init_progress_fd(fd);
	for (idx = 0; maxchunks != 0; idx++, maxchunks--)
	{
		n = read(fd, chunk.data, chunklen);
		if (n <= 0)
			break;

		/* zero tail of a partial (last) chunk */
		if ((unsigned)n < chunklen)
			memset(chunk.data + n, 0, chunklen - n);
		chunk.len = chunklen;

		if (memcmp(chunk.data, zerodata, chunklen) == 0) {
			write_chunk(idx, &zerochunk);
		} else {
			encrypt_chunk(&chunk, tmp, chunklen);
			write_chunk(idx, &chunk);
		}

		progress(chunklen);
	}
	finish_progress();

	close(fd);

	g_free(zerochunk.data);
	g_free(zerodata);
	g_free(chunk.data);
	g_free(tmp);
}

int main(int argc, char **argv)
{
	GOptionContext *ctx;
	GError *err = NULL;

	ctx = g_option_context_new("[image] - import VM disk image");
	g_option_context_add_main_entries(ctx, options, NULL);
	if (!g_option_context_parse(ctx, &argc, &argv, &err))
		die("%s", err->message);
	g_option_context_free(ctx);

	if (chunksize <= 0)
		die("Invalid chunksize specified");

	if (chunksperdir <= 0)
		die("Invalid number of chunks per directory specified");

	if (argc < 2)
		die("No image specified");

	init();

	import_image(argv[1]);

	fini();

	exit(0);
}

