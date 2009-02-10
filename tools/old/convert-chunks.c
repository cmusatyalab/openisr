/*
 * convert-chunks - tool to translate an OpenISR (R) 0.8 chunk store to
 *                  0.9 format
 *
 * Copyright (C) 2007 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <zlib.h>

sqlite3 *db;
sqlite3_stmt *lookup;
sqlite3_stmt *insert;
unsigned chunks_complete;
unsigned total_chunks;
int do_profile = 0;
int got_signal;

#define SHA_LEN 20
#define CHUNK_BUF 140000
#define COMPRESS_THRESH (131072 - 17)  /* depends on cipher block size */
#define PROFILE_INTERVAL 5
#define PROGRESS_HASHES 50

enum compresstype {
	COMP_UNKNOWN=0,
	COMP_NONE=1,
	COMP_ZLIB=2,
	COMP_LZF=3
};

static int sql_shutdown(void)
{
	if (lookup != NULL)
		sqlite3_finalize(lookup);
	if (insert != NULL)
		sqlite3_finalize(insert);
	return sqlite3_close(db);
}

static void __attribute__ ((noreturn)) die(char *str, ...)
{
	va_list ap;

	va_start(ap, str);
	vfprintf(stderr, str, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	sql_shutdown();
	exit(1);
}

static void __attribute__ ((noreturn)) sqlerr(char *prefix)
{
	fprintf(stderr, "%s: %s\n", prefix, sqlite3_errmsg(db));
	sql_shutdown();
	exit(1);
}

static void profile(void)
{
	static unsigned last_sample;
	static int hashes_printed;
	int hashes_needed;

	if (got_signal) {
		got_signal=0;
		printf("%d/%d complete, %d chunks/second\n",
					chunks_complete, total_chunks,
					(chunks_complete - last_sample) /
					PROFILE_INTERVAL);
		last_sample=chunks_complete;
	} else if (!do_profile) {
		hashes_needed = total_chunks ? ((chunks_complete *
					PROGRESS_HASHES) / total_chunks) :
					PROGRESS_HASHES;
		for (; hashes_printed < hashes_needed; hashes_printed++)
			printf("#");
		fflush(stdout);
	}
}

static void profile_signal_handler(int __attribute__ ((unused)) signum)
{
	got_signal=1;
}

static void start_profile(void)
{
	struct sigaction act;
	struct itimerval tmr;

	memset(&act, 0, sizeof(act));
	act.sa_handler=profile_signal_handler;
	act.sa_flags=SA_RESTART;
	if (sigaction(SIGALRM, &act, NULL))
		die("Couldn't set signal handler");
	memset(&tmr, 0, sizeof(tmr));
	tmr.it_interval.tv_sec=PROFILE_INTERVAL;
	tmr.it_value.tv_sec=PROFILE_INTERVAL;
	if (setitimer(ITIMER_REAL, &tmr, NULL))
		die("Couldn't configure interval timer");
}

static void attachmap(char *path)
{
	sqlite3_stmt *stmt;

	if (sqlite3_prepare(db, "ATTACH ? as map", -1, &stmt, NULL))
		sqlerr("Preparing ATTACH statement");
	if (sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC))
		sqlerr("Binding ATTACH statement");
	if (sqlite3_step(stmt) != SQLITE_DONE)
		sqlerr("Attaching map database");
	sqlite3_finalize(stmt);
}

static void initmap(void)
{
	if (sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS map.tags ("
				"old_tag BLOB NOT NULL PRIMARY KEY "
						"ON CONFLICT IGNORE,"
				"new_tag BLOB NOT NULL,"
				"new_key BLOB NOT NULL,"
				"new_compress INTEGER NOT NULL)",
				NULL, NULL, NULL))
		sqlerr("Creating map database");
}

static void swap(void **a, void **b)
{
	void *tmp=*a;
	*a=*b;
	*b=tmp;
}

static size_t read_file(const char *file, void *buf, unsigned buflen)
{
	FILE *fp=fopen(file, "r");
	size_t size=0;

	if (fp == NULL)
		die("Couldn't open %s", file);
	while (!feof(fp)) {
		size += fread(buf + size, 1, buflen - size, fp);
		if (ferror(fp) || (size == buflen && !feof(fp)))
			die("Error reading %s", file);
	}
	fclose(fp);
	return size;
}

static void write_file(const char *file, const void *buf, unsigned buflen)
{
	FILE *fp=fopen(file, "w");
	size_t size=0;

	if (fp == NULL)
		die("Couldn't open %s", file);
	while (size < buflen) {
		size += fwrite(buf + size, 1, buflen - size, fp);
		if (ferror(fp))
			die("Error writing %s", file);
	}
	fclose(fp);
}

static size_t do_encrypt(const void *in, void *out, const void *key,
			unsigned len, int pad)
{
	EVP_CIPHER_CTX ctx;
	unsigned char iv[16] = {0};
	int outl;
	int outl2;

	if (!EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, iv))
		die("Couldn't initialize encryption");
	EVP_CIPHER_CTX_set_padding(&ctx, pad);
	if (!EVP_EncryptUpdate(&ctx, out, &outl, in, len))
		die("Couldn't encrypt");
	if (!EVP_EncryptFinal(&ctx, out + outl, &outl2))
		die("Couldn't finalize encryption");
	return outl + outl2;
}

static size_t do_decrypt(const void *in, void *out, const void *key,
			unsigned len, int pad)
{
	EVP_CIPHER_CTX ctx;
	unsigned char iv[8] = {0};
	int outl;
	int outl2;

	/* default key length conveniently does what we want */
	if (!EVP_DecryptInit(&ctx, EVP_bf_cbc(), key, iv))
		die("Couldn't initialize decryption");
	EVP_CIPHER_CTX_set_padding(&ctx, pad);
	if (!EVP_DecryptUpdate(&ctx, out, &outl, in, len))
		die("Couldn't decrypt");
	if (!EVP_DecryptFinal(&ctx, out + outl, &outl2))
		die("Couldn't finalize decryption");
	return outl + outl2;
}

static void do_hash(void *in, unsigned len, void *out)
{
	EVP_MD_CTX ctx;

	if (!EVP_DigestInit(&ctx, EVP_sha1()))
		die("Couldn't initialize hash");
	if (!EVP_DigestUpdate(&ctx, in, len))
		die("Couldn't hash data");
	if (!EVP_DigestFinal(&ctx, out, NULL))
		die("Couldn't finalize hash");
}

static size_t do_uncompress(void *in, void *out, unsigned len)
{
	unsigned long destlen=CHUNK_BUF;

	if (uncompress(out, &destlen, in, len) != Z_OK)
		die("Couldn't uncompress chunk");
	return destlen;
}

static void convert_chunk(unsigned chunk_num, const char *src, const char *dst)
{
	const void *old_tag;
	const void *old_key;
	enum compresstype old_compress;
	char validate[SHA_LEN];
	char new_tag[SHA_LEN];
	char new_key[SHA_LEN];
	enum compresstype new_compress;
	void *in;
	void *out;
	size_t len;

	if (sqlite3_bind_int(lookup, 1, chunk_num))
		sqlerr("Binding chunk number to query");
	if (sqlite3_step(lookup) != SQLITE_ROW)
		sqlerr("Couldn't obtain chunk information");
	old_tag=sqlite3_column_blob(lookup, 0);
	old_key=sqlite3_column_blob(lookup, 1);
	old_compress=sqlite3_column_int(lookup, 2);

	in=malloc(CHUNK_BUF);
	out=malloc(CHUNK_BUF);
	if (in == NULL || out == NULL)
		die("malloc failure");
	len=read_file(src, in, CHUNK_BUF);
	do_hash(in, len, validate);
	if (memcmp(old_tag, validate, SHA_LEN))
		die("Tag validation failed for chunk %u", chunk_num);
	len=do_decrypt(in, out, old_key, len, (old_compress == COMP_ZLIB));
	swap(&in, &out);
	new_compress = (len > COMPRESS_THRESH) ? COMP_NONE : COMP_ZLIB;
	do_hash(in, len, validate);
	if (memcmp(old_key, validate, SHA_LEN))
		die("Key validation failed for chunk %u", chunk_num);
	if (old_compress != new_compress) {
		if (new_compress == COMP_ZLIB)
			die("BUG: trying to recompress uncompressed chunk");
		len=do_uncompress(in, out, len);
		swap(&in, &out);
	}
	do_hash(in, len, new_key);
	len=do_encrypt(in, out, new_key, len, (new_compress == COMP_ZLIB));
	swap(&in, &out);
	do_hash(in, len, new_tag);
	write_file(dst, in, len);

	if (sqlite3_bind_blob(insert, 1, old_tag, SHA_LEN, SQLITE_STATIC))
		sqlerr("Binding old tag for INSERT");
	if (sqlite3_bind_blob(insert, 2, new_tag, SHA_LEN, SQLITE_STATIC))
		sqlerr("Binding new tag for INSERT");
	if (sqlite3_bind_blob(insert, 3, new_key, SHA_LEN, SQLITE_STATIC))
		sqlerr("Binding new key for INSERT");
	if (sqlite3_bind_int(insert, 4, new_compress))
		sqlerr("Binding new compression type for INSERT");
	if (sqlite3_step(insert) != SQLITE_DONE)
		sqlerr("Couldn't execute INSERT");

	if (sqlite3_step(lookup) != SQLITE_DONE)
		sqlerr("Couldn't finish chunk query");
	sqlite3_reset(insert);
	sqlite3_reset(lookup);
	free(in);
	free(out);
	chunks_complete++;
	profile();
}

static void count_chunk(unsigned __attribute__ ((unused)) chunk_num,
			const char __attribute__ ((unused)) *src,
			const char __attribute__ ((unused)) *dst)
{
	total_chunks++;
}

static int dirent(DIR *parent, const char *parent_src, const char *parent_dst,
			char **ent_src, char **ent_dst, unsigned *ent_num,
			int is_top)
{
	char *endp;
	struct dirent *ent;

again:
	errno=0;
	ent=readdir(parent);
	if (ent == NULL) {
		if (errno)
			die("Error reading directory %s", parent_src);
		else
			return 0;
	}
	*ent_num=strtoul(ent->d_name, &endp, 10);
	if (*endp != 0) {
		if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name))
			goto again;
		if (is_top) {
			if (strcmp("index.lev1", ent->d_name))
				fprintf(stderr, "Warning: ignoring %s/%s\n",
							parent_src,
							ent->d_name);
			goto again;
		} else {
			die("Found unexpected file %s/%s", parent_src,
						ent->d_name);
		}
	}
	if (asprintf(ent_src, "%s/%s", parent_src, ent->d_name) < 0)
		die("malloc failure");
	if (asprintf(ent_dst, "%s/%s", parent_dst, ent->d_name) < 0)
		die("malloc failure");
	return 1;
}

static void for_each_chunk(char *hdksrc, char *hdkdst, unsigned chunks_per_dir,
			int do_mkdir,
			void (*action)(unsigned, const char *, const char *))
{
	DIR *top;
	DIR *sub;
	char *sub_src;
	char *sub_dst;
	unsigned sub_num;
	char *chunk_src;
	char *chunk_dst;
	unsigned chunk_num;

	top=opendir(hdksrc);
	if (top == NULL)
		die("Couldn't read %s", hdksrc);
	while (dirent(top, hdksrc, hdkdst, &sub_src, &sub_dst, &sub_num, 1)) {
		sub=opendir(sub_src);
		if (sub == NULL)
			die("Couldn't read %s", sub_src);
		if (do_mkdir && mkdir(sub_dst, 0755))
			die("Couldn't create %s", sub_dst);
		while (dirent(sub, sub_src, sub_dst, &chunk_src, &chunk_dst,
					&chunk_num, 0)) {
			action(sub_num * chunks_per_dir + chunk_num,
						chunk_src, chunk_dst);
			free(chunk_src);
			free(chunk_dst);
		}
		closedir(sub);
		free(sub_src);
		free(sub_dst);
	}
	closedir(top);
}

static void __attribute__ ((noreturn)) usage(char *argv0)
{
	die("Usage: %s mapdb keyring src-hdkdir dst-hdkdir chunks-per-dir",
				argv0);
}

int main(int argc, char **argv)
{
	struct stat st;
	char *mapdb;
	char *keyring;
	char *hdksrc;
	char *hdkdst;
	unsigned chunks_per_dir;
	char *ep;

	if (argc != 6)
		usage(argv[0]);
	mapdb=argv[1];
	keyring=argv[2];
	hdksrc=argv[3];
	hdkdst=argv[4];
	chunks_per_dir=strtoul(argv[5], &ep, 10);
	if (*argv[5] == 0 || *ep != 0)
		usage(argv[0]);

	if (stat(keyring, &st) || !S_ISREG(st.st_mode))
		die("%s does not exist or is not a regular file", keyring);
	if (stat(hdksrc, &st) || !S_ISDIR(st.st_mode))
		die("%s does not exist or is not a directory", hdksrc);
	if (stat(hdkdst, &st) || !S_ISDIR(st.st_mode))
		die("%s does not exist or is not a directory", hdkdst);
	if (sqlite3_open(keyring, &db))
		sqlerr("Opening keyring");
	attachmap(mapdb);
	initmap();

	if (sqlite3_prepare(db, "SELECT tag, key, compression FROM keys "
				"WHERE chunk == ?", -1, &lookup, NULL))
		sqlerr("Preparing SELECT statement");
	if (sqlite3_prepare(db, "INSERT INTO map.tags "
				"(old_tag, new_tag, new_key, new_compress) "
				"VALUES(?, ?, ?, ?)", -1, &insert, NULL))
		sqlerr("Preparing INSERT statement");
	for_each_chunk(hdksrc, hdkdst, chunks_per_dir, 0, count_chunk);
	if (do_profile)
		start_profile();
	for_each_chunk(hdksrc, hdkdst, chunks_per_dir, 1, convert_chunk);
	profile();
	if (!do_profile)
		printf("\n");

	if (sql_shutdown())
		sqlerr("Closing database connection");
	return 0;
}
