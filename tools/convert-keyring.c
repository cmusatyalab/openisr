/*
 * convert-keyring - tool to translate an OpenISR 0.8 keyring to 0.9 format
 *
 * Copyright (C) 2007 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#define HASHLEN 20
#define ASCII_HASHLEN 40
#define DELIM1_OFFSET (ASCII_HASHLEN)
#define KEY_OFFSET (ASCII_HASHLEN + 1)
#define DELIM2_OFFSET (KEY_OFFSET + ASCII_HASHLEN)
#define LINE_LENGTH (DELIM2_OFFSET + 1)

enum kr_compress {
	KR_COMPRESS_NONE = 0,
	KR_COMPRESS_ZLIB = 1
};

#define KR_MAGIC 0x51528039
#define KR_VERSION 0

/* All u32's in network byte order */
struct kr_header {
	uint32_t magic;
	uint32_t entries;
	uint8_t version;
	uint8_t reserved[31];
};

struct kr_entry {
	uint8_t compress;
	uint8_t tag[HASHLEN];
	uint8_t key[HASHLEN];
};

enum sql_compresstype {
	COMP_UNKNOWN=0,
	COMP_NONE=1,
	COMP_ZLIB=2,
	COMP_LZF=3
};

static FILE *in;
static sqlite3 *db;
static char *dbpath;
extern int optind;


/**** Helpers ****/

static void __attribute__ ((noreturn)) die(char *str, ...)
{
	va_list ap;

	va_start(ap, str);
	vprintf(str, ap);
	printf("\n");
	va_end(ap);
	if (dbpath != NULL)
		unlink(dbpath);
	exit(1);
}

static void __attribute__ ((noreturn)) sqlerr(char *prefix)
{
	printf("%s: %s\n", prefix, sqlite3_errmsg(db));
	sqlite3_close(db);
	if (dbpath != NULL)
		unlink(dbpath);
	exit(1);
}

static int exists(char *file)
{
	struct stat buf;

	return stat(file, &buf) ? 0 : 1;
}

static void step(char *desc, sqlite3_stmt *step)
{
	if (sqlite3_step(step) != SQLITE_DONE)
		sqlerr(desc);
	if (sqlite3_reset(step))
		sqlerr(desc);
}


/**** ASCII keyring ****/

static inline int charval(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	die("Invalid character %u", c);
}

static inline void hex2bin(char *hex, char *bin, int bin_len)
{
	unsigned char *uhex=(unsigned char *)hex;
	int i;

	for (i=0; i<bin_len; i++)
		bin[i] = (charval(uhex[2*i]) << 4) + charval(uhex[2*i+1]);
}

static int fetch_entry_ascii(int line, char *tag, char *key, int *compress)
{
	char buf[LINE_LENGTH];

	if (!fread(buf, sizeof(buf), 1, in))
		return -1;
	if (buf[DELIM1_OFFSET] != ' ' || buf[DELIM2_OFFSET] != '\n')
		die("Parse error at line %d", line);
	hex2bin(buf, tag, HASHLEN);
	hex2bin(buf + KEY_OFFSET, key, HASHLEN);
	*compress=COMP_ZLIB;
	return 0;
}


/**** Binary keyring ****/

static void validate_binary_header(void)
{
	struct kr_header hdr;
	unsigned long len;

	fseek(in, 0, SEEK_END);
	len=ftell(in);
	rewind(in);
	if (!fread(&hdr, sizeof(hdr), 1, in))
		die("Couldn't read binary keyring header");
	hdr.magic=htonl(hdr.magic);
	hdr.entries=htonl(hdr.entries);
	if (hdr.magic != KR_MAGIC)
		die("Invalid magic number for binary keyring: 0x%x", hdr.magic);
	if (hdr.version != KR_VERSION)
		die("Invalid version for binary keyring: %d", hdr.version);
	if (len != hdr.entries * sizeof(struct kr_entry) +
				sizeof(struct kr_header))
		die("Invalid keyring length");
}

static int fetch_entry_binary(int line, char *tag, char *key, int *compress)
{
	struct kr_entry entry;

	if (!fread(&entry, sizeof(entry), 1, in))
		return -1;
	switch (entry.compress) {
	case KR_COMPRESS_NONE:
		*compress=COMP_NONE;
		break;
	case KR_COMPRESS_ZLIB:
		*compress=COMP_ZLIB;
		break;
	default:
		die("Decode error at line %d", line);
	}
	memcpy(tag, entry.tag, HASHLEN);
	memcpy(key, entry.key, HASHLEN);
	return 0;
}


/**** Main ****/

static void process_entries(int binary)
{
	int (*fetch_entry)(int, char *, char *, int *);
	sqlite3_stmt *begin;
	sqlite3_stmt *ins;
	sqlite3_stmt *end;
	char *tag;
	char *key;
	int compress;
	int i;

	if (binary)
		fetch_entry=fetch_entry_binary;
	else
		fetch_entry=fetch_entry_ascii;

	if (sqlite3_prepare(db, "BEGIN TRANSACTION", -1, &begin, NULL))
		sqlerr("Preparing begin statement");
	if (sqlite3_prepare(db, "COMMIT", -1, &end, NULL))
		sqlerr("Preparing commit statement");
	if (sqlite3_prepare(db, "INSERT INTO keys "
				"(chunk, tag, key, compression) "
				"VALUES (?1, ?2, ?3, ?4)", -1, &ins, NULL))
		sqlerr("Preparing insert statement");

	step("Beginning transaction", begin);
	for (i=0; ; i++) {
		tag=malloc(HASHLEN);
		key=malloc(HASHLEN);
		if (tag == NULL || key == NULL)
			die("malloc failed");
		if (fetch_entry(i + 1, tag, key, &compress))
			break;
		if (sqlite3_bind_int(ins, 1, i))
			sqlerr("Binding chunk number");
		if (sqlite3_bind_blob(ins, 2, tag, HASHLEN, free))
			sqlerr("Binding tag");
		if (sqlite3_bind_blob(ins, 3, key, HASHLEN, free))
			sqlerr("Binding key");
		if (sqlite3_bind_int(ins, 4, compress))
			sqlerr("Binding compression");
		step("Executing insert", ins);
		if (i > 0 && i % 5000 == 0) {
			step("Ending transaction", end);
			step("Beginning transaction", begin);
		}
	}
	step("Ending transaction", end);

	if (sqlite3_finalize(begin))
		sqlerr("Finalizing begin statement");
	if (sqlite3_finalize(ins))
		sqlerr("Finalizing insert statement");
	if (sqlite3_finalize(end))
		sqlerr("Finalizing end statement");
}

static void usage(char *argv0)
{
	die("Usage: %s [-b] infile outfile", argv0);
}

int main(int argc, char **argv)
{
	char *infile;
	char *outfile;
	int opt;
	int binary=0;

	while (1) {
		opt=getopt(argc, argv, "b");
		if (opt == 'b')
			binary=1;
		else if (opt == -1)
			break;
		else
			usage(argv[0]);
	}
	if (optind != argc - 2)
		usage(argv[0]);
	infile=argv[optind];
	outfile=argv[optind+1];

	in=fopen(infile, "r");
	if (in == NULL)
		die("Couldn't open %s", infile);
	if (binary)
		validate_binary_header();
	if (exists(outfile))
		die("%s already exists", outfile);
	if (sqlite3_open(outfile, &db))
		sqlerr("Opening database");
	dbpath=outfile;

	if (sqlite3_exec(db, "PRAGMA auto_vacuum = 0", NULL, NULL, NULL))
		sqlerr("Disabling auto-vacuum");
	if (sqlite3_exec(db, "PRAGMA legacy_file_format = ON", NULL, NULL,
				NULL))
		sqlerr("Enabling legacy database format");
	if (sqlite3_exec(db, "PRAGMA user_version = 1", NULL, NULL, NULL))
		sqlerr("Setting schema version");

	if (sqlite3_exec(db, "CREATE TABLE keys ("
				"chunk INTEGER PRIMARY KEY NOT NULL, "
				"tag BLOB NOT NULL, "
				"key BLOB NOT NULL, "
				"compression INTEGER NOT NULL)",
				NULL, NULL, NULL))
		sqlerr("Creating table");
	/* XXX makes the file larger.  do we need this? */
	if (sqlite3_exec(db, "CREATE INDEX keys_tags ON keys (tag)",
				NULL, NULL, NULL))
		sqlerr("Creating index");

	process_entries(binary);

	if (sqlite3_close(db))
		sqlerr("Closing database");
	fclose(in);
	return 0;
}
