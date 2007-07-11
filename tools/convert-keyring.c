#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#define HASHLEN 20
#define ASCII_HASHLEN 40

enum kr_compress {
	KR_COMPRESS_NONE = 0,
	KR_COMPRESS_ZLIB = 1,
	KR_COMPRESS_LZF  = 2
};

sqlite3 *db;

#define die(str, args...) do { \
		printf(str "\n", ##args); \
		exit(1); \
	} while (0)

static void sqlerr(char *prefix)
{
	printf("%s: %s\n", prefix, sqlite3_errmsg(db));
	sqlite3_close(db);
	exit(1);
}

static inline int charval(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a';
	if (c >= 'A' && c <= 'F')
		return c - 'A';
	die("Invalid character %u", c);
}

static inline void hex2bin(char *hex, char *bin, int bin_len)
{
	unsigned char *uhex=(unsigned char *)hex;
	int i;

	for (i=0; i<bin_len; i++)
		bin[i] = (charval(uhex[2*i]) << 4) + charval(uhex[2*i+1]);
}

static void step(char *desc, sqlite3_stmt *step)
{
	if (sqlite3_step(step) != SQLITE_DONE)
		sqlerr(desc);
	if (sqlite3_reset(step))
		sqlerr(desc);
}

int main(int argc, char **argv)
{
	sqlite3_stmt *begin;
	sqlite3_stmt *ins;
	sqlite3_stmt *end;
	FILE *fp;
	char buf[128];
	int i;
	char *tag;
	char *key;

	if (argc != 3)
		die("Usage: %s infile outfile", argv[0]);

	fp=fopen(argv[1], "r");
	if (fp == NULL)
		die("Couldn't open %s", argv[1]);
	if (sqlite3_open(argv[2], &db))
		sqlerr("Opening database");

	if (sqlite3_exec(db, "PRAGMA auto_vacuum = none", NULL, NULL, NULL))
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

	if (sqlite3_prepare(db, "BEGIN TRANSACTION", -1, &begin, NULL))
		sqlerr("Preparing begin statement");
	if (sqlite3_prepare(db, "COMMIT", -1, &end, NULL))
		sqlerr("Preparing commit statement");
	if (sqlite3_prepare(db, "INSERT INTO keys "
				"(chunk, tag, key, compression) "
				"VALUES (?1, ?2, ?3, ?4)", -1, &ins, NULL))
		sqlerr("Preparing insert statement");

	step("Beginning transaction", begin);
	for (i=0; fgets(buf, sizeof(buf), fp); i++) {
		tag=malloc(HASHLEN);
		key=malloc(HASHLEN);
		if (tag == NULL || key == NULL)
			die("malloc failed");
		if (buf[ASCII_HASHLEN] != ' ' ||
					buf[2 * ASCII_HASHLEN + 1] != '\n')
			die("Parse error at line %d", i + 1);
		buf[ASCII_HASHLEN]=buf[2 * ASCII_HASHLEN + 1]=0;
		hex2bin(buf, tag, HASHLEN);
		hex2bin(buf + ASCII_HASHLEN + 1, key, HASHLEN);
		if (sqlite3_bind_int(ins, 1, i))
			sqlerr("Binding chunk number");
		if (sqlite3_bind_blob(ins, 2, tag, HASHLEN, free))
			sqlerr("Binding tag");
		if (sqlite3_bind_blob(ins, 3, key, HASHLEN, free))
			sqlerr("Binding key");
		if (sqlite3_bind_int(ins, 4, KR_COMPRESS_ZLIB))
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

	if (sqlite3_close(db))
		sqlerr("Closing database");
	fclose(fp);
	return 0;
}
