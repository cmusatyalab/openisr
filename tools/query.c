#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sqlite3.h>

#define RETRY_USECS 5000

static sqlite3 *db;

static void sqlerr(char *prefix)
{
	fprintf(stderr, "%s: %s\n", prefix, sqlite3_errmsg(db));
}

static void __attribute__ ((noreturn)) die(char *str, ...)
{
	va_list ap;

	va_start(ap, str);
	vfprintf(stderr, str, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

static void bin2hex(unsigned const char *bin, char *hex, int bin_len)
{
	int i;
	unsigned cur;

	for (i=0; i<bin_len; i++) {
		cur=bin[i];
		sprintf(hex+2*i, "%.2x", cur);
	}
}

static void handle_row(sqlite3_stmt *stmt)
{
	int i;
	int count=sqlite3_column_count(stmt);
	const void *out;
	char *buf;
	int len;

	for (i=0; i<count; i++) {
		if (i)
			printf("|");
		if (sqlite3_column_type(stmt, i) == SQLITE_BLOB) {
			out=sqlite3_column_blob(stmt, i);
			len=sqlite3_column_bytes(stmt, i);
			buf=malloc(2 * len + 1);
			if (buf == NULL)
				die("malloc failure");
			bin2hex(out, buf, len);
			printf("%s", buf);
			free(buf);
		} else {
			printf("%s", sqlite3_column_text(stmt, i));
		}
	}
	if (count)
		printf("\n");
}

static int make_queries(char *str)
{
	const char *query;
	sqlite3_stmt *stmt;
	int ret;

	for (query=str; *query; ) {
		if (sqlite3_prepare(db, query, -1, &stmt, &query)) {
			sqlerr("Preparing query");
			return -1;
		}
		while ((ret=sqlite3_step(stmt)) != SQLITE_DONE) {
			if (ret == SQLITE_ROW) {
				handle_row(stmt);
			} else {
				if (ret != SQLITE_BUSY)
					sqlerr("Executing query");
				sqlite3_finalize(stmt);
				return -1;
			}
		}
		sqlite3_finalize(stmt);
	}
	return 0;
}

static int commit(void)
{
	int ret;
	int i;

	for (i=0; i<20; i++) {
		ret=sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
		if (ret == SQLITE_BUSY) {
			usleep(RETRY_USECS);
		} else if (ret) {
			sqlerr("Committing transaction");
			return -1;
		} else {
			return 0;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	int i;
	int ret=0;

	if (argc != 3)
		die("Usage: %s database query", argv[0]);
	if (sqlite3_open(argv[1], &db)) {
		sqlerr("Opening database");
		exit(1);
	}
	for (i=0; i<10; i++) {
		if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL)) {
			sqlerr("Beginning transaction");
			ret=1;
			break;
		}
		if (make_queries(argv[2]) || commit()) {
			if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL)) {
				sqlerr("Rolling back transaction");
				ret=1;
				break;
			}
		} else {
			break;
		}
	}
	if (sqlite3_close(db))
		sqlerr("Closing database");
	if (i == 10)
		die("Retries exceeded");
	return ret;
}
