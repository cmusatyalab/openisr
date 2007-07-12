#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#define RETRY_USECS 5000
#define MAX_PARAMS 256

static sqlite3 *db;
static FILE *tmp;
static char *params[MAX_PARAMS];
static unsigned param_length[MAX_PARAMS];  /* zero if not blob */
static int num_params;
static int used_params;
extern char *optarg;
extern int optind;

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

static inline int charval(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	die("Invalid hex character '%c'", c);
}

static inline void hex2bin(char *hex, char *bin, int bin_len)
{
	unsigned char *uhex=(unsigned char *)hex;
	int i;

	for (i=0; i<bin_len; i++)
		bin[i] = (charval(uhex[2*i]) << 4) + charval(uhex[2*i+1]);
}

static char *mkbin(char *hex, unsigned *length)
{
	size_t len=strlen(hex);
	char *buf;

	if (len == 0 || len % 2)
		die("Invalid hex string: %s", hex);
	len /= 2;
	buf=malloc(len);
	if (buf == NULL)
		die("malloc failure");
	hex2bin(hex, buf, len);
	*length=len;
	return buf;
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
			fprintf(tmp, "|");
		if (sqlite3_column_type(stmt, i) == SQLITE_BLOB) {
			out=sqlite3_column_blob(stmt, i);
			len=sqlite3_column_bytes(stmt, i);
			buf=malloc(2 * len + 1);
			if (buf == NULL)
				die("malloc failure");
			bin2hex(out, buf, len);
			fprintf(tmp, "%s", buf);
			free(buf);
		} else {
			fprintf(tmp, "%s", sqlite3_column_text(stmt, i));
		}
	}
	if (count)
		fprintf(tmp, "\n");
}

/* Returns 0 on success, 1 on temporary error, -1 on fatal error */
static int make_queries(char *str)
{
	const char *query;
	sqlite3_stmt *stmt;
	int ret;
	int i;
	int count;

	used_params=0;
	for (query=str; *query; ) {
		if (sqlite3_prepare(db, query, -1, &stmt, &query)) {
			sqlerr("Preparing query");
			return -1;
		}
		count=sqlite3_bind_parameter_count(stmt);
		for (i=1; i <= count; i++) {
			if (used_params == num_params) {
				fprintf(stderr, "Not enough parameters "
						"for query\n");
				sqlite3_finalize(stmt);
				return -1;
			}
			if (param_length[used_params])
				ret=sqlite3_bind_blob(stmt, i,
						params[used_params],
						param_length[used_params],
						SQLITE_STATIC);
			else
				ret=sqlite3_bind_text(stmt, i,
						params[used_params], -1,
						SQLITE_STATIC);
			if (ret) {
				sqlerr("Binding parameter");
				sqlite3_finalize(stmt);
				return (ret == SQLITE_NOMEM) ? 1 : -1;
			}
			used_params++;
		}
		while ((ret=sqlite3_step(stmt)) != SQLITE_DONE) {
			if (ret == SQLITE_ROW) {
				handle_row(stmt);
			} else {
				if (ret != SQLITE_BUSY)
					sqlerr("Executing query");
				sqlite3_finalize(stmt);
				return 1;
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

static void cat_tmp(void)
{
	char buf[4096];
	size_t len;
	size_t i;

	rewind(tmp);
	while ((len=fread(buf, 1, sizeof(buf), tmp))) {
		for (i=0; i<len; i += fwrite(buf + i, 1, len - i, stdout));
	}
}

static void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [flags] database query\n", argv0);
	fprintf(stderr, "\t-p param - statement parameter\n");
	fprintf(stderr, "\t-b param - blob parameter in hex\n");
	exit(2);
}

int main(int argc, char **argv)
{
	int i;
	int ret=0;
	int qres;
	int opt;

	while ((opt=getopt(argc, argv, "b:p:")) != -1) {
		if (opt == '?')
			usage(argv[0]);
		if (opt == 'b' || opt == 'p') {
			if (num_params == MAX_PARAMS)
				die("Too many parameters");
			if (opt == 'b') {
				params[num_params]=mkbin(optarg,
						&param_length[num_params]);
			} else {
				params[num_params]=optarg;
			}
			num_params++;
		}
	}
	if (optind != argc - 2)
		usage(argv[0]);

	tmp=tmpfile();
	if (tmp == NULL)
		die("Can't create temporary file");
	if (sqlite3_open(argv[optind], &db)) {
		sqlerr("Opening database");
		exit(1);
	}
	for (i=0; i<10; i++) {
		if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL)) {
			sqlerr("Beginning transaction");
			ret=1;
			break;
		}
		qres=make_queries(argv[optind+1]);
		if (qres || commit()) {
			fflush(tmp);
			rewind(tmp);
			ftruncate(fileno(tmp), 0);
			if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL)) {
				sqlerr("Rolling back transaction");
				ret=1;
				break;
			}
			if (qres < 0) {
				ret=1;
				break;
			}
		} else {
			cat_tmp();
			break;
		}
	}
	if (ret == 0 && used_params < num_params)
		fprintf(stderr, "Warning: %d params provided but only %d "
					"used\n", num_params, used_params);
	if (sqlite3_close(db))
		sqlerr("Closing database");
	if (i == 10)
		die("Retries exceeded");
	return ret;
}
