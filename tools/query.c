#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#define RETRY_USECS 5000
#define MAX_PARAMS 256
#define MAX_ATTACHED 10

static sqlite3 *db;
static FILE *tmp;
static char *params[MAX_PARAMS];  /* null if loop counter */
static unsigned param_length[MAX_PARAMS];  /* zero if not blob */
static char *attached_names[MAX_ATTACHED];
static char *attached_files[MAX_ATTACHED];
static int loop_min=1;
static int loop_max=1;
static int show_col_names;
static int no_transaction;
static int num_params;
static int used_params;
static int num_attached;
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

static int attach_dbs(void)
{
	sqlite3_stmt *stmt;
	int i;
	int j;
	int ret;

	for (i=0; i<MAX_ATTACHED; i++) {
		if (attached_names[i] == NULL)
			break;
		/* A successful ATTACH invalidates prepared statements, so we
		   have to redo this every iteration */
		if (sqlite3_prepare(db, "ATTACH ?1 as ?2", -1, &stmt, NULL)) {
			sqlerr("Preparing ATTACH statement");
			return -1;
		}
		if (sqlite3_bind_text(stmt, 1, attached_files[i], -1,
					SQLITE_STATIC)) {
			sqlerr("Binding database filename");
			goto bad;
		}
		if (sqlite3_bind_text(stmt, 2, attached_names[i], -1,
					SQLITE_STATIC)) {
			sqlerr("Binding database name");
			goto bad;
		}
		for (j=0; ; j++) {
			if (j >= 10) {
				fprintf(stderr, "Retries exceeded\n");
				goto bad;
			}
			ret=sqlite3_step(stmt);
			if (ret == SQLITE_DONE) {
				break;
			} else if (ret == SQLITE_BUSY) {
				usleep(RETRY_USECS);
			} else {
				sqlerr("Executing ATTACH statement");
				goto bad;
			}
		}
		sqlite3_finalize(stmt);
	}
	return 0;

bad:
	sqlite3_finalize(stmt);
	return -1;
}

/* Returns the number of parameters used in this binding, -1 on temporary
   error, or -2 on fatal error */
static int bind_parameters(sqlite3_stmt *stmt, int loop_ctr)
{
	int i;
	int count=sqlite3_bind_parameter_count(stmt);
	int param=used_params;
	int ret;

	for (i=1; i <= count; i++) {
		if (param == num_params) {
			fprintf(stderr, "Not enough parameters for query\n");
			return -2;
		}
		if (param_length[param])
			ret=sqlite3_bind_blob(stmt, i, params[param],
						param_length[param],
						SQLITE_STATIC);
		else if (params[param])
			ret=sqlite3_bind_text(stmt, i, params[param], -1,
						SQLITE_STATIC);
		else
			ret=sqlite3_bind_int(stmt, i, loop_ctr);
		if (ret) {
			sqlerr("Binding parameter");
			return (ret == SQLITE_NOMEM) ? -1 : -2;
		}
		param++;
	}
	return count;
}

static void handle_col_names(sqlite3_stmt *stmt)
{
	int i;
	int count=sqlite3_column_count(stmt);

	for (i=0; i<count; i++) {
		if (i)
			fprintf(tmp, "|");
		fprintf(tmp, "%s", sqlite3_column_name(stmt, i));
	}
	if (count)
		fprintf(tmp, "\n");
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
		switch (sqlite3_column_type(stmt, i)) {
		case SQLITE_BLOB:
			out=sqlite3_column_blob(stmt, i);
			len=sqlite3_column_bytes(stmt, i);
			buf=malloc(2 * len + 1);
			if (buf == NULL)
				die("malloc failure");
			bin2hex(out, buf, len);
			fprintf(tmp, "%s", buf);
			free(buf);
			break;
		case SQLITE_NULL:
			fprintf(tmp, "<null>");
			break;
		default:
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
	int ctr;
	int did_cols;
	unsigned changes=0;
	int params;

	used_params=0;
	for (query=str; *query; ) {
		if (sqlite3_prepare(db, query, -1, &stmt, &query)) {
			sqlerr("Preparing query");
			return -1;
		}
		for (ctr=loop_min; ctr <= loop_max; ctr++) {
			params=bind_parameters(stmt, ctr);
			if (params < 0) {
				sqlite3_finalize(stmt);
				return params == -2 ? -1 : 1;
			}
			did_cols=0;
			while ((ret=sqlite3_step(stmt)) != SQLITE_DONE) {
				if (ret == SQLITE_ROW) {
					if (show_col_names && !did_cols) {
						did_cols=1;
						handle_col_names(stmt);
					}
					handle_row(stmt);
				} else {
					if (ret != SQLITE_BUSY)
						sqlerr("Executing query");
					sqlite3_finalize(stmt);
					return (ret == SQLITE_BUSY) ? 1 : -1;
				}
			}
			changes += sqlite3_changes(db);
			sqlite3_reset(stmt);
		}
		used_params += params;
		if (changes)
			fprintf(tmp, "%d rows updated\n", changes);
		sqlite3_finalize(stmt);
	}
	return 0;
}

static int begin(void)
{
	if (no_transaction)
		return 0;
	if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL)) {
		sqlerr("Beginning transaction");
		return -1;
	}
	return 0;
}

static int rollback(void)
{
	if (no_transaction) {
		fprintf(stderr, "Can't roll back: not within a transaction");
		return -1;
	}
	if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL)) {
		sqlerr("Rolling back transaction");
		return -1;
	}
	return 0;
}

static int commit(void)
{
	int ret;
	int i;

	if (no_transaction)
		return 0;
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

static int do_transaction(char *sql)
{
	int qres;
	int i;

	for (i=0; i<10; i++) {
		if (begin())
			return -1;
		qres=make_queries(sql);
		if (qres || commit()) {
			fflush(tmp);
			rewind(tmp);
			ftruncate(fileno(tmp), 0);
			if (rollback() || qres < 0)
				return -1;
		} else {
			cat_tmp();
			if (used_params < num_params)
				fprintf(stderr, "Warning: %d params provided "
							"but only %d used\n",
							num_params,
							used_params);
			return 0;
		}
	}
	fprintf(stderr, "Retries exceeded\n");
	return -1;
}

static void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [flags] database query\n", argv0);
	fprintf(stderr, "\t-a name:file - attach database\n");
	fprintf(stderr, "\t-r min:max - iterate each statement over counter range\n");
	fprintf(stderr, "\t-p param - statement parameter\n");
	fprintf(stderr, "\t-b param - blob parameter in hex\n");
	fprintf(stderr, "\t-i - use loop counter as statement parameter\n");
	fprintf(stderr, "\t-c - print column names\n");
	fprintf(stderr, "\t-t - don't execute query within a transaction\n");
	exit(2);
}

static int parseInt(char *argv0, char *str)
{
	char *endptr;
	int ret;

	ret=strtol(str, &endptr, 10);
	if (*str == 0 || *endptr != 0)
		usage(argv0);
	return ret;
}

static void parse_cmdline(int argc, char **argv, char **dbfile, char **sql)
{
	int opt;
	char *cp;

	while ((opt=getopt(argc, argv, "a:r:b:p:ict")) != -1) {
		switch (opt) {
		case '?':
			usage(argv[0]);
			break;
		case 'b':
		case 'p':
		case 'i':
			if (num_params == MAX_PARAMS)
				die("Too many parameters");
			if (opt == 'b') {
				params[num_params]=mkbin(optarg,
						&param_length[num_params]);
			} else if (opt == 'p') {
				params[num_params]=optarg;
			}
			num_params++;
			break;
		case 'a':
			if (num_attached == MAX_ATTACHED)
				die("Too many attached databases");
			cp=strchr(optarg, ':');
			if (cp == NULL)
				usage(argv[0]);
			*cp=0;
			attached_names[num_attached]=optarg;
			attached_files[num_attached]=cp+1;
			num_attached++;
			break;
		case 'r':
			cp=strchr(optarg, ':');
			if (cp == NULL)
				usage(argv[0]);
			*cp=0;
			loop_min=parseInt(argv[0], optarg);
			loop_max=parseInt(argv[0], cp+1);
			if (loop_min > loop_max)
				die("min cannot be greater than max for -r");
			break;
		case 'c':
			show_col_names=1;
			break;
		case 't':
			no_transaction=1;
			break;
		}
	}
	if (optind != argc - 2)
		usage(argv[0]);
	*dbfile=argv[optind];
	*sql=argv[optind+1];
}

int main(int argc, char **argv)
{
	char *dbfile;
	char *sql;
	int ret=0;

	parse_cmdline(argc, argv, &dbfile, &sql);

	tmp=tmpfile();
	if (tmp == NULL)
		die("Can't create temporary file");
	if (sqlite3_open(dbfile, &db)) {
		sqlerr("Opening database");
		exit(1);
	}
	if (attach_dbs() || do_transaction(sql))
		ret=1;
	if (sqlite3_close(db))
		sqlerr("Closing database");
	return ret;
}
