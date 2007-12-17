/*
 * query - SQLite command-line query tool
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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sqlite3.h>

#define MAX_PARAMS 256
#define MAX_ATTACHED 10
#define MAX_RETRY_USECS 5000

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

typedef enum {
	OK = 0,
	FAIL_TEMP = -1,  /* temporary error */
	FAIL = -2        /* fatal error */
} ret_t;

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

static void backoff_delay(void)
{
	usleep(random() % MAX_RETRY_USECS);
}

static ret_t attach_dbs(void)
{
	sqlite3_stmt *stmt;
	int i;

	for (i=0; i<MAX_ATTACHED; i++) {
		if (attached_names[i] == NULL)
			break;
		/* A successful ATTACH invalidates prepared statements, so we
		   have to redo this every iteration */
		if (sqlite3_prepare_v2(db, "ATTACH ?1 as ?2", -1, &stmt,
					NULL)) {
			sqlerr("Preparing ATTACH statement");
			return FAIL;
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
		if (sqlite3_step(stmt) != SQLITE_DONE) {
			sqlerr("Executing ATTACH statement");
			goto bad;
		}
		sqlite3_finalize(stmt);
	}
	return OK;

bad:
	sqlite3_finalize(stmt);
	return FAIL;
}

/* Returns the number of parameters used in this binding or an error code */
static int bind_parameters(sqlite3_stmt *stmt, int loop_ctr)
{
	int i;
	int count=sqlite3_bind_parameter_count(stmt);
	int param=used_params;
	int ret;

	for (i=1; i <= count; i++) {
		if (param == num_params) {
			fprintf(stderr, "Not enough parameters for query\n");
			return FAIL;
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
			return (ret == SQLITE_NOMEM) ? FAIL_TEMP : FAIL;
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

static ret_t handle_rows(sqlite3_stmt *stmt, int do_cols)
{
	int ret;

	while ((ret=sqlite3_step(stmt)) != SQLITE_DONE) {
		if (ret == SQLITE_ROW) {
			if (show_col_names && do_cols) {
				do_cols=0;
				handle_col_names(stmt);
			}
			handle_row(stmt);
		} else {
			if (ret != SQLITE_BUSY)
				sqlerr("Executing query");
			return (ret == SQLITE_BUSY) ? FAIL_TEMP : FAIL;
		}
	}
	return OK;
}

static ret_t make_queries(char *str)
{
	const char *query;
	sqlite3_stmt *stmt;
	ret_t ret;
	int ctr;
	unsigned changes=0;
	int params=0;  /* Silence compiler warning */

	used_params=0;
	for (query=str; *query; ) {
		if (sqlite3_prepare_v2(db, query, -1, &stmt, &query)) {
			sqlerr("Preparing query");
			return FAIL;
		}
		for (ctr=loop_min; ctr <= loop_max; ctr++) {
			params=bind_parameters(stmt, ctr);
			if (params < 0) {
				sqlite3_finalize(stmt);
				return params;
			}
			ret=handle_rows(stmt, ctr == loop_min);
			if (ret) {
				sqlite3_finalize(stmt);
				return ret;
			}
			changes += sqlite3_changes(db);
			sqlite3_reset(stmt);
		}
		used_params += params;
		if (changes)
			fprintf(tmp, "%d rows updated\n", changes);
		sqlite3_finalize(stmt);
	}
	return OK;
}

static ret_t begin(void)
{
	if (no_transaction)
		return OK;
	if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL)) {
		sqlerr("Beginning transaction");
		return FAIL;
	}
	return OK;
}

static ret_t rollback(void)
{
	if (no_transaction) {
		fprintf(stderr, "Can't roll back: not within a transaction");
		return FAIL;
	}
	if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL)) {
		sqlerr("Rolling back transaction");
		return FAIL;
	}
	return OK;
}

static ret_t commit(void)
{
	if (no_transaction)
		return OK;
	if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL)) {
		sqlerr("Committing transaction");
		return FAIL;
	}
	return OK;
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

static ret_t do_transaction(char *sql)
{
	ret_t qres;
	int i;

	for (i=0; i<10; i++) {
		if (begin())
			return FAIL;
		qres=make_queries(sql);
		if (qres != OK || commit()) {
			fflush(tmp);
			rewind(tmp);
			ftruncate(fileno(tmp), 0);
			if (rollback() || qres != FAIL_TEMP)
				return FAIL;
		} else {
			cat_tmp();
			if (used_params < num_params)
				fprintf(stderr, "Warning: %d params provided "
							"but only %d used\n",
							num_params,
							used_params);
			return OK;
		}
	}
	fprintf(stderr, "Retries exceeded\n");
	return FAIL;
}

static int busy_handler(void *unused, int count)
{
	(void)unused;  /* silence warning */
	(void)count;   /* likewise */
	backoff_delay();
	return 1;
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
	char *arg;
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
			arg=strdup(optarg);
			if (arg == NULL)
				die("malloc error");
			cp=strchr(arg, ':');
			if (cp == NULL)
				usage(argv[0]);
			*cp=0;
			attached_names[num_attached]=arg;
			attached_files[num_attached]=cp+1;
			num_attached++;
			break;
		case 'r':
			arg=strdup(optarg);
			if (arg == NULL)
				die("malloc error");
			cp=strchr(arg, ':');
			if (cp == NULL)
				usage(argv[0]);
			*cp=0;
			loop_min=parseInt(argv[0], arg);
			loop_max=parseInt(argv[0], cp+1);
			if (loop_min > loop_max)
				die("min cannot be greater than max for -r");
			free(arg);
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

	srandom(time(NULL));
	tmp=tmpfile();
	if (tmp == NULL)
		die("Can't create temporary file");
	if (sqlite3_open(dbfile, &db)) {
		sqlerr("Opening database");
		exit(1);
	}
	if (sqlite3_busy_handler(db, busy_handler, NULL)) {
		sqlerr("Setting busy handler");
		sqlite3_close(db);
		exit(1);
	}
	if (attach_dbs() || do_transaction(sql))
		ret=1;
	if (sqlite3_close(db))
		sqlerr("Closing database");
	return ret;
}
