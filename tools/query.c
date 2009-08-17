/*
 * query - SQLite command-line query tool
 *
 * Copyright (C) 2007-2008 Carnegie Mellon University
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <sql.h>

#define MAX_PARAMS 256
#define MAX_ATTACHED 10

static struct db *db;
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
static int num_attached;

typedef enum {
	OK = 0,
	FAIL_TEMP = -1,  /* temporary error */
	FAIL = -2        /* fatal error */
} ret_t;

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

static ret_t attach_dbs(void)
{
	int i;

	for (i=0; i<MAX_ATTACHED; i++) {
		if (attached_names[i] == NULL)
			break;
		if (!attach(db, attached_names[i], attached_files[i]))
			return FAIL;
	}
	return OK;
}

static ret_t init_query(struct query **new_qry, const char *sql, int loop_ctr,
			int initial_param, int n_params)
{
	struct query_params *qparams;
	struct query *qry;
	int i;
	gboolean ret;

	qparams = query_params_new(SQL_PARAM_INPUT);
	for (i = 0; i < n_params; i++) {
		if (param_length[i + initial_param])
			 query_param_set(qparams, i, 'B',
					params[i + initial_param],
					param_length[i + initial_param]);
		else if (params[i + initial_param])
			query_param_set(qparams, i, 'S',
					params[i + initial_param]);
		else
			query_param_set(qparams, i, 'd', loop_ctr);
	}
	ret = query_v(&qry, db, sql, qparams);
	query_params_free(qparams);
	if (!ret) {
		sql_log_err(db, "Couldn't construct query");
		if (query_busy(db))
			return FAIL_TEMP;
		else
			return FAIL;
	}
	*new_qry = qry;
	return OK;
}

static void handle_col_names(struct query *qry)
{
	gchar **names;
	int count;
	int i;

	if (!show_col_names)
		return;
	names = query_column_names(qry);
	count = g_strv_length(names);
	for (i = 0; i < count; i++) {
		if (i)
			fprintf(tmp, "|");
		fprintf(tmp, "%s", names[i]);
	}
	if (count)
		fprintf(tmp, "\n");
	g_strfreev(names);
}

static void handle_row(struct query *qry)
{
	gchar *types = query_column_types(qry);
	int count = strlen(types);
	const char *string[count];
	const void *blob[count];
	const int bloblen[count];
	struct query_params *qparams;
	int i;
	gchar *buf;

	qparams = query_params_new(SQL_PARAM_OUTPUT);
	for (i = 0; i < count; i++) {
		switch (types[i]) {
		case 'b':
			query_param_set(qparams, i, 'b', &blob[i], &bloblen[i]);
			break;
		case '0':
			break;
		default:
			query_param_set(qparams, i, 's', &string[i]);
		}
	}
	query_row_v(qry, qparams);
	for (i = 0; i < count; i++) {
		if (i)
			fprintf(tmp, "|");
		switch (types[i]) {
		case 'b':
			buf = g_malloc(2 * bloblen[i] + 1);
			bin2hex(blob[i], buf, bloblen[i]);
			fprintf(tmp, "%s", buf);
			g_free(buf);
			break;
		case '0':
			fprintf(tmp, "<null>");
			break;
		default:
			fprintf(tmp, "%s", string[i]);
		}
	}
	if (count)
		fprintf(tmp, "\n");
	query_params_free(qparams);
	g_free(types);
	query_next(qry);
}

static int get_changes(struct query *qry)
{
	gchar *types;
	gchar **names;
	int count;

	if (!query_has_row(db))
		return 0;
	types = query_column_types(qry);
	if (strcmp("d", types)) {
		g_free(types);
		return 0;
	}
	g_free(types);
	names = query_column_names(qry);
	if (!g_str_has_prefix(names[0], "rows ")) {
		g_strfreev(names);
		return 0;
	}
	g_strfreev(names);
	query_row(qry, "d", &count);
	query_next(qry);
	return count;
}

static ret_t make_queries(gchar **queries, int param_count[])
{
	int query_count = g_strv_length(queries);
	int cur_param;
	struct query *qry;
	int i;
	ret_t ret;
	int ctr;
	int changes;

	for (i = 0, cur_param = 0; i < query_count;
				cur_param += param_count[i++]) {
		for (ctr = loop_min, changes = 0; ctr <= loop_max; ctr++) {
			ret = init_query(&qry, queries[i], ctr, cur_param,
						param_count[i]);
			if (ret)
				return ret;

			changes += get_changes(qry);
			if (query_has_row(db) && ctr == loop_min)
				handle_col_names(qry);
			while (query_has_row(db))
				handle_row(qry);

			query_free(qry);
			if (query_busy(db)) {
				return FAIL_TEMP;
			} else if (!query_ok(db)) {
				sql_log_err(db, "Executing query");
				return FAIL;
			}
		}
		if (changes)
			fprintf(tmp, "%d rows updated\n", changes);
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
	gchar **queries;
	int query_count;
	int *param_count;
	int total_params = 0;
	int i;
	ret_t qres;

	queries = sql_split(db, sql);
	if (queries == NULL)
		return FAIL;
	query_count = g_strv_length(queries);
	param_count = g_new(int, query_count);
	for (i = 0; i < query_count; i++) {
		param_count[i] = query_parameter_count(db, queries[i]);
		total_params += param_count[i];
	}
	if (total_params > num_params) {
		fprintf(stderr, "Not enough parameters for query\n");
		goto fail;
	} else if (total_params < num_params) {
		fprintf(stderr, "Warning: %d params provided but only %d "
					"used\n", num_params, total_params);
	}

again:
	if (no_transaction) {
		if (!begin_bare(db))
			goto fail;
	} else {
		if (!begin(db))
			goto fail;
	}
	qres=make_queries(queries, param_count);
	if (qres != OK || !commit(db)) {
		if (!rollback(db) || qres != FAIL_TEMP)
			goto fail;
		fflush(tmp);
		rewind(tmp);
		if (ftruncate(fileno(tmp), 0))
			goto fail;
		query_backoff(db);
		goto again;
	}

	cat_tmp();
	g_free(param_count);
	g_strfreev(queries);
	return OK;

fail:
	g_free(param_count);
	g_strfreev(queries);
	return FAIL;
}

static void handle_log_message(const gchar *domain, GLogLevelFlags level,
			const gchar *message, void *data)
{
	/* Silence compiler warnings */
	(void)domain;
	(void)data;

	if (level == G_LOG_LEVEL_CRITICAL || level == G_LOG_LEVEL_MESSAGE)
		fprintf(stderr, "%s\n", message);
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

	g_log_set_handler("isrsql", G_LOG_LEVEL_MASK, handle_log_message, NULL);
	sql_init();
	tmp=tmpfile();
	if (tmp == NULL)
		die("Can't create temporary file");
	if (!sql_conn_open(dbfile, &db)) {
		g_critical("Couldn't open database");
		exit(1);
	}
	if (attach_dbs() || do_transaction(sql))
		ret=1;
	sql_conn_close(db);
	return ret;
}
