/*
 * Parcelkeeper - support daemon for the OpenISR (R) system virtual disk
 *
 * Copyright (C) 2006-2009 Carnegie Mellon University
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

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sqlite3.h>
#include "defs.h"

#define CACHE_BUCKETS 199
#define SLOW_THRESHOLD_MS 200
#define ERRBUFSZ 256
#define MAX_WAIT_USEC 10000
#define PROGRESS_HANDLER_INTERVAL 100000

struct query {
	sqlite3_stmt *stmt;
	const char *sql;
	struct timeval start;
};

static struct query *prepared[CACHE_BUCKETS];
static __thread int result;  /* set by query() and query_next() */
static __thread char errmsg[ERRBUFSZ];

static void sqlerr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(errmsg, ERRBUFSZ, fmt, ap);
	va_end(ap);
}

static unsigned get_bucket(const char *sql)
{
	/* DJB string hash algorithm */
	unsigned hash = 5381;

	while (*sql)
		hash = ((hash << 5) + hash) ^ *sql++;
	return hash % CACHE_BUCKETS;
}

static int alloc_query(struct query **new_qry, sqlite3 *db, const char *sql)
{
	struct query *qry;
	int ret;

	qry=g_slice_new(struct query);
	ret=sqlite3_prepare_v2(db, sql, -1, &qry->stmt, NULL);
	if (ret) {
		sqlerr("%s", sqlite3_errmsg(db));
		g_slice_free(struct query, qry);
	} else {
		qry->sql=sqlite3_sql(qry->stmt);
		*new_qry=qry;
	}
	return ret;
}

static void destroy_query(struct query *qry)
{
	sqlite3_finalize(qry->stmt);
	g_slice_free(struct query, qry);
}

static int get_query(struct query **new_qry, sqlite3 *db, const char *sql)
{
	unsigned bucket=get_bucket(sql);
	int ret;

	/* XXX when we go to multi-threaded, this will need locking */
	/* XXX also, might need a better hash table */
	if (prepared[bucket] && db == sqlite3_db_handle(prepared[bucket]->stmt)
				&& !strcmp(sql, prepared[bucket]->sql)) {
		*new_qry=prepared[bucket];
		prepared[bucket]=NULL;
		ret=SQLITE_OK;
		state.sql_hits++;
	} else {
		ret=alloc_query(new_qry, db, sql);
		state.sql_misses++;
	}

	if (ret == SQLITE_OK)
		gettimeofday(&(*new_qry)->start, NULL);
	return ret;
}

pk_err_t query(struct query **new_qry, sqlite3 *db, const char *query,
			const char *fmt, ...)
{
	struct query *qry;
	sqlite3_stmt *stmt;
	va_list ap;
	int i=1;
	int found_unknown=0;
	void *blob;

	if (new_qry != NULL)
		*new_qry=NULL;
	result=get_query(&qry, db, query);
	if (result)
		return PK_SQLERR;
	stmt=qry->stmt;
	va_start(ap, fmt);
	for (; fmt != NULL && *fmt; fmt++) {
		switch (*fmt) {
		case 'd':
			result=sqlite3_bind_int(stmt, i++, va_arg(ap, int));
			break;
		case 'D':
			result=sqlite3_bind_int64(stmt, i++, va_arg(ap,
						int64_t));
			break;
		case 'f':
			result=sqlite3_bind_double(stmt, i++, va_arg(ap,
						double));
			break;
		case 's':
		case 'S':
			result=sqlite3_bind_text(stmt, i++, va_arg(ap, char *),
						-1, *fmt == 's'
						? SQLITE_TRANSIENT
						: SQLITE_STATIC);
			break;
		case 'b':
		case 'B':
			blob=va_arg(ap, void *);
			result=sqlite3_bind_blob(stmt, i++, blob, va_arg(ap,
						int), *fmt == 'b'
						? SQLITE_TRANSIENT
						: SQLITE_STATIC);
			break;
		default:
			sqlerr("Unknown format specifier %c", *fmt);
			result=SQLITE_MISUSE;
			found_unknown=1;
			break;
		}
		if (result)
			break;
	}
	va_end(ap);
	if (result == SQLITE_OK)
		query_next(qry);
	else if (!found_unknown)
		sqlerr("%s", sqlite3_errmsg(db));
	if (result != SQLITE_ROW || new_qry == NULL)
		query_free(qry);
	else
		*new_qry=qry;
	if (result == SQLITE_OK || result == SQLITE_ROW)
		return PK_SUCCESS;
	else
		return PK_SQLERR;
}

pk_err_t query_next(struct query *qry)
{
	if (pending_signal()) {
		/* Try to stop the query.  If this succeeds, the transaction
		   will be automatically rolled back.  Often, though, the
		   attempt will not succeed. */
		sqlite3_interrupt(sqlite3_db_handle(qry->stmt));
	}
	result=sqlite3_step(qry->stmt);
	/* Collapse DONE into OK, since they're semantically equivalent and
	   it simplifies error checking */
	if (result == SQLITE_DONE)
		result=SQLITE_OK;
	/* Collapse IOERR_BLOCKED into BUSY, likewise */
	if (result == SQLITE_IOERR_BLOCKED)
		result=SQLITE_BUSY;
	if (result == SQLITE_OK || result == SQLITE_ROW) {
		return PK_SUCCESS;
	} else {
		sqlerr("%s", sqlite3_errmsg(sqlite3_db_handle(qry->stmt)));
		return PK_SQLERR;
	}
}

int query_result(void)
{
	return result;
}

const char *query_errmsg(void)
{
	return errmsg;
}

void query_row(struct query *qry, const char *fmt, ...)
{
	struct sqlite3_stmt *stmt=qry->stmt;
	va_list ap;
	int i=0;

	va_start(ap, fmt);
	for (; *fmt; fmt++) {
		switch (*fmt) {
		case 'd':
			*va_arg(ap, int *)=sqlite3_column_int(stmt, i++);
			break;
		case 'D':
			*va_arg(ap, int64_t *)=sqlite3_column_int64(stmt, i++);
			break;
		case 'f':
			*va_arg(ap, double *)=sqlite3_column_double(stmt, i++);
			break;
		case 's':
		case 'S':
			*va_arg(ap, const unsigned char **)=
						sqlite3_column_text(stmt, i);
			if (*fmt == 'S')
				*va_arg(ap, int *)=sqlite3_column_bytes(stmt,
							i);
			i++;
			break;
		case 'b':
			*va_arg(ap, const void **)=sqlite3_column_blob(stmt, i);
			*va_arg(ap, int *)=sqlite3_column_bytes(stmt, i++);
			break;
		case 'n':
			*va_arg(ap, int *)=sqlite3_column_bytes(stmt, i++);
			break;
		default:
			pk_log(LOG_ERROR, "Unknown format specifier %c", *fmt);
			break;
		}
	}
	va_end(ap);
}

void query_free(struct query *qry)
{
	struct timeval cur;
	struct timeval diff;
	unsigned ms;
	unsigned bucket;

	if (qry == NULL)
		return;

	gettimeofday(&cur, NULL);
	timersub(&cur, &qry->start, &diff);
	ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;
	/* COMMIT is frequently slow, but we don't learn anything by logging
	   that, and it clutters up the logs */
	if (ms >= SLOW_THRESHOLD_MS && strcmp(qry->sql, "COMMIT"))
		pk_log(LOG_SLOW_QUERY, "Slow query took %u ms: \"%s\"",
					ms, qry->sql);
	pk_log(LOG_QUERY, "Query took %u ms: \"%s\"", ms, qry->sql);

	sqlite3_reset(qry->stmt);
	sqlite3_clear_bindings(qry->stmt);
	bucket=get_bucket(qry->sql);
	/* XXX locking */
	if (prepared[bucket]) {
		destroy_query(prepared[bucket]);
		state.sql_replacements++;
	}
	prepared[bucket]=qry;
}

void sql_init(void)
{
	pk_log(LOG_INFO, "Using SQLite %s", sqlite3_version);
	if (strcmp(SQLITE_VERSION, sqlite3_version))
		pk_log(LOG_INFO, "Warning: built against version "
					SQLITE_VERSION);
	srandom(time(NULL));
}

void sql_shutdown(void)
{
	pk_log(LOG_STATS, "Prepared statement cache: %u hits, %u misses, "
	    			"%u replacements", state.sql_hits,
				state.sql_misses, state.sql_replacements);
	pk_log(LOG_STATS, "Busy handler called for %u queries; %u timeouts",
				state.sql_busy_queries,
				state.sql_busy_timeouts);
	pk_log(LOG_STATS, "%u SQL retries; %llu ms spent in backoffs",
				state.sql_retries,
				(unsigned long long) state.sql_wait_usecs
				/ 1000);
}

static int busy_handler(void *db, int count)
{
	long time;

	(void)db;  /* silence warning */
	if (count == 0)
		state.sql_busy_queries++;
	if (count >= 10) {
		state.sql_busy_timeouts++;
		return 0;
	}
	time=random() % (MAX_WAIT_USEC/2);
	state.sql_wait_usecs += time;
	usleep(time);
	return 1;
}

static int progress_handler(void *db)
{
	(void)db;  /* silence warning */
	return pending_signal();
}

static pk_err_t sql_setup_db(sqlite3 *db, const char *name)
{
	gchar *str;

	/* SQLite won't let us use a prepared statement parameter for the
	   database name. */
	str = g_strdup_printf("PRAGMA %s.synchronous = OFF", name);
again:
	if (query(NULL, db, str, NULL)) {
		if (query_retry())
			goto again;
		g_free(str);
		pk_log_sqlerr("Couldn't set synchronous pragma for "
					"%s database", name);
		return PK_CALLFAIL;
	}
	g_free(str);
	return PK_SUCCESS;
}

pk_err_t sql_conn_open(const char *path, sqlite3 **handle)
{
	sqlite3 *db;
	pk_err_t ret;

	*handle = NULL;
	if (sqlite3_open(path, &db)) {
		pk_log(LOG_ERROR, "Couldn't open database %s: %s",
					path, sqlite3_errmsg(db));
		return PK_IOERR;
	}
	if (sqlite3_extended_result_codes(db, 1)) {
		pk_log(LOG_ERROR, "Couldn't enable extended result codes "
					"for database %s", path);
		sqlite3_close(db);
		return PK_CALLFAIL;
	}
	if (sqlite3_busy_handler(db, busy_handler, db)) {
		pk_log(LOG_ERROR, "Couldn't set busy handler for database %s",
					path);
		sqlite3_close(db);
		return PK_CALLFAIL;
	}
	/* Every so often during long-running queries, check to see if a
	   signal is pending */
	sqlite3_progress_handler(db, PROGRESS_HANDLER_INTERVAL,
				progress_handler, db);
again:
	if (query(NULL, db, "PRAGMA count_changes = TRUE", NULL)) {
		if (query_retry())
			goto again;
		pk_log_sqlerr("Couldn't enable count_changes for %s", path);
		sqlite3_close(db);
		return PK_CALLFAIL;
	}
	ret = sql_setup_db(db, "main");
	if (ret) {
		sqlite3_close(db);
		return ret;
	}
	*handle = db;
	return PK_SUCCESS;
}

void sql_conn_close(sqlite3 *db)
{
	int i;

	/* XXX locking */
	for (i=0; i<CACHE_BUCKETS; i++) {
		if (prepared[i]) {
			destroy_query(prepared[i]);
			prepared[i]=NULL;
		}
	}
	if (db != NULL)
		if (sqlite3_close(db))
			pk_log(LOG_ERROR, "Couldn't close database: %s",
						sqlite3_errmsg(db));
}

/* This should not be called inside a transaction, since the whole point of
   sleeping is to do it without locks held */
int query_retry(void)
{
	long time;

	if (query_busy()) {
		/* The SQLite busy handler is not called when SQLITE_BUSY
		   results from a failed attempt to promote a shared
		   lock to reserved.  So we can't just retry after getting
		   SQLITE_BUSY; we have to back off first. */
		time=random() % MAX_WAIT_USEC;
		state.sql_wait_usecs += time;
		usleep(time);
		state.sql_retries++;
		return 1;
	}
	return 0;
}

pk_err_t attach(sqlite3 *db, const char *handle, const char *file)
{
	pk_err_t ret;

again:
	if (query(NULL, db, "ATTACH ? AS ?", "ss", file, handle)) {
		if (query_retry())
			goto again;
		pk_log_sqlerr("Couldn't attach %s", file);
		return PK_IOERR;
	}
	ret=sql_setup_db(db, handle);
	if (ret) {
again_detach:
		if (query(NULL, db, "DETACH ?", "s", handle)) {
			if (query_retry())
				goto again_detach;
			pk_log_sqlerr("Couldn't detach %s", handle);
		}
		return ret;
	}
	return PK_SUCCESS;
}

pk_err_t _begin(sqlite3 *db, const char *caller, int immediate)
{
again:
	if (query(NULL, db, immediate ? "BEGIN IMMEDIATE" : "BEGIN", NULL)) {
		if (query_busy())
			goto again;
		pk_log_sqlerr("Couldn't begin transaction on behalf of %s()",
					caller);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

pk_err_t _commit(sqlite3 *db, const char *caller)
{
again:
	if (query(NULL, db, "COMMIT", NULL)) {
		if (query_busy())
			goto again;
		pk_log_sqlerr("Couldn't commit transaction on behalf of %s()",
					caller);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

pk_err_t _rollback(sqlite3 *db, const char *caller)
{
	int saved=result;
	pk_err_t ret=PK_SUCCESS;

again:
	/* Several SQLite errors *sometimes* result in an automatic rollback.
	   Always try to roll back, just to be safe, but don't report an error
	   if no transaction is active afterward, even if the rollback claimed
	   to fail. */
	if (query(NULL, db, "ROLLBACK", NULL) && !sqlite3_get_autocommit(db)) {
		if (query_busy())
			goto again;
		pk_log_sqlerr("Couldn't roll back transaction on behalf of "
					"%s()", caller);
		ret=PK_IOERR;
	}
	result=saved;
	return ret;
}

pk_err_t vacuum(sqlite3 *db)
{
	pk_err_t ret;

again_vacuum:
	ret=query(NULL, db, "VACUUM", NULL);
	if (ret) {
		pk_log_sqlerr("Couldn't vacuum database");
		if (query_retry())
			goto again_vacuum;
		else
			return ret;
	}

again_trans:
	/* VACUUM flushes the connection's schema cache.  Perform a dummy
	   transaction on the connection to reload the cache; otherwise,
	   the next transaction on the connection would unexpectedly take
	   a lock on all attached databases. */
	ret=begin(db);
	if (ret)
		return ret;
	ret=query(NULL, db, "SELECT * FROM sqlite_master LIMIT 1", NULL);
	if (ret) {
		pk_log_sqlerr("Couldn't query sqlite_master");
		goto bad_trans;
	}
	ret=commit(db);
	if (ret)
		goto bad_trans;

bad_trans:
	rollback(db);
	if (query_retry())
		goto again_trans;
	return ret;
}

/* This validates both the primary and attached databases */
pk_err_t validate_db(sqlite3 *db)
{
	struct query *qry;
	const char *str;
	int res;

again:
	query(&qry, db, "PRAGMA integrity_check(1)", NULL);
	if (query_retry()) {
		goto again;
	} else if (!query_has_row()) {
		pk_log_sqlerr("Couldn't run SQLite integrity check");
		return PK_IOERR;
	}
	query_row(qry, "s", &str);
	res=strcmp(str, "ok");
	query_free(qry);
	if (res) {
		pk_log(LOG_WARNING, "SQLite integrity check failed");
		return PK_BADFORMAT;
	}
	return PK_SUCCESS;
}

pk_err_t cleanup_action(sqlite3 *db, const char *sql, enum pk_log_type logtype,
			const char *desc)
{
	struct query *qry;
	int changes;

	if (query(&qry, db, sql, NULL)) {
		pk_log_sqlerr("Couldn't clean %s", desc);
		return PK_IOERR;
	}
	query_row(qry, "d", &changes);
	query_free(qry);
	if (changes > 0)
		pk_log(logtype, "Cleaned %d %s", changes, desc);
	return PK_SUCCESS;
}
