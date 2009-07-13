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
#include <sqlite3.h>
#include "defs.h"

#define SLOW_THRESHOLD_MS 200
#define MAX_WAIT_USEC 10000
#define PROGRESS_HANDLER_INTERVAL 100000

struct db {
	pthread_mutex_t lock;
	pthread_t holder;
	sqlite3 *conn;
	unsigned queries;
	int result;  /* set by query() and query_next() */
	gchar *file;
	gchar *errmsg;

	/* Statistics */
	unsigned busy_queries;
	unsigned busy_timeouts;
	unsigned retries;
	uint64_t wait_usecs;
};

struct query {
	struct db *db;
	sqlite3_stmt *stmt;
	const char *sql;
	GTimer *timer;
};

static void sqlerr(struct db *db, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (db->errmsg != NULL)
		g_free(db->errmsg);
	db->errmsg = g_strdup_vprintf(fmt, ap);
	va_end(ap);
}

static void db_get(struct db *db)
{
	pthread_mutex_lock(&db->lock);
	db->holder = pthread_self();
}

static void db_put(struct db *db)
{
	if (db->queries) {
		pk_log(LOG_ERROR, "Leaked %u queries", db->queries);
		db->queries = 0;
	}
	db->holder = (pthread_t) 0;
	pthread_mutex_unlock(&db->lock);
}

static gboolean db_in_trans(struct db *db)
{
	if (!pthread_mutex_trylock(&db->lock)) {
		pthread_mutex_unlock(&db->lock);
		return FALSE;
	}
	if (db->holder != pthread_self())
		return FALSE;
	return TRUE;
}

static void db_assert_trans(struct db *db)
{
	if (!db_in_trans(db))
		pk_log(LOG_ERROR, "Attempt to perform database operation "
					"outside a transaction");
}

static int alloc_query(struct query **new_qry, struct db *db, const char *sql)
{
	struct query *qry;
	int ret;

	qry=g_slice_new(struct query);
	qry->db=db;
	ret=sqlite3_prepare_v2(db->conn, sql, -1, &qry->stmt, NULL);
	if (ret) {
		sqlerr(db, "%s", sqlite3_errmsg(db->conn));
		g_slice_free(struct query, qry);
	} else {
		qry->sql=sqlite3_sql(qry->stmt);
		qry->timer=g_timer_new();
		db->queries++;
		*new_qry=qry;
	}
	return ret;
}

gboolean query(struct query **new_qry, struct db *db, const char *query,
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
	if (!db_in_trans(db)) {
		db->result=SQLITE_MISUSE;
		sqlerr(db, "Attempt to perform database operation outside "
					"a transaction");
		return FALSE;
	}
	db->result=alloc_query(&qry, db, query);
	if (db->result)
		return FALSE;
	stmt=qry->stmt;
	va_start(ap, fmt);
	for (; fmt != NULL && *fmt; fmt++) {
		switch (*fmt) {
		case 'd':
			db->result=sqlite3_bind_int(stmt, i++, va_arg(ap,
						int));
			break;
		case 'D':
			db->result=sqlite3_bind_int64(stmt, i++, va_arg(ap,
						int64_t));
			break;
		case 'f':
			db->result=sqlite3_bind_double(stmt, i++, va_arg(ap,
						double));
			break;
		case 's':
		case 'S':
			db->result=sqlite3_bind_text(stmt, i++, va_arg(ap,
						char *), -1, *fmt == 's'
						? SQLITE_TRANSIENT
						: SQLITE_STATIC);
			break;
		case 'b':
		case 'B':
			blob=va_arg(ap, void *);
			db->result=sqlite3_bind_blob(stmt, i++, blob,
						va_arg(ap, int), *fmt == 'b'
						? SQLITE_TRANSIENT
						: SQLITE_STATIC);
			break;
		default:
			sqlerr(db, "Unknown format specifier %c", *fmt);
			db->result=SQLITE_MISUSE;
			found_unknown=1;
			break;
		}
		if (db->result)
			break;
	}
	va_end(ap);
	if (db->result == SQLITE_OK)
		query_next(qry);
	else if (!found_unknown)
		sqlerr(db, "%s", sqlite3_errmsg(db->conn));
	if (db->result != SQLITE_ROW || new_qry == NULL)
		query_free(qry);
	else
		*new_qry=qry;
	if (db->result == SQLITE_OK || db->result == SQLITE_ROW)
		return TRUE;
	else
		return FALSE;
}

gboolean query_next(struct query *qry)
{
	int result;

	if (pending_signal()) {
		/* Try to stop the query.  If this succeeds, the transaction
		   will be automatically rolled back.  Often, though, the
		   attempt will not succeed. */
		sqlite3_interrupt(qry->db->conn);
	}
	result=sqlite3_step(qry->stmt);
	/* Collapse DONE into OK, since they're semantically equivalent and
	   it simplifies error checking */
	if (result == SQLITE_DONE)
		result=SQLITE_OK;
	/* Collapse IOERR_BLOCKED into BUSY, likewise */
	if (result == SQLITE_IOERR_BLOCKED)
		result=SQLITE_BUSY;
	qry->db->result=result;
	if (result == SQLITE_OK || result == SQLITE_ROW) {
		return TRUE;
	} else {
		sqlerr(qry->db, "%s", sqlite3_errmsg(qry->db->conn));
		return FALSE;
	}
}

gboolean query_has_row(struct db *db)
{
	db_assert_trans(db);
	return (db->result == SQLITE_ROW);
}

gboolean query_ok(struct db *db)
{
	db_assert_trans(db);
	return (db->result == SQLITE_OK);
}

gboolean query_busy(struct db *db)
{
	db_assert_trans(db);
	return (db->result == SQLITE_BUSY);
}

gboolean query_constrained(struct db *db)
{
	db_assert_trans(db);
	return (db->result == SQLITE_CONSTRAINT);
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
	unsigned ms;

	if (qry == NULL)
		return;

	ms = g_timer_elapsed(qry->timer, NULL) * 1000;
	/* COMMIT is frequently slow, but we don't learn anything by logging
	   that, and it clutters up the logs */
	if (ms >= SLOW_THRESHOLD_MS && strcmp(qry->sql, "COMMIT"))
		pk_log(LOG_SLOW_QUERY, "Slow query took %u ms: \"%s\"",
					ms, qry->sql);
	pk_log(LOG_QUERY, "Query took %u ms: \"%s\"", ms, qry->sql);

	g_timer_destroy(qry->timer);
	sqlite3_finalize(qry->stmt);
	qry->db->queries--;
	g_slice_free(struct query, qry);
}

void pk_log_sqlerr(struct db *db, const char *fmt, ...)
{
	gchar *str;
	va_list ap;

	db_assert_trans(db);
	if (db->result != SQLITE_BUSY && db->result != SQLITE_INTERRUPT) {
		va_start(ap, fmt);
		str = g_strdup_vprintf(fmt, ap);
		va_end(ap);
		if (db->result != SQLITE_ROW && db->result != SQLITE_OK)
			pk_log(LOG_WARNING, "%s (%d, %s)", str, db->result,
						db->errmsg);
		else
			pk_log(LOG_WARNING, "%s", str);
		g_free(str);
	}
}

void sql_init(void)
{
	pk_log(LOG_INFO, "Using SQLite %s", sqlite3_version);
	if (strcmp(SQLITE_VERSION, sqlite3_version))
		pk_log(LOG_INFO, "Warning: built against version "
					SQLITE_VERSION);
	srandom(time(NULL));
}

static int busy_handler(void *data, int count)
{
	struct db *db = data;
	long time;

	if (count == 0)
		db->busy_queries++;
	if (count >= 10) {
		db->busy_timeouts++;
		return 0;
	}
	time=random() % (MAX_WAIT_USEC/2);
	db->wait_usecs += time;
	usleep(time);
	return 1;
}

static int progress_handler(void *db)
{
	(void)db;  /* silence warning */
	return pending_signal();
}

static gboolean sql_setup_db(struct db *db, const char *name)
{
	gchar *str;

	/* SQLite won't let us use a prepared statement parameter for the
	   database name. */
	str = g_strdup_printf("PRAGMA %s.synchronous = OFF", name);
again:
	if (!query(NULL, db, str, NULL)) {
		if (query_busy(db)) {
			query_backoff(db);
			goto again;
		}
		g_free(str);
		pk_log_sqlerr(db, "Couldn't set synchronous pragma for "
					"%s database", name);
		return FALSE;
	}
	g_free(str);
	return TRUE;
}

gboolean sql_conn_open(const char *path, struct db **handle)
{
	struct db *db;

	*handle = NULL;
	db = g_slice_new0(struct db);
	pthread_mutex_init(&db->lock, NULL);
	db_get(db);
	if (sqlite3_open(path, &db->conn)) {
		pk_log(LOG_ERROR, "Couldn't open database %s: %s",
					path, sqlite3_errmsg(db->conn));
		db_put(db);
		pthread_mutex_destroy(&db->lock);
		g_slice_free(struct db, db);
		return FALSE;
	}
	db->file = g_strdup(path);
	if (sqlite3_extended_result_codes(db->conn, 1)) {
		pk_log(LOG_ERROR, "Couldn't enable extended result codes "
					"for database %s", path);
		goto bad;
	}
	if (sqlite3_busy_handler(db->conn, busy_handler, db)) {
		pk_log(LOG_ERROR, "Couldn't set busy handler for database %s",
					path);
		goto bad;
	}
	/* Every so often during long-running queries, check to see if a
	   signal is pending */
	sqlite3_progress_handler(db->conn, PROGRESS_HANDLER_INTERVAL,
				progress_handler, db);
again:
	if (!query(NULL, db, "PRAGMA count_changes = TRUE", NULL)) {
		if (query_busy(db)) {
			query_backoff(db);
			goto again;
		}
		pk_log_sqlerr(db, "Couldn't enable count_changes for %s", path);
		goto bad;
	}
	if (!sql_setup_db(db, "main"))
		goto bad;
	db_put(db);
	*handle = db;
	return TRUE;

bad:
	sqlite3_close(db->conn);
	g_free(db->file);
	db_put(db);
	pthread_mutex_destroy(&db->lock);
	g_slice_free(struct db, db);
	return FALSE;
}

void sql_conn_close(struct db *db)
{
	if (db == NULL)
		return;
	if (sqlite3_close(db->conn))
		pk_log(LOG_ERROR, "Couldn't close database: %s",
					sqlite3_errmsg(db->conn));
	pthread_mutex_destroy(&db->lock);
	g_free(db->errmsg);
	pk_log(LOG_STATS, "%s: Busy handler called for %u queries; %u timeouts",
				db->file, db->busy_queries, db->busy_timeouts);
	pk_log(LOG_STATS, "%s: %u SQL retries; %llu ms spent in backoffs",
				db->file, db->retries,
				(unsigned long long) db->wait_usecs / 1000);
	g_free(db->file);
	g_slice_free(struct db, db);
}

/* This should not be called inside a transaction, since the whole point of
   sleeping is to do it without locks held */
void query_backoff(struct db *db)
{
	long time;

	/* The SQLite busy handler is not called when SQLITE_BUSY results
	   from a failed attempt to promote a shared lock to reserved.  So
	   we can't just retry after getting SQLITE_BUSY; we have to back
	   off first. */
	time=random() % MAX_WAIT_USEC;
	db->wait_usecs += time;
	usleep(time);
	db->retries++;
}

gboolean attach(struct db *db, const char *handle, const char *file)
{
	gboolean ret = TRUE;

	db_get(db);
again:
	if (!query(NULL, db, "ATTACH ? AS ?", "ss", file, handle)) {
		if (query_busy(db)) {
			query_backoff(db);
			goto again;
		}
		pk_log_sqlerr(db, "Couldn't attach %s", file);
		ret = FALSE;
		goto out;
	}
	if (!sql_setup_db(db, handle)) {
		ret = FALSE;
again_detach:
		if (!query(NULL, db, "DETACH ?", "s", handle)) {
			if (query_busy(db)) {
				query_backoff(db);
				goto again_detach;
			}
			pk_log_sqlerr(db, "Couldn't detach %s", handle);
		}
	}
out:
	db_put(db);
	return ret;
}

gboolean _begin(struct db *db, gboolean immediate)
{
	db_get(db);
again:
	if (!query(NULL, db, immediate ? "BEGIN IMMEDIATE" : "BEGIN", NULL)) {
		if (query_busy(db))
			goto again;
		pk_log_sqlerr(db, "Couldn't begin transaction");
		db_put(db);
		return FALSE;
	}
	return TRUE;
}

gboolean commit(struct db *db)
{
again:
	if (!query(NULL, db, "COMMIT", NULL)) {
		if (query_busy(db))
			goto again;
		pk_log_sqlerr(db, "Couldn't commit transaction");
		return FALSE;
	}
	db_put(db);
	return TRUE;
}

gboolean rollback(struct db *db)
{
again:
	/* Several SQLite errors *sometimes* result in an automatic rollback.
	   Always try to roll back, just to be safe, but don't report an error
	   if no transaction is active afterward, even if the rollback claimed
	   to fail. */
	if (!query(NULL, db, "ROLLBACK", NULL) &&
				!sqlite3_get_autocommit(db->conn)) {
		if (query_busy(db))
			goto again;
		pk_log_sqlerr(db, "Couldn't roll back transaction");
		return FALSE;
	} else {
		db_put(db);
		return TRUE;
	}
}

gboolean vacuum(struct db *db)
{
	gboolean retry;

	db_get(db);
again_vacuum:
	if (!query(NULL, db, "VACUUM", NULL)) {
		pk_log_sqlerr(db, "Couldn't vacuum database");
		if (query_busy(db)) {
			query_backoff(db);
			goto again_vacuum;
		} else {
			db_put(db);
			return FALSE;
		}
	}
	db_put(db);

again_trans:
	/* VACUUM flushes the connection's schema cache.  Perform a dummy
	   transaction on the connection to reload the cache; otherwise,
	   the next transaction on the connection would unexpectedly take
	   a lock on all attached databases. */
	if (!begin(db))
		return FALSE;
	if (!query(NULL, db, "SELECT * FROM sqlite_master LIMIT 1", NULL)) {
		pk_log_sqlerr(db, "Couldn't query sqlite_master");
		goto bad_trans;
	}
	if (!commit(db))
		goto bad_trans;
	return TRUE;

bad_trans:
	retry = query_busy(db);
	rollback(db);
	if (retry) {
		query_backoff(db);
		goto again_trans;
	}
	return FALSE;
}

/* This validates both the primary and attached databases */
gboolean validate_db(struct db *db)
{
	struct query *qry;
	const char *str;
	int res;

	db_get(db);
again:
	query(&qry, db, "PRAGMA integrity_check(1)", NULL);
	if (query_busy(db)) {
		query_backoff(db);
		goto again;
	} else if (!query_has_row(db)) {
		pk_log_sqlerr(db, "Couldn't run SQLite integrity check");
		db_put(db);
		return FALSE;
	}
	query_row(qry, "s", &str);
	res=strcmp(str, "ok");
	query_free(qry);
	db_put(db);
	if (res) {
		pk_log(LOG_WARNING, "SQLite integrity check failed");
		return FALSE;
	}
	return TRUE;
}
