/*
 * libisrsql - Wrapper code around a private version of SQLite
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

#ifndef ISR_SQL_H
#define ISR_SQL_H

/* Log domain:
 *	isrsql
 * Error levels:
 *	G_LOG_LEVEL_CRITICAL		- Programmer errors
 *	G_LOG_LEVEL_MESSAGE		- Ordinary errors
 *	G_LOG_LEVEL_INFO		- Statistics
 *	SQL_LOG_LEVEL_QUERY		- Query strings
 *	SQL_LOG_LEVEL_SLOW_QUERY	- Slow-query warnings
 */
enum sql_log_level {
	SQL_LOG_LEVEL_QUERY		= 1 << G_LOG_LEVEL_USER_SHIFT,
	SQL_LOG_LEVEL_SLOW_QUERY	= 1 << (G_LOG_LEVEL_USER_SHIFT + 1),
};

struct db;
struct query;

void sql_init(void);
gboolean sql_conn_open(const char *path, struct db **handle);
void sql_conn_close(struct db *db);
gboolean query(struct query **new_qry, struct db *db, const char *query,
			const char *fmt, ...);
gboolean query_next(struct query *qry);
gboolean query_has_row(struct db *db);
gboolean query_ok(struct db *db);
gboolean query_busy(struct db *db);
gboolean query_constrained(struct db *db);
void query_row(struct query *qry, const char *fmt, ...);
void query_free(struct query *qry);
void query_backoff(struct db *db);
void sql_log_err(struct db *db, const char *fmt, ...);
gboolean attach(struct db *db, const char *handle, const char *file);
gboolean _begin(struct db *db, gboolean immediate);
#define begin(db) _begin(db, FALSE)
#define begin_immediate(db) _begin(db, TRUE)
gboolean commit(struct db *db);
gboolean rollback(struct db *db);
gboolean vacuum(struct db *db);
gboolean validate_db(struct db *db);

#endif
