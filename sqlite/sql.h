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

/* glib log domain:
 *	isrsql
 * Log levels:
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

/* Initialize the library. */
void sql_init(void);

/* Open and return a database connection to the given database file, which
   need not exist.  Returns FALSE on error. */
gboolean sql_conn_open(const char *path, struct db **handle);

/* Close the given database connection. */
void sql_conn_close(struct db *db);

/* Start the SQL query @query against the given @db.  @fmt is a string
   containing individual characters representing the types of the positional
   parameters:
	d - int
	D - int64_t
	f - double
	s - string (to be copied into the query structure)
	S - string (not copied; must be constant until *new_qry is freed)
	b - blob (copied into the query) - void * (data) + int (length)
	B - blob (not copied) - void * (data) + int (length)
   fmt may be NULL if there are no positional parameters.  new_qry may be
   NULL, even if the query is a SELECT.  This will set the status flags
   queried by query_has_row(), etc., without returning a query structure.
   This function returns TRUE on success (whether or not the query returned
   any rows), FALSE otherwise. */
gboolean query(struct query **new_qry, struct db *db, const char *query,
			const char *fmt, ...);

/* Step to the next row of results.  Returns TRUE on success (whether or not
   there are any more rows), FALSE otherwise. */
gboolean query_next(struct query *qry);

/* Returns TRUE if the last database operation caused a row to be returned,
   FALSE otherwise.  Note that INSERT/UPDATE/DELETE statements return a row
   with a single column giving the number of rows that were modified. */
gboolean query_has_row(struct db *db);

/* Returns TRUE if the last database operation succeeded WITHOUT returning a
   row, FALSE otherwise.  Note that INSERT/UPDATE/DELETE statements return
   a row with a single column giving the number of rows that were modified. */
gboolean query_ok(struct db *db);

/* Returns TRUE if the last database operation failed because of contention
   for the database file (such that rolling back and retrying the transaction
   might succeed), FALSE otherwise. */
gboolean query_busy(struct db *db);

/* Returns TRUE if the last database operation failed due to a constraint
   violation, FALSE otherwise. */
gboolean query_constrained(struct db *db);

/* Fetch the current row of data from the query.  @fmt is a string containing
   individual characters representing the data types of the positional
   parameters, which are pointers to values to be filled in with the contents
   of each column in turn.  The column contents will be coerced to the
   requested type if possible.  The available types are:
	d - int *
	D - int64_t *
	f - double *
	s - const unsigned char **
	S - const unsigned char ** (string) + int * (length)
	b - const void ** (data) + int * (length)
	n - int * (blob length)
   Returned pointer values are valid until the next row is accessed. */
void query_row(struct query *qry, const char *fmt, ...);

/* Free an allocated query.  All queries must be freed before ending a
   transaction. */
void query_free(struct query *qry);

/* Sleeps for a random interval in order to do backoff on @db after
   query_busy() returns TRUE.  A typical transaction looks like this:

	gboolean retry;

again:
	if (begin(db))
		return FALSE;
	if (!query(...)) {
		sql_log_err(db, "Couldn't frob the database");
		goto bad;
	}
	...
	if (commit(db))
		goto bad;
	return TRUE;

bad:
	retry = query_busy(db);
	rollback(db);
	if (retry) {
		query_backoff(db);
		goto again;
	}
	return FALSE;
  */
void query_backoff(struct db *db);

/* Set the interrupt flag on @db.  When the flag is set, query operations will
   eventually fail (but may not fail immediately or every time).  This
   function is signal-handler- and thread-safe. */
void query_interrupt(struct db *db);

/* Clear the interrupt flag on @db.  This function is signal-handler- and
   thread-safe. */
void query_clear_interrupt(struct db *db);

/* Log the most recent SQL error on @db, including the SQLite error code and
   error detail string.  The message will be logged at level
   G_LOG_LEVEL_MESSAGE.  No message will be logged if the error is retryable
   (i.e. query_busy() would return TRUE) or if it occurred as a result of
   query_interrupt(); this is a feature intended to prevent spurious log
   messages in correctible failure cases. */
void sql_log_err(struct db *db, const char *fmt, ...);

/* Attach an additional database @file (which need not exist) to the @db
   handle, giving it the shortname @handle.  Return TRUE on success, FALSE
   otherwise.  This function performs query_busy() and query_backoff()
   internally. */
gboolean attach(struct db *db, const char *handle, const char *file);

/* Begin a transaction against @db.  All queries must be done in the context
   of a transaction opened in the same thread.  If another thread already has
   a transaction open, _begin() will block until it is committed or rolled
   back.  Returns FALSE on error.  This function performs query_busy() and
   query_backoff() internally. */
gboolean _begin(struct db *db, gboolean immediate);
#define begin(db) _begin(db, FALSE)
#define begin_immediate(db) _begin(db, TRUE)

/* Commit the open transaction against @db.  All queries must have been freed.
   Returns FALSE on error.  This function performs query_busy() and
   query_backoff() internally. */
gboolean commit(struct db *db);

/* Roll back the open transaction on @db.  All queries must have been freed.
   Returns FALSE on error.  This function performs query_busy() and
   query_backoff() internally. */
gboolean rollback(struct db *db);

/* Reorganize the tables of @db for faster access.  Must be performed outside
   a transaction.  Returns FALSE on error.  This function performs
   query_busy() and query_backoff() internally. */
gboolean vacuum(struct db *db);

/* Perform an internal consistency check on the main and attached databases
   of @db.  Must be performed outside a transaction.  Returns FALSE if the
   consistency check fails, or on other error.  This function performs
   query_busy() and query_backoff() internally. */
gboolean validate_db(struct db *db);

#endif
