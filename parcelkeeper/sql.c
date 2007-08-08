/*
 * Parcelkeeper - support daemon for the OpenISR (TM) system virtual disk
 *
 * Copyright (C) 2006-2007 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <stdarg.h>
#include <sqlite3.h>
#include "defs.h"

static void sqlerr(sqlite3 *db)
{
	pk_log(LOG_ERROR, "SQL error: %s", sqlite3_errmsg(db));
}

void query_free(sqlite3_stmt *stmt)
{
	if (stmt == NULL)
		return;
	sqlite3_finalize(stmt);
}

int query(sqlite3_stmt **result, sqlite3 *db, char *query, char *fmt, ...)
{
	sqlite3_stmt *stmt;
	va_list ap;
	int i=1;
	int ret;
	int found_unknown=0;
	void *blob;

	if (result != NULL)
		*result=NULL;
	ret=sqlite3_prepare(db, query, -1, &stmt, NULL);
	if (ret) {
		sqlerr(db);
		return ret;
	}
	va_start(ap, fmt);
	for (; fmt != NULL && *fmt; fmt++) {
		switch (*fmt) {
		case 'd':
			ret=sqlite3_bind_int(stmt, i++, va_arg(ap, int));
			break;
		case 'f':
			ret=sqlite3_bind_double(stmt, i++, va_arg(ap, double));
			break;
		case 's':
		case 'S':
			ret=sqlite3_bind_text(stmt, i++, va_arg(ap, char *),
						-1, *fmt == 's'
						? SQLITE_TRANSIENT
						: SQLITE_STATIC);
			break;
		case 'b':
		case 'B':
			blob=va_arg(ap, void *);
			ret=sqlite3_bind_blob(stmt, i++, blob, va_arg(ap, int),
						*fmt == 'b' ? SQLITE_TRANSIENT
						: SQLITE_STATIC);
			break;
		default:
			pk_log(LOG_ERROR, "Unknown format specifier %c", *fmt);
			ret=SQLITE_MISUSE;
			/* Don't call sqlerr(), since we synthesized this
			   error */
			found_unknown=1;
			break;
		}
		if (ret)
			break;
	}
	va_end(ap);
	if (ret == SQLITE_OK)
		ret=sqlite3_step(stmt);
	/* Collapse DONE into OK, since we don't want everyone to have to test
	   for a gratuitously nonzero error code */
	if (ret == SQLITE_DONE)
		ret=SQLITE_OK;
	if (ret != SQLITE_OK && ret != SQLITE_ROW && !found_unknown)
		sqlerr(db);
	if ((ret != SQLITE_OK && ret != SQLITE_ROW) || result == NULL)
		query_free(stmt);
	else
		*result=stmt;
	return ret;
}

int query_next(sqlite3_stmt *stmt)
{
	int ret;

	ret=sqlite3_step(stmt);
	if (ret == SQLITE_DONE)
		ret=SQLITE_OK;
	if (ret != SQLITE_OK && ret != SQLITE_ROW)
		sqlerr(sqlite3_db_handle(stmt));
	return ret;
}

void query_row(sqlite3_stmt *stmt, char *fmt, ...)
{
	va_list ap;
	int i=0;

	va_start(ap, fmt);
	for (; *fmt; fmt++) {
		switch (*fmt) {
		case 'd':
			*va_arg(ap, int *)=sqlite3_column_int(stmt, i++);
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
		default:
			pk_log(LOG_ERROR, "Unknown format specifier %c", *fmt);
			break;
		}
	}
	va_end(ap);
}

pk_err_t attach(sqlite3 *db, const char *handle, const char *file)
{
	if (query(NULL, db, "ATTACH ? AS ?", "ss", file, handle)) {
		pk_log(LOG_ERROR, "Couldn't attach %s", file);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}
