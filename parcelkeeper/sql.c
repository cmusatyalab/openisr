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

	if (result != NULL)
		*result=NULL;
	ret=sqlite3_prepare(db, query, -1, &stmt, NULL);
	if (ret)
		return ret;
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
			ret=sqlite3_bind_blob(stmt, i++, va_arg(ap, void *),
						va_arg(ap, int), *fmt == 'b'
						? SQLITE_TRANSIENT
						: SQLITE_STATIC);
			break;
		default:
			pk_log(LOG_ERROR, "Unknown format specifier %c",
						*fmt);
			ret=SQLITE_MISUSE;
			/* XXX sqlite3_errmsg() will return "not an error" */
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
	if ((ret != SQLITE_OK && ret != SQLITE_ROW) || result == NULL)
		query_free(stmt);  /* XXX may clobber errstring */
	else
		*result=stmt;
	return ret;
}
