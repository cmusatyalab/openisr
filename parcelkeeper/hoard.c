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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "defs.h"

#define HOARD_INDEX_VERSION 1

static pk_err_t create_hoard_index(void)
{
	/* XXX auto_vacuum */
	if (query(NULL, state.db, "PRAGMA hoard.user_version = "
				stringify(HOARD_INDEX_VERSION), NULL)) {
		pk_log(LOG_ERROR, "Couldn't set schema version");
		return PK_IOERR;
	}

	if (query(NULL, state.db, "CREATE TABLE hoard.parcels ("
				"parcel INTEGER PRIMARY KEY NOT NULL, "
				"uuid TEXT UNIQUE NOT NULL, "
				"server TEXT NOT NULL, "
				"user TEXT NOT NULL, "
				"name TEXT NOT NULL)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create parcel table");
		return PK_IOERR;
	}

	if (query(NULL, state.db, "CREATE TABLE hoard.chunks ("
				"tag BLOB PRIMARY KEY, "
				"offset INTEGER UNIQUE NOT NULL, "
				"length INTEGER,"
				"last_accessed INTEGER)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create chunk table");
		return PK_IOERR;
	}
	if (query(NULL, state.db, "CREATE INDEX hoard.chunks_lru ON "
				"chunks (last_accessed)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create chunk LRU index");
		return PK_IOERR;
	}

	if (query(NULL, state.db, "CREATE TABLE hoard.refs ("
				"parcel INTEGER NOT NULL, "
				"tag BLOB NOT NULL)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create reference table");
		return PK_IOERR;
	}
	if (query(NULL, state.db, "CREATE UNIQUE INDEX hoard.refs_constraint "
				"ON refs (parcel, tag)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create chunk LRU index");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

static pk_err_t get_parcel_ident(void)
{
	sqlite3_stmt *stmt;
	pk_err_t ret;
	int sret;

	ret=begin(state.db);
	if (ret)
		return ret;
	while ((sret=query(&stmt, state.db, "SELECT parcel FROM hoard.parcels "
				"WHERE uuid == ?", "S", state.uuid))
				== SQLITE_OK) {
		query_free(stmt);
		if (query(NULL, state.db, "INSERT INTO hoard.parcels "
					"(uuid, server, user, name) "
					"VALUES (?, ?, ?, ?)", "SSSS",
					state.uuid, state.server, config.user,
					config.parcel)) {
			pk_log(LOG_ERROR, "Couldn't insert parcel record");
			ret=PK_IOERR;
			goto bad;
		}
	}
	if (sret != SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query hoard.parcels");
		ret=PK_IOERR;
		goto bad;
	}
	query_row(stmt, "d", &state.hoard_ident);
	query_free(stmt);
	ret=commit(state.db);
	if (ret)
		goto bad;
	return PK_SUCCESS;

bad:
	rollback(state.db);
	return ret;
}

pk_err_t hoard_init(void)
{
	sqlite3_stmt *stmt;
	int ver;
	pk_err_t ret;

	if (config.hoard_index == NULL)
		return PK_INVALID;
	if (!is_dir(config.hoard_dir) && mkdir(config.hoard_dir, 0777)) {
		pk_log(LOG_ERROR, "Couldn't create hoard directory %s",
					config.hoard_dir);
		return PK_CALLFAIL;
	}
	ret=attach(state.db, "hoard", config.hoard_index);
	if (ret)
		return ret;
	ret=begin(state.db);
	if (ret)
		return ret;
	if (query(&stmt, state.db, "PRAGMA hoard.user_version", NULL) !=
				SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't get hoard cache index version");
		ret=PK_IOERR;
		goto bad;
	}
	query_row(stmt, "d", &ver);
	query_free(stmt);
	switch (ver) {
	case 0:
		ret=create_hoard_index();
		if (ret)
			goto bad;
		break;
	case HOARD_INDEX_VERSION:
		break;
	default:
		pk_log(LOG_ERROR, "Unknown hoard cache version %d", ver);
		ret=PK_BADFORMAT;
		goto bad;
	}
	ret=commit(state.db);
	if (ret)
		goto bad;
	ret=get_parcel_ident();
	if (ret)
		return ret;
	state.hoard_fd=open(config.hoard_file, O_RDWR|O_CREAT, 0666);
	if (state.hoard_fd == -1) {
		pk_log(LOG_ERROR, "Couldn't open %s", config.hoard_file);
		return PK_IOERR;
	}
	return PK_SUCCESS;

bad:
	rollback(state.db);
	return ret;
}

void hoard_shutdown(void)
{
	close(state.hoard_fd);
}
