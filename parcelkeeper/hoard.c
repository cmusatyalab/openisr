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
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include "defs.h"

#define HOARD_INDEX_VERSION 4
#define EXPAND_CHUNKS 64

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
				"tag BLOB UNIQUE, "
				/* 512-byte sectors */
				"offset INTEGER UNIQUE NOT NULL, "
				"length INTEGER NOT NULL DEFAULT 0,"
				"last_access INTEGER NOT NULL DEFAULT 0,"
				"referenced INTEGER NOT NULL DEFAULT 0)",
				NULL)) {
		pk_log(LOG_ERROR, "Couldn't create chunk table");
		return PK_IOERR;
	}
	if (query(NULL, state.db, "CREATE INDEX hoard.chunks_lru ON "
				"chunks (last_access)", NULL)) {
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

static int timestamp(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec;
}

/* XXX cache chunks of different sizes */
/* must be within transaction */
static pk_err_t expand_cache(void)
{
	sqlite3_stmt *stmt;
	int count;
	int start;
	int i;
	int step = parcel.chunksize >> 9;

	if (query(&stmt, state.db, "SELECT count(*), max(offset) "
				"FROM hoard.chunks", NULL) != SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't find maximum hoard cache offset");
		return PK_IOERR;
	}
	query_row(stmt, "dd", &count, &start);
	query_free(stmt);
	if (count)
		start += step;
	for (i=0; i<EXPAND_CHUNKS; i++) {
		if (query(NULL, state.db, "INSERT INTO hoard.chunks (offset) "
					"VALUES (?)", "d", start + i * step)) {
			pk_log(LOG_ERROR, "Couldn't expand hoard cache to "
						"offset %d", start + i * step);
			return PK_IOERR;
		}
	}
	return PK_SUCCESS;
}

/* must be within transaction */
static pk_err_t allocate_chunk_offset(int *offset)
{
	sqlite3_stmt *stmt;
	pk_err_t ret;
	int sret;
	int hoarded=0;

	while (1) {
		/* First, try to find an unused hoard cache slot */
		sret=query(&stmt, state.db, "SELECT offset FROM hoard.chunks "
					"WHERE tag ISNULL AND referenced == 0 "
					"LIMIT 1", NULL);
		if (sret == SQLITE_ROW) {
			query_row(stmt, "d", offset);
			query_free(stmt);
			break;
		} else if (sret != SQLITE_OK) {
			pk_log(LOG_ERROR, "Error finding unused hoard cache "
						"offset");
			return PK_IOERR;
		}
		query_free(stmt);

		/* Next, we may want to try reclaiming an existing,
		   unreferenced chunk.  See if we're permitted to do so. */
		if (config.minsize > 0) {
			sret=query(&stmt, state.db, "SELECT count(tag) "
						"FROM hoard.chunks", NULL);
			if (sret != SQLITE_ROW) {
				query_free(stmt);
				pk_log(LOG_ERROR, "Error finding size of "
							"hoard cache");
				return PK_IOERR;
			}
			query_row(stmt, "d", &hoarded);
			query_free(stmt);
		}

		/* XXX assumes 128 KB */
		if ((unsigned)(hoarded / 8) >= config.minsize) {
			/* Try to reclaim the LRU unreferenced chunk */
			sret=query(&stmt, state.db, "SELECT offset "
					"FROM hoard.chunks WHERE tag NOTNULL "
					"AND referenced == 0 "
					"ORDER BY last_access LIMIT 1", NULL);
			if (sret == SQLITE_ROW) {
				query_row(stmt, "d", offset);
				query_free(stmt);
				break;
			} else if (sret != SQLITE_OK) {
				pk_log(LOG_ERROR, "Error finding reclaimable "
							"hoard cache offset");
				return PK_IOERR;
			}
			query_free(stmt);
		}

		/* Now expand the cache and try again */
		ret=expand_cache();
		if (ret)
			return ret;
	}

	if (query(NULL, state.db, "UPDATE hoard.chunks SET referenced = 1, "
				"tag = NULL, length = 0, last_access = 0 "
				"WHERE offset == ?", "d", *offset)) {
		pk_log(LOG_ERROR, "Couldn't allocate hoard cache chunk");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

static void deallocate_chunk_offset(int offset)
{
	if (query(NULL, state.db, "UPDATE hoard.chunks SET tag = NULL, "
				"length = 0, last_access = 0, referenced = 0 "
				"WHERE offset = ?", "d", offset)) {
		pk_log(LOG_ERROR, "Couldn't deallocate hoard chunk at "
					"offset %d", offset);
	}
}

static pk_err_t add_chunk_reference(const void *tag)
{
	char *ftag;

	if (query(NULL, state.db, "INSERT OR IGNORE INTO hoard.refs "
				"(parcel, tag) VALUES (?, ?)", "db",
				state.hoard_ident, tag, parcel.hashlen)
				!= SQLITE_OK) {
		ftag=format_tag(tag);
		pk_log(LOG_ERROR, "Couldn't add chunk reference for tag %s",
					ftag);
		free(ftag);
		return PK_IOERR;
	}
	if (query(NULL, state.db, "UPDATE hoard.chunks SET referenced = 1 "
				" WHERE tag == ?", "b", tag, parcel.hashlen)) {
		ftag=format_tag(tag);
		pk_log(LOG_ERROR, "Couldn't set referenced flag for tag %s",
					ftag);
		free(ftag);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

pk_err_t hoard_get_chunk(const void *tag, void *buf, unsigned *len)
{
	sqlite3_stmt *stmt;
	int offset;
	int clen;
	pk_err_t ret;
	int sret;

	if (config.hoard_dir == NULL)
		return PK_NOTFOUND;
	ret=begin(state.db);
	if (ret)
		return ret;

	sret=query(&stmt, state.db, "SELECT offset, length FROM hoard.chunks "
				"WHERE tag == ?", "b", tag, parcel.hashlen);
	if (sret == SQLITE_OK) {
		query_free(stmt);
		ret=commit(state.db);
		if (ret)
			goto bad;
		return PK_NOTFOUND;
	} else if (sret != SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't query hoard chunk index");
		ret=PK_IOERR;
		goto bad;
	}
	query_row(stmt, "dd", &offset, &clen);
	query_free(stmt);

	if (query(NULL, state.db, "UPDATE hoard.chunks SET last_access = ? "
				"WHERE tag == ?", "db", timestamp(), tag,
				parcel.hashlen)) {
		/* Not fatal */
		pk_log(LOG_ERROR, "Couldn't update chunk timestamp");
	}
	ret=add_chunk_reference(tag);
	if (ret)
		goto bad;

	ret=commit(state.db);
	if (ret)
		goto bad;

	/* XXX what if the reference is released right now?  we could read in
	   bad chunk data.  do we need to hold a read lock the whole time? */

	if (clen <= 0 || (unsigned)clen > parcel.chunksize)
		/* XXX */;

	if (pread(state.hoard_fd, buf, clen, ((off_t)offset) << 9) != clen) {
		pk_log(LOG_ERROR, "Couldn't read chunk at offset %d", offset);
		/* XXX */
	}

#if 0
	XXX
	if chunk does not match hash {
		warn;
		delete from references where tag == hash;
		update chunks (tag, length) set to (null, null) where
			tag == hash;
		fail;
	}
#endif

	*len=clen;
	return PK_SUCCESS;

bad:
	rollback(state.db);
	return ret;
}

pk_err_t hoard_put_chunk(const void *tag, const void *buf, unsigned len)
{
	pk_err_t ret;
	int offset;
	int sret;

	if (config.hoard_dir == NULL)
		return PK_SUCCESS;
	ret=begin(state.db);
	if (ret)
		return ret;

	sret=query(NULL, state.db, "SELECT tag FROM hoard.chunks WHERE "
				"tag == ?", "b", tag, parcel.hashlen);
	if (sret == SQLITE_ROW) {
		ret=add_chunk_reference(tag);
		if (ret)
			goto bad;
		ret=commit(state.db);
		if (ret)
			goto bad;
		return PK_SUCCESS;
	} else if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't look up tag in hoard cache index");
		goto bad;
	}

	ret=allocate_chunk_offset(&offset);
	if (ret)
		goto bad;

	ret=commit(state.db);
	if (ret)
		goto bad;

	if (pwrite(state.hoard_fd, buf, len, ((off_t)offset) << 9) !=
				(int)len) {
		pk_log(LOG_ERROR, "Couldn't write hoard cache: offset %d, "
					"length %d", offset, len);
		deallocate_chunk_offset(offset);
		return PK_IOERR;
	}

	ret=begin(state.db);
	if (ret) {
		deallocate_chunk_offset(offset);
		return ret;
	}
	sret=query(NULL, state.db, "UPDATE hoard.chunks SET tag = ?, "
				"length = ?, last_access = ? WHERE offset = ?",
				"bddd", tag, parcel.hashlen, len, timestamp(),
				offset);
	if (sret == SQLITE_CONSTRAINT) {
		/* Someone else has already written this tag */
		deallocate_chunk_offset(offset);
	} else if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't commit hoard cache chunk");
		ret=PK_IOERR;
		goto bad_dealloc;
	}
	ret=add_chunk_reference(tag);
	if (ret)
		goto bad_dealloc;
	ret=commit(state.db);
	if (ret) {
		pk_log(LOG_ERROR, "Couldn't commit hoard cache chunk");
		goto bad_dealloc;
	}
	return PK_SUCCESS;

bad:
	rollback(state.db);
	return ret;
bad_dealloc:
	rollback(state.db);
	deallocate_chunk_offset(offset);
	return ret;
}

pk_err_t hoard_sync_refs(int from_cache)
{
	pk_err_t ret;
	int sret;

	ret=begin(state.db);
	if (ret)
		return ret;
	if (from_cache)
		sret=query(NULL, state.db, "CREATE TEMP VIEW newrefs AS "
					"SELECT DISTINCT tag FROM keys", NULL);
	else
		sret=query(NULL, state.db, "CREATE TEMP VIEW newrefs AS "
					"SELECT DISTINCT tag FROM prev.keys",
					NULL);
	ret=PK_IOERR;
	if (sret) {
		pk_log(LOG_ERROR, "Couldn't generate tag list");
		goto bad;
	}
	if (query(NULL, state.db, "UPDATE hoard.chunks SET referenced = 0 "
				"WHERE tag IN "
				"(SELECT tag FROM hoard.refs WHERE parcel == ? "
				"AND tag NOT IN (SELECT tag FROM temp.newrefs) "
				"AND tag NOT IN (SELECT tag FROM hoard.refs "
				"WHERE parcel != ?))", "dd", state.hoard_ident,
				state.hoard_ident)) {
		pk_log(LOG_ERROR, "Couldn't garbage-collect referenced flags");
		goto bad;
	}
	if (query(NULL, state.db, "DELETE FROM hoard.refs WHERE parcel == ? "
				"AND tag NOT IN (SELECT tag FROM temp.newrefs)",
				"d", state.hoard_ident)) {
		pk_log(LOG_ERROR, "Couldn't garbage-collect hoard refs");
		goto bad;
	}
	if (query(NULL, state.db, "INSERT OR IGNORE INTO hoard.refs "
				"(parcel, tag) SELECT ?, tag FROM temp.newrefs "
				"WHERE tag IN (SELECT tag FROM hoard.chunks)",
				"d", state.hoard_ident)) {
		pk_log(LOG_ERROR, "Couldn't insert new hoard refs");
		goto bad;
	}
	if (query(NULL, state.db, "UPDATE hoard.chunks SET referenced = 1 "
				"WHERE tag IN (SELECT tag FROM temp.newrefs)",
				NULL)) {
		pk_log(LOG_ERROR, "Couldn't updated referenced flags");
		goto bad;
	}
	if (query(NULL, state.db, "DROP VIEW temp.newrefs", NULL)) {
		pk_log(LOG_ERROR, "Couldn't drop temporary view");
		goto bad;
	}
	ret=commit(state.db);
	if (ret)
		goto bad;
	return PK_SUCCESS;

bad:
	rollback(state.db);
	return ret;
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
				"WHERE uuid == ?", "S", parcel.uuid))
				== SQLITE_OK) {
		query_free(stmt);
		if (query(NULL, state.db, "INSERT INTO hoard.parcels "
					"(uuid, server, user, name) "
					"VALUES (?, ?, ?, ?)", "SSSS",
					parcel.uuid, parcel.server,
					parcel.user, parcel.parcel)) {
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

/* Releases the hoard_fd lock before returning, including on error */
static pk_err_t hoard_try_cleanup(void)
{
	pk_err_t ret;

	ret=get_file_lock(state.hoard_fd, FILE_LOCK_WRITE);
	if (ret == PK_BUSY) {
		pk_log(LOG_INFO, "Hoard cache in use; skipping cleanup");
		ret=PK_SUCCESS;
		goto out;
	} else if (ret) {
		goto out;
	}

	pk_log(LOG_INFO, "Cleaning up hoard cache...");
	ret=cleanup_action(state.db, "UPDATE hoard.chunks SET referenced = 0 "
				"WHERE referenced == 1 AND tag ISNULL",
				"orphaned cache slots");
	if (ret)
		goto out;
	ret=cleanup_action(state.db, "DELETE FROM hoard.parcels WHERE parcel "
				"NOT IN (SELECT parcel FROM hoard.refs)",
				"dangling parcel records");
out:
	put_file_lock(state.hoard_fd);
	return ret;
}

pk_err_t hoard_init(void)
{
	sqlite3_stmt *stmt;
	int ver;
	pk_err_t ret;

	if (config.hoard_dir == NULL)
		return PK_INVALID;
	if (!is_dir(config.hoard_dir) && mkdir(config.hoard_dir, 0777)) {
		pk_log(LOG_ERROR, "Couldn't create hoard directory %s",
					config.hoard_dir);
		return PK_CALLFAIL;
	}

	state.hoard_fd=open(config.hoard_file, O_RDWR|O_CREAT, 0666);
	if (state.hoard_fd == -1) {
		pk_log(LOG_ERROR, "Couldn't open %s", config.hoard_file);
		return PK_IOERR;
	}
	ret=get_file_lock(state.hoard_fd, FILE_LOCK_READ|FILE_LOCK_WAIT);
	if (ret) {
		pk_log(LOG_ERROR, "Couldn't get read lock on %s",
					config.hoard_file);
		goto bad;
	}

	ret=attach(state.db, "hoard", config.hoard_index);
	if (ret)
		goto bad;
	ret=begin(state.db);
	if (ret)
		goto bad;
	if (query(&stmt, state.db, "PRAGMA hoard.user_version", NULL) !=
				SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't get hoard cache index version");
		ret=PK_IOERR;
		goto bad_rollback;
	}
	query_row(stmt, "d", &ver);
	query_free(stmt);
	switch (ver) {
	case 0:
		ret=create_hoard_index();
		if (ret)
			goto bad_rollback;
		break;
	case HOARD_INDEX_VERSION:
		break;
	default:
		pk_log(LOG_ERROR, "Unknown hoard cache version %d", ver);
		ret=PK_BADFORMAT;
		goto bad_rollback;
	}
	ret=commit(state.db);
	if (ret)
		goto bad_rollback;

	if (config.parcel_dir != NULL) {
		ret=get_parcel_ident();
		if (ret)
			goto bad;
	}
	return PK_SUCCESS;

bad_rollback:
	rollback(state.db);
bad:
	close(state.hoard_fd);
	return ret;
}

void hoard_shutdown(void)
{
	hoard_try_cleanup();
	close(state.hoard_fd);
}
