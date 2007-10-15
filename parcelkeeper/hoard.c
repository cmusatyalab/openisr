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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include "defs.h"

#define HOARD_INDEX_VERSION 1
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
				"length INTEGER,"
				"last_access INTEGER)", NULL)) {
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

static void deallocate_chunk_offset(int offset)
{
	if (query(NULL, state.db, "UPDATE hoard.chunks SET tag = NULL, "
				"length = NULL, last_access = NULL "
				"WHERE offset = ?", "d", offset)) {
		pk_log(LOG_ERROR, "Couldn't deallocate hoard chunk at "
					"offset %d", offset);
	}
}

static void add_chunk_reference(const void *tag)
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
		/* Non-fatal */
	}
}

pk_err_t hoard_get_chunk(const void *tag, void *buf, unsigned *len)
{
	sqlite3_stmt *stmt;
	struct timeval tv;
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

	gettimeofday(&tv, NULL);
	if (query(NULL, state.db, "UPDATE hoard.chunks SET last_access = ? "
				"WHERE tag == ?", "db", tv.tv_sec, tag,
				parcel.hashlen)) {
		/* Not fatal */
		pk_log(LOG_ERROR, "Couldn't update chunk timestamp");
	}
	add_chunk_reference(tag);

	ret=commit(state.db);
	if (ret)
		goto bad;

	/* XXX what if the reference is released right now?  we could read in
	   bad chunk data.  do we need to hold a read lock the whole time? */

	if (clen <= 0 || clen > parcel.chunksize)
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
	sqlite3_stmt *stmt;
	struct timeval tv;
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
		add_chunk_reference(tag);
		ret=commit(state.db);
		if (ret)
			goto bad;
		return PK_SUCCESS;
	} else if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't look up tag in hoard cache index");
		goto bad;
	}

	while ((sret=query(&stmt, state.db, "SELECT offset FROM hoard.chunks "
				"WHERE length ISNULL LIMIT 1", NULL))
				== SQLITE_OK) {
		query_free(stmt);
		ret=expand_cache();
		if (ret)
			goto bad;
	}
	if (sret != SQLITE_ROW) {
		pk_log(LOG_ERROR, "Error finding unused hoard cache offset");
		goto bad;
	}
	query_row(stmt, "d", &offset);
	query_free(stmt);

	gettimeofday(&tv, NULL);
	if (query(NULL, state.db, "UPDATE hoard.chunks SET length = ?, "
				"last_access = ? WHERE offset == ?", "ddd",
				len, tv.tv_sec, offset)) {
		pk_log(LOG_ERROR, "Couldn't allocate hoard cache chunk");
		ret=PK_IOERR;
		goto bad;
	}

	ret=commit(state.db);
	if (ret)
		goto bad;

	/* XXX how do we guarantee no floating unused chunks?  look for very
	   old last-access time? */

	if (pwrite(state.hoard_fd, buf, len, ((off_t)offset) << 9) != len) {
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
	sret=query(NULL, state.db, "UPDATE hoard.chunks SET tag = ? "
				"WHERE offset = ?", "bd",
				tag, parcel.hashlen, offset);
	if (sret == SQLITE_CONSTRAINT) {
		/* Someone else has already written this tag */
		deallocate_chunk_offset(offset);
	} else if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't commit hoard cache chunk");
		rollback(state.db);
		deallocate_chunk_offset(offset);
		return PK_IOERR;
	}
	add_chunk_reference(tag);
	ret=commit(state.db);
	if (ret) {
		pk_log(LOG_ERROR, "Couldn't commit hoard cache chunk");
		rollback(state.db);
		deallocate_chunk_offset(offset);
		return ret;
	}
	return PK_SUCCESS;

bad:
	rollback(state.db);
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
					"SELECT DISTINCT tag FROM last.keys",
					NULL);
	if (sret) {
		pk_log(LOG_ERROR, "Couldn't generate tag list");
		ret=PK_IOERR;
		goto bad;
	}
	if (query(NULL, state.db, "DELETE FROM hoard.refs WHERE parcel == ? "
				"AND tag NOT IN (SELECT tag FROM temp.newrefs)",
				"d", state.hoard_ident)) {
		pk_log(LOG_ERROR, "Couldn't garbage-collect hoard refs");
		/* Non-fatal */
	}
	if (query(NULL, state.db, "INSERT OR IGNORE INTO hoard.refs "
				"(parcel, tag) SELECT ?, tag FROM temp.newrefs "
				"WHERE tag IN (SELECT tag FROM hoard.chunks)",
				"d", state.hoard_ident)) {
		pk_log(LOG_ERROR, "Couldn't insert new hoard refs");
		/* XXX? */
	}
	if (query(NULL, state.db, "DROP VIEW temp.newrefs", NULL)) {
		pk_log(LOG_ERROR, "Couldn't drop temporary view");
		ret=PK_IOERR;
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

/* XXX should select some number of rows at once.  we don't want to do too many
   selects, but we don't want to download again if e.g. multiple parcels are
   hoarding at once. */
/* XXX SIGINT */
int hoard(void)
{
	sqlite3_stmt *stmt;
	void *buf;
	size_t chunklen;
	int chunk;
	void *tagp;
	char tag[parcel.hashlen];
	int taglen;
	int num_hoarded=0;
	int to_hoard;
	int ret=1;
	int sret;

	buf=malloc(parcel.chunksize);
	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failure");
		return 1;
	}

	if (hoard_sync_refs(0)) {
		pk_log(LOG_ERROR, "Couldn't synchronize reference list");
		goto out;
	}

	if (query(&stmt, state.db, "SELECT count(DISTINCT tag) FROM last.keys "
				"WHERE tag NOT IN "
				"(SELECT tag FROM hoard.chunks)",
				NULL) != SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't count unhoarded chunks");
		goto out;
	}
	query_row(stmt, "d", &to_hoard);
	query_free(stmt);

	while ((sret=query(&stmt, state.db, "SELECT chunk, tag FROM last.keys "
				"WHERE tag NOT IN "
				"(SELECT tag FROM hoard.chunks) LIMIT 1", NULL))
				== SQLITE_ROW) {
		query_row(stmt, "db", &chunk, &tagp, &taglen);
		if (taglen != parcel.hashlen) {
			query_free(stmt);
			pk_log(LOG_ERROR, "Invalid tag length for chunk %d",
						chunk);
			goto out;
		}
		memcpy(tag, tagp, parcel.hashlen);
		query_free(stmt);
		if (transport_fetch_chunk(buf, chunk, tag, &chunklen))
			goto out;
		print_progress(++num_hoarded, to_hoard);
	}
	query_free(stmt);
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Querying hoard index failed");
		goto out;
	}
	ret=0;
out:
	free(buf);
	return ret;
}

int examine_hoard(void)
{
	sqlite3_stmt *stmt;
	unsigned validchunks;
	unsigned maxchunks;
	unsigned valid_mb;
	unsigned max_mb;
	unsigned valid_pct;

	if (hoard_sync_refs(0)) {
		pk_log(LOG_ERROR, "Couldn't synchronize reference list");
		return 1;
	}

	if (begin(state.db))
		return 1;
	if (query(&stmt, state.db, "SELECT count(DISTINCT tag) FROM last.keys",
				NULL) != SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query last keyring");
		goto bad;
	}
	query_row(stmt, "d", &maxchunks);
	query_free(stmt);
	if (query(&stmt, state.db, "SELECT count(DISTINCT hoard.chunks.tag) "
				"FROM last.keys JOIN hoard.chunks "
				"ON last.keys.tag == hoard.chunks.tag", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query hoard cache");
		goto bad;
	}
	query_row(stmt, "d", &validchunks);
	query_free(stmt);
	if (commit(state.db))
		goto bad;

	max_mb=(((off64_t)maxchunks) * parcel.chunksize) >> 20;
	valid_mb=(((off64_t)validchunks) * parcel.chunksize) >> 20;
	valid_pct=(100 * validchunks) / maxchunks;
	printf("Hoard cache : %u%% populated (%u/%u MB)\n", valid_pct,
				valid_mb, max_mb);
	return 0;

bad:
	rollback(state.db);
	return 1;
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
