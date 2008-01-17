/*
 * Parcelkeeper - support daemon for the OpenISR (R) system virtual disk
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
#include <string.h>
#include <time.h>
#include "defs.h"

#define HOARD_INDEX_VERSION 7
#define EXPAND_CHUNKS 128

static pk_err_t create_hoard_index(void)
{
	/* XXX auto_vacuum */
	if (query(NULL, state.hoard, "PRAGMA user_version = "
				stringify(HOARD_INDEX_VERSION), NULL)) {
		pk_log_sqlerr("Couldn't set schema version");
		return PK_IOERR;
	}

	if (query(NULL, state.hoard, "CREATE TABLE parcels ("
				"parcel INTEGER PRIMARY KEY NOT NULL, "
				"uuid TEXT UNIQUE NOT NULL, "
				"server TEXT NOT NULL, "
				"user TEXT NOT NULL, "
				"name TEXT NOT NULL)", NULL)) {
		pk_log_sqlerr("Couldn't create parcel table");
		return PK_IOERR;
	}

	if (query(NULL, state.hoard, "CREATE TABLE chunks ("
				"tag BLOB UNIQUE, "
				/* 512-byte sectors */
				"offset INTEGER UNIQUE NOT NULL, "
				"length INTEGER NOT NULL DEFAULT 0, "
				"crypto INTEGER NOT NULL DEFAULT 0, "
				"last_access INTEGER NOT NULL DEFAULT 0, "
				"referenced INTEGER NOT NULL DEFAULT 0)",
				NULL)) {
		pk_log_sqlerr("Couldn't create chunk table");
		return PK_IOERR;
	}
	if (query(NULL, state.hoard, "CREATE INDEX chunks_lru ON "
				"chunks (referenced, last_access)", NULL)) {
		pk_log_sqlerr("Couldn't create chunk LRU index");
		return PK_IOERR;
	}

	if (query(NULL, state.hoard, "CREATE TABLE refs ("
				"parcel INTEGER NOT NULL, "
				"tag BLOB NOT NULL)", NULL)) {
		pk_log_sqlerr("Couldn't create reference table");
		return PK_IOERR;
	}
	if (query(NULL, state.hoard, "CREATE UNIQUE INDEX refs_constraint "
				"ON refs (parcel, tag)", NULL)) {
		pk_log_sqlerr("Couldn't create chunk LRU index");
		return PK_IOERR;
	}
	if (query(NULL, state.hoard, "CREATE INDEX refs_bytag ON refs "
				"(tag, parcel)", NULL)) {
		pk_log_sqlerr("Couldn't create chunk reverse index");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

static pk_err_t upgrade_hoard_index(int ver)
{
	pk_log(LOG_INFO, "Upgrading hoard cache version %d to version %d",
				ver, HOARD_INDEX_VERSION);
	switch (ver) {
	default:
		pk_log(LOG_ERROR, "Unrecognized hoard cache version %d, "
					"bailing out", ver);
		return PK_BADFORMAT;
	case 5:
		if (query(NULL, state.hoard, "DROP INDEX chunks_lru", NULL)) {
			pk_log_sqlerr("Couldn't drop old chunk LRU index");
			return PK_IOERR;
		}
		if (query(NULL, state.hoard, "CREATE INDEX chunks_lru ON "
					"chunks (referenced, last_access)",
					NULL)) {
			pk_log_sqlerr("Couldn't create new chunk LRU index");
			return PK_IOERR;
		}
		/* Fall through */
	case 6:
		if (query(NULL, state.hoard, "CREATE INDEX refs_bytag ON refs "
					"(tag, parcel)", NULL)) {
			pk_log_sqlerr("Couldn't create chunk reverse index");
			return PK_IOERR;
		}
	}
	if (query(NULL, state.hoard, "PRAGMA user_version = "
				stringify(HOARD_INDEX_VERSION), NULL)) {
		pk_log_sqlerr("Couldn't update schema version");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

/* XXX cache chunks of different sizes */
/* must be within transaction */
static pk_err_t expand_cache(void)
{
	struct query *qry;
	int count;
	int start;
	int i;
	int step = parcel.chunksize >> 9;

	query(&qry, state.hoard, "SELECT count(*), max(offset) FROM chunks",
				NULL);
	if (!query_has_row()) {
		pk_log_sqlerr("Couldn't find maximum hoard cache offset");
		return PK_IOERR;
	}
	query_row(qry, "dd", &count, &start);
	query_free(qry);
	if (count)
		start += step;
	for (i=0; i<EXPAND_CHUNKS; i++) {
		if (query(NULL, state.hoard, "INSERT INTO chunks (offset) "
					"VALUES (?)", "d", start + i * step)) {
			pk_log_sqlerr("Couldn't expand hoard cache to "
						"offset %d", start + i * step);
			return PK_IOERR;
		}
	}
	return PK_SUCCESS;
}

/* must be within transaction */
static pk_err_t allocate_chunk_offset(int *offset)
{
	struct query *qry;
	pk_err_t ret;
	int hoarded=0;

	while (1) {
		/* First, try to find an unused hoard cache slot */
		query(&qry, state.hoard, "SELECT offset FROM chunks "
					"WHERE tag ISNULL LIMIT 1", NULL);
		if (query_has_row()) {
			query_row(qry, "d", offset);
			query_free(qry);
			break;
		} else if (!query_ok()) {
			pk_log_sqlerr("Error finding unused hoard cache "
						"offset");
			return PK_IOERR;
		}

		/* Next, we may want to try reclaiming an existing,
		   unreferenced chunk.  See if we're permitted to do so. */
		if (config.minsize > 0) {
			query(&qry, state.hoard, "SELECT count(tag) "
						"FROM chunks", NULL);
			if (!query_has_row()) {
				pk_log_sqlerr("Error finding size of "
							"hoard cache");
				return PK_IOERR;
			}
			query_row(qry, "d", &hoarded);
			query_free(qry);
		}

		/* XXX assumes 128 KB */
		if ((unsigned)(hoarded / 8) >= config.minsize) {
			/* Try to reclaim the LRU unreferenced chunk */
			query(&qry, state.hoard, "SELECT offset "
					"FROM chunks WHERE referenced == 0 "
					"ORDER BY last_access LIMIT 1", NULL);
			if (query_has_row()) {
				query_row(qry, "d", offset);
				query_free(qry);
				break;
			} else if (!query_ok()) {
				pk_log_sqlerr("Error finding reclaimable "
							"hoard cache offset");
				return PK_IOERR;
			}
		}

		/* Now expand the cache and try again */
		ret=expand_cache();
		if (ret)
			return ret;
	}
	return PK_SUCCESS;
}

static pk_err_t add_chunk_reference(const void *tag)
{
	char *ftag;

	if (query(NULL, state.hoard, "INSERT OR IGNORE INTO refs "
				"(parcel, tag) VALUES (?, ?)", "db",
				state.hoard_ident, tag, parcel.hashlen)) {
		ftag=format_tag(tag, parcel.hashlen);
		pk_log_sqlerr("Couldn't add chunk reference for tag %s", ftag);
		free(ftag);
		return PK_IOERR;
	}
	if (query(NULL, state.hoard, "UPDATE chunks SET referenced = 1 "
				" WHERE tag == ?", "b", tag, parcel.hashlen)) {
		ftag=format_tag(tag, parcel.hashlen);
		pk_log_sqlerr("Couldn't set referenced flag for tag %s", ftag);
		free(ftag);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

/* This function is intended to be used when a particular chunk in the hoard
   cache is found to be invalid (e.g., the data does not match the tag).
   It first checks to make sure that the provided tag/offset pair is still
   valid, in case the chunk in the hoard cache was deleted out from under us
   as we were reading it.  (hoard_get_chunk() cares about this case.)
   Must be called within transaction for hoard connection. */
static pk_err_t _hoard_invalidate_chunk(int offset, const void *tag,
			unsigned taglen)
{
	struct query *qry;
	char *ftag;

	query(&qry, state.hoard, "SELECT offset FROM chunks WHERE "
				"offset == ? AND tag == ?", "db",
				offset, tag, taglen);
	if (query_ok()) {
		/* Harmless: it's already not there.  But let's warn anyway. */
		ftag=format_tag(tag, taglen);
		pk_log(LOG_ERROR, "Attempted to invalidate tag %s at "
					"offset %d, but it does not exist "
					"(harmless)", ftag, offset);
		free(ftag);
		return PK_SUCCESS;
	} else if (!query_has_row()) {
		pk_log_sqlerr("Could not query chunk list");
		return PK_IOERR;
	}
	query_free(qry);

	if (query(NULL, state.hoard, "UPDATE chunks SET tag = NULL, "
				"length = 0, crypto = 0, last_access = 0, "
				"referenced = 0 WHERE offset = ?", "d",
				offset)) {
		pk_log_sqlerr("Couldn't deallocate hoard chunk at offset %d",
					offset);
		return PK_IOERR;
	}
	if (query(NULL, state.hoard, "DELETE FROM refs WHERE tag == ?", "b",
				tag, taglen)) {
		ftag=format_tag(tag, taglen);
		pk_log_sqlerr("Couldn't invalidate references to tag %s",
					ftag);
		free(ftag);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

void hoard_invalidate_chunk(int offset, const void *tag, unsigned taglen)
{
again:
	if (begin(state.hoard))
		return;
	if (_hoard_invalidate_chunk(offset, tag, taglen)) {
		rollback(state.hoard);
		if (query_retry())
			goto again;
		return;
	}
	if (commit(state.hoard))
		rollback(state.hoard);
}

pk_err_t hoard_get_chunk(const void *tag, void *buf, unsigned *len)
{
	struct query *qry;
	char calctag[parcel.hashlen];
	int offset;
	int clen;
	pk_err_t ret;

	if (config.hoard_dir == NULL)
		return PK_NOTFOUND;

again:
	ret=begin(state.hoard);
	if (ret)
		return ret;

	query(&qry, state.hoard, "SELECT offset, length FROM chunks "
				"WHERE tag == ?", "b", tag, parcel.hashlen);
	if (query_ok()) {
		ret=commit(state.hoard);
		if (ret)
			goto bad;
		return PK_NOTFOUND;
	} else if (!query_has_row()) {
		pk_log_sqlerr("Couldn't query hoard chunk index");
		ret=PK_IOERR;
		goto bad;
	}
	query_row(qry, "dd", &offset, &clen);
	query_free(qry);

	if (offset < 0 || clen <= 0 || (unsigned)clen > parcel.chunksize) {
		pk_log(LOG_ERROR, "Chunk has unreasonable offset/length "
					"%d/%d; invalidating", offset, clen);
		ret=_hoard_invalidate_chunk(offset, tag, parcel.hashlen);
		if (ret)
			goto bad;
		ret=PK_BADFORMAT;
		if (commit(state.hoard))
			goto bad;
		return ret;
	}

	if (query(NULL, state.hoard, "UPDATE chunks SET last_access = ? "
				"WHERE tag == ?", "db", time(NULL), tag,
				parcel.hashlen)) {
		/* Not fatal, but if we got SQLITE_BUSY, retry anyway */
		pk_log_sqlerr("Couldn't update chunk timestamp");
		if (query_busy())
			goto bad;
	}
	ret=add_chunk_reference(tag);
	if (ret)
		goto bad;

	ret=commit(state.hoard);
	if (ret)
		goto bad;

	if (pread(state.hoard_fd, buf, clen, ((off_t)offset) << 9) != clen) {
		pk_log(LOG_ERROR, "Couldn't read chunk at offset %d", offset);
		hoard_invalidate_chunk(offset, tag, parcel.hashlen);
		return PK_IOERR;
	}

	/* Make sure the stored hash matches the actual hash of the data.
	   If not, remove the chunk from the hoard cache.  If the reference
	   is released right now (e.g. by an rmhoard) and the chunk slot is
	   immediately reused, we'll find a hash mismatch, but we don't want
	   to blindly invalidate the slot because some other data has been
	   stored there in the interim.  Therefore, _hoard_invalidate_chunk()
	   checks that the tag/index pair is still present in the chunks
	   table before invalidating the slot. */

	ret=digest(parcel.crypto, calctag, buf, clen);
	if (ret)
		return ret;
	if (memcmp(tag, calctag, parcel.hashlen)) {
		pk_log(LOG_ERROR, "Tag mismatch reading hoard cache at "
					"offset %d", offset);
		log_tag_mismatch(tag, calctag, parcel.hashlen);
		hoard_invalidate_chunk(offset, tag, parcel.hashlen);
		return PK_TAGFAIL;
	}

	*len=clen;
	return PK_SUCCESS;

bad:
	rollback(state.hoard);
	if (query_retry())
		goto again;
	return ret;
}

pk_err_t hoard_put_chunk(const void *tag, const void *buf, unsigned len)
{
	pk_err_t ret;
	int offset;

	if (config.hoard_dir == NULL)
		return PK_SUCCESS;

again:
	ret=begin(state.hoard);
	if (ret)
		return ret;

	query(NULL, state.hoard, "SELECT tag FROM chunks WHERE tag == ?",
				"b", tag, parcel.hashlen);
	if (query_has_row()) {
		ret=add_chunk_reference(tag);
		if (ret)
			goto bad;
		ret=commit(state.hoard);
		if (ret)
			goto bad;
		return PK_SUCCESS;
	} else if (!query_ok()) {
		pk_log_sqlerr("Couldn't look up tag in hoard cache index");
		goto bad;
	}

	ret=allocate_chunk_offset(&offset);
	if (ret)
		goto bad;
	if (query(NULL, state.hoard, "UPDATE chunks SET referenced = 1, "
				"tag = ?, length = ?, crypto = ?, "
				"last_access = ? WHERE offset = ?", "bdddd",
				tag, parcel.hashlen, len, parcel.crypto,
				time(NULL), offset)) {
		pk_log_sqlerr("Couldn't add metadata for hoard cache chunk");
		ret=PK_IOERR;
		goto bad;
	}
	ret=add_chunk_reference(tag);
	if (ret)
		goto bad;

	if (pwrite(state.hoard_fd, buf, len, ((off_t)offset) << 9) !=
				(int)len) {
		pk_log(LOG_ERROR, "Couldn't write hoard cache: offset %d, "
					"length %d", offset, len);
		ret=PK_IOERR;
		goto bad;
	}

	ret=commit(state.hoard);
	if (ret) {
		pk_log(LOG_ERROR, "Couldn't commit hoard cache chunk");
		goto bad;
	}
	return PK_SUCCESS;

bad:
	rollback(state.hoard);
	if (query_retry())
		goto again;
	return ret;
}

/* We use state.db rather than state.hoard in this function, since we need to
   compare to the previous or current keyring */
pk_err_t hoard_sync_refs(int from_cache)
{
	pk_err_t ret;

	if (config.hoard_dir == NULL)
		return PK_SUCCESS;

again:
	ret=begin(state.db);
	if (ret)
		return ret;
	if (from_cache)
		query(NULL, state.db, "CREATE TEMP TABLE newrefs AS "
					"SELECT DISTINCT tag FROM keys", NULL);
	else
		query(NULL, state.db, "CREATE TEMP TABLE newrefs AS "
					"SELECT DISTINCT tag FROM prev.keys",
					NULL);
	ret=PK_IOERR;
	if (!query_ok()) {
		pk_log_sqlerr("Couldn't generate tag list");
		goto bad;
	}
	if (query(NULL, state.db, "CREATE INDEX temp.newrefs_tags ON "
				"newrefs (tag)", NULL)) {
		pk_log_sqlerr("Couldn't create tag index");
		goto bad;
	}
	if (query(NULL, state.db, "UPDATE hoard.chunks SET referenced = 0 "
				"WHERE tag IN "
				"(SELECT tag FROM hoard.refs WHERE parcel == ? "
				"AND tag NOT IN (SELECT tag FROM temp.newrefs) "
				"AND tag NOT IN (SELECT tag FROM hoard.refs "
				"WHERE parcel != ?))", "dd", state.hoard_ident,
				state.hoard_ident)) {
		pk_log_sqlerr("Couldn't garbage-collect referenced flags");
		goto bad;
	}
	if (query(NULL, state.db, "DELETE FROM hoard.refs WHERE parcel == ? "
				"AND tag NOT IN (SELECT tag FROM temp.newrefs)",
				"d", state.hoard_ident)) {
		pk_log_sqlerr("Couldn't garbage-collect hoard refs");
		goto bad;
	}
	if (query(NULL, state.db, "INSERT OR IGNORE INTO hoard.refs "
				"(parcel, tag) SELECT ?, tag FROM temp.newrefs "
				"WHERE tag IN (SELECT tag FROM hoard.chunks)",
				"d", state.hoard_ident)) {
		pk_log_sqlerr("Couldn't insert new hoard refs");
		goto bad;
	}
	if (query(NULL, state.db, "UPDATE hoard.chunks SET referenced = 1 "
				"WHERE referenced == 0 AND tag IN "
				"(SELECT tag FROM temp.newrefs)", NULL)) {
		pk_log_sqlerr("Couldn't updated referenced flags");
		goto bad;
	}
	if (query(NULL, state.db, "DROP TABLE temp.newrefs", NULL)) {
		pk_log_sqlerr("Couldn't drop temporary table");
		goto bad;
	}
	ret=commit(state.db);
	if (ret)
		goto bad;
	return PK_SUCCESS;

bad:
	rollback(state.db);
	if (query_retry())
		goto again;
	return ret;
}

static pk_err_t get_parcel_ident(void)
{
	struct query *qry;
	pk_err_t ret;

again:
	ret=begin(state.hoard);
	if (ret)
		return ret;
	if (query(NULL, state.hoard, "INSERT OR IGNORE INTO parcels "
				"(uuid, server, user, name) "
				"VALUES (?, ?, ?, ?)", "SSSS",
				parcel.uuid, parcel.server,
				parcel.user, parcel.parcel)) {
		pk_log_sqlerr("Couldn't insert parcel record");
		ret=PK_IOERR;
		goto bad;
	}
	query(&qry, state.hoard, "SELECT parcel FROM parcels WHERE uuid == ?",
				"S", parcel.uuid);
	if (!query_has_row()) {
		pk_log_sqlerr("Couldn't query parcels table");
		ret=PK_IOERR;
		goto bad;
	}
	query_row(qry, "d", &state.hoard_ident);
	query_free(qry);
	ret=commit(state.hoard);
	if (ret)
		goto bad;
	return PK_SUCCESS;

bad:
	rollback(state.hoard);
	if (query_retry())
		goto again;
	return ret;
}

static void close_hoard_index(void)
{
	query_flush();
	if (sqlite3_close(state.hoard))
		pk_log(LOG_ERROR, "Couldn't close hoard cache index: %s",
					sqlite3_errmsg(state.hoard));
}

static pk_err_t open_hoard_index(void)
{
	struct query *qry;
	pk_err_t ret;
	int ver;

	/* First open the dedicated hoard cache DB connection */
	if (sqlite3_open(config.hoard_index, &state.hoard)) {
		pk_log(LOG_ERROR, "Couldn't open hoard cache index %s: %s",
					config.hoard_index,
					sqlite3_errmsg(state.hoard));
		return PK_IOERR;
	}
	ret=sql_setup_conn(state.hoard);
	if (ret)
		goto bad;

again:
	ret=begin(state.hoard);
	if (ret)
		goto bad;
	query(&qry, state.hoard, "PRAGMA user_version", NULL);
	if (!query_has_row()) {
		pk_log_sqlerr("Couldn't get hoard cache index version");
		ret=PK_IOERR;
		goto bad_rollback;
	}
	query_row(qry, "d", &ver);
	query_free(qry);
	if (ver == 0) {
		ret=create_hoard_index();
	} else if (ver < HOARD_INDEX_VERSION) {
		ret=upgrade_hoard_index(ver);
	} else if (ver > HOARD_INDEX_VERSION) {
		pk_log(LOG_ERROR, "Hoard cache version %d too new (expected "
					"%d)", ver, HOARD_INDEX_VERSION);
		ret=PK_BADFORMAT;
	}
	if (ret)
		goto bad_rollback;
	ret=commit(state.hoard);
	if (ret)
		goto bad_rollback;

	/* Now attach the hoard cache index to the primary DB connection
	   for cross-table queries */
	ret=attach(state.db, "hoard", config.hoard_index);
	if (ret)
		goto bad;
	return PK_SUCCESS;

bad_rollback:
	rollback(state.hoard);
	if (query_retry())
		goto again;
bad:
	close_hoard_index();
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
again:
	ret=cleanup_action(state.hoard, "DELETE FROM parcels WHERE parcel "
				"NOT IN (SELECT DISTINCT parcel FROM refs)",
				LOG_INFO, "dangling parcel records");
	if (query_retry())
		goto again;
out:
	put_file_lock(state.hoard_fd);
	return ret;
}

pk_err_t hoard_init(void)
{
	pk_err_t ret;

	if (config.hoard_dir == NULL)
		return PK_INVALID;
	if (parcel.chunksize != 0 && parcel.chunksize != 131072) {
		pk_log(LOG_ERROR, "Hoard cache non-functional for chunk "
					"sizes != 128 KB");
		return PK_INVALID;
	}
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

	ret=open_hoard_index();
	if (ret)
		goto bad;

	if (config.parcel_dir != NULL) {
		ret=get_parcel_ident();
		if (ret)
			goto bad_close;
	}
	return PK_SUCCESS;

bad_close:
	close_hoard_index();
bad:
	close(state.hoard_fd);
	return ret;
}

void hoard_shutdown(void)
{
	hoard_try_cleanup();
	close_hoard_index();
	close(state.hoard_fd);
}
