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

#include <string.h>
#include <stdlib.h>
#include "defs.h"

/* XXX SIGINT */
int hoard(void)
{
	struct query *qry;
	void *buf;
	size_t chunklen;
	int chunk;
	void *tag;
	unsigned taglen;
	int num_hoarded=0;
	int to_hoard;
	int ret=1;
	int sret;

	buf=malloc(parcel.chunksize);
	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failure");
		return 1;
	}

	/* We need to do this first; otherwise, chunks we thought were hoarded
	   could disappear out from under us */
	if (hoard_sync_refs(0)) {
		pk_log(LOG_ERROR, "Couldn't synchronize reference list");
		goto out_free;
	}

	/* Build a temp table listing the chunks to hoard, so that
	   while we're actually hoarding we don't have locks against
	   the hoard index.  Take care not to list a tag more than once,
	   to keep the progress meter accurate */
	if (query(NULL, state.db, "CREATE TEMP TABLE to_hoard "
				"(chunk INTEGER NOT NULL, "
				"tag BLOB UNIQUE NOT NULL)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create temporary table");
		goto out_free;
	}
	if (query(NULL, state.db, "INSERT OR IGNORE INTO temp.to_hoard "
				"(chunk, tag) SELECT chunk, tag "
				"FROM prev.keys WHERE tag NOT IN "
				"(SELECT tag FROM hoard.chunks)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't build list of chunks to hoard");
		goto out_drop;
	}

	/* See how much we need to hoard */
	if (query(&qry, state.db, "SELECT count(*) FROM temp.to_hoard", NULL)
				!= SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't count unhoarded chunks");
		goto out_drop;
	}
	query_row(qry, "d", &to_hoard);
	query_free(qry);

	/* If WANT_CHECK, that's all we need to do */
	if (config.flags & WANT_CHECK) {
		if (to_hoard == 0)
			ret=0;
		goto out_drop;
	}

	for (sret=query(&qry, state.db, "SELECT chunk, tag "
				"FROM temp.to_hoard", NULL);
				sret == SQLITE_ROW; sret=query_next(qry)) {
		query_row(qry, "db", &chunk, &tag, &taglen);
		if (taglen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Invalid tag length for chunk %d",
						chunk);
			goto out_qry;
		}

		/* Make sure the chunk hasn't already been put in the hoard
		   cache (because someone else already downloaded it) before
		   we download.  Use the hoard DB connection so that state.db
		   doesn't acquire the hoard DB lock. */
		sret=query(NULL, state.hoard, "SELECT tag FROM chunks "
					"WHERE tag == ?", "b", tag, taglen);
		if (sret == SQLITE_OK) {
			if (transport_fetch_chunk(buf, chunk, tag, &chunklen))
				goto out_qry;
			print_progress_chunks(++num_hoarded, to_hoard);
		} else if (sret == SQLITE_ROW) {
			print_progress_chunks(num_hoarded, --to_hoard);
		} else {
			pk_log(LOG_ERROR, "Couldn't query hoard cache index");
			goto out_qry;
		}
	}
	if (sret != SQLITE_OK)
		pk_log(LOG_ERROR, "Querying hoard index failed");
	else
		ret=0;
out_qry:
	query_free(qry);
out_drop:
	if (query(NULL, state.db, "DROP TABLE temp.to_hoard", NULL))
		pk_log(LOG_ERROR, "Couldn't drop table temp.to_hoard");
out_free:
	free(buf);
	return ret;
}

int examine_hoard(void)
{
	struct query *qry;
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
	if (query(&qry, state.db, "SELECT count(DISTINCT tag) FROM prev.keys",
				NULL) != SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't query previous keyring");
		goto bad;
	}
	query_row(qry, "d", &maxchunks);
	query_free(qry);
	if (query(&qry, state.db, "SELECT count(DISTINCT hoard.chunks.tag) "
				"FROM prev.keys JOIN hoard.chunks "
				"ON prev.keys.tag == hoard.chunks.tag", NULL)
				!= SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't query hoard cache");
		goto bad;
	}
	query_row(qry, "d", &validchunks);
	query_free(qry);
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

int list_hoard(void)
{
	struct query *p_qry;
	struct query *t_qry;
	int sret;
	int ret=1;
	int parcel;
	const char *uuid;
	const char *server;
	const char *user;
	const char *name;
	int p_total;
	int p_unique;
	int shared;
	int unreferenced;
	int unused;

	if (begin(state.db))
		return 1;
	if (query(&t_qry, state.db, "SELECT count(tag) FROM hoard.chunks "
				"WHERE referenced == 1", NULL) != SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't count referenced chunks");
		goto out;
	}
	query_row(t_qry, "d", &shared);
	query_free(t_qry);
	if (query(&t_qry, state.db, "SELECT count(tag) FROM hoard.chunks "
				"WHERE referenced == 0", NULL) != SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't count unreferenced chunks");
		goto out;
	}
	query_row(t_qry, "d", &unreferenced);
	query_free(t_qry);
	if (query(&t_qry, state.db, "SELECT count(*) FROM hoard.chunks "
				"WHERE tag ISNULL", NULL) != SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't count unused chunk slots");
		goto out;
	}
	query_row(t_qry, "d", &unused);
	query_free(t_qry);
	for (sret=query(&p_qry, state.db, "SELECT parcel, uuid, server, "
				"user, name FROM hoard.parcels", NULL);
				sret == SQLITE_ROW; sret=query_next(p_qry)) {
		query_row(p_qry, "dssss", &parcel, &uuid, &server, &user,
					&name);
		if (query(&t_qry, state.db, "SELECT count(*) FROM hoard.refs "
					"WHERE parcel == ?", "d", parcel)
					!= SQLITE_ROW) {
			pk_log(LOG_ERROR, "Couldn't query hoard index for "
						"parcel %s", name);
			break;
		}
		query_row(t_qry, "d", &p_total);
		query_free(t_qry);
		if (query(&t_qry, state.db, "SELECT count(*) FROM hoard.refs "
					"WHERE parcel == ? AND tag NOT IN "
					"(SELECT tag FROM hoard.refs WHERE "
					"parcel != ?)", "dd", parcel, parcel)
					!= SQLITE_ROW) {
			pk_log(LOG_ERROR, "Couldn't query hoard index for "
						"parcel %s", name);
			break;
		}
		query_row(t_qry, "d", &p_unique);
		query_free(t_qry);
		printf("%s %s %s %s %d %d\n", uuid, server, user, name, p_total,
					p_unique);
		shared -= p_unique;
	}
	query_free(p_qry);
	if (sret == SQLITE_OK) {
		printf("shared %d\n", shared);
		printf("unreferenced %d\n", unreferenced);
		printf("unused %d\n", unused);
		ret=0;
	} else {
		pk_log(LOG_ERROR, "Couldn't list parcels in hoard cache");
	}
out:
	rollback(state.db);
	return ret;
}

int rmhoard(void)
{
	struct query *qry;
	const char *server;
	const char *user;
	const char *name;
	char *desc;
	int parcel;
	int removed;

	if (begin_immediate(state.db))
		return 1;
	if (query(&qry, state.db, "SELECT parcel, server, user, name "
				"FROM hoard.parcels WHERE uuid == ?", "S",
				config.uuid) != SQLITE_ROW) {
		pk_log(LOG_INFO, "rmhoard: %s: No such parcel", config.uuid);
		rollback(state.db);
		return 0;
	}
	query_row(qry, "dsss", &parcel, &server, &user, &name);
	/* server, user, and name expire when we free the query */
	if (asprintf(&desc, "%s/%s/%s", server, user, name) == -1) {
		query_free(qry);
		pk_log(LOG_ERROR, "malloc failure");
		goto bad;
	}
	query_free(qry);

	if (query(&qry, state.db, "SELECT count(*) FROM hoard.refs WHERE "
				"parcel == ? AND tag NOT IN (SELECT tag "
				"FROM hoard.refs WHERE parcel != ?)", "dd",
				parcel, parcel) != SQLITE_ROW) {
		free(desc);
		pk_log(LOG_ERROR, "Couldn't enumerate unique parcel chunks");
		goto bad;
	}
	query_row(qry, "d", &removed);
	query_free(qry);

	pk_log(LOG_INFO, "Removing parcel %s from hoard cache...", desc);
	free(desc);
	if (query(NULL, state.db, "UPDATE hoard.chunks SET referenced = 0 "
				"WHERE tag IN (SELECT tag FROM hoard.refs "
				"WHERE parcel == ? AND tag NOT IN "
				"(SELECT tag FROM hoard.refs WHERE "
				"PARCEL != ?))", "dd", parcel, parcel)) {
		pk_log(LOG_ERROR, "Couldn't update referenced flags");
		goto bad;
	}
	if (query(NULL, state.db, "DELETE FROM hoard.refs WHERE parcel == ?",
				"d", parcel) != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't remove parcel from hoard cache");
		goto bad;
	}

	/* We can't remove the parcel from the parcels table unless we know
	   that no other Parcelkeeper process is running against that parcel */

	if (commit(state.db))
		goto bad;
	pk_log(LOG_INFO, "Deallocated %d chunks", removed);
	return 0;

bad:
	rollback(state.db);
	return 1;
}

static pk_err_t check_hoard_data(void)
{
	struct query *qry;
	char buf[131072];  /* XXX assumes 128 KB */
	const void *tag;
	char calctag[20];  /* XXX */
	unsigned expected_taglen;
	unsigned taglen;
	unsigned offset;
	unsigned len;
	off64_t examined_bytes;
	off64_t total_bytes;
	int sret;
	pk_err_t ret=PK_SUCCESS;
	int count=0;

	pk_log(LOG_INFO, "Validating hoard cache data");
	printf("Validating hoard cache data...\n");

	if (query(&qry, state.db, "SELECT sum(length) FROM temp.to_check",
				NULL) != SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't find the amount of data to check");
		return PK_IOERR;
	}
	query_row(qry, "D", &total_bytes);
	query_free(qry);

	/* XXX shouldn't hardcode crypto type -- we need a column for this */
	expected_taglen=crypto_hashlen(CRY_AES_SHA1);
	examined_bytes=0;
	for (sret=query(&qry, state.db, "SELECT tag, offset, length "
				"FROM temp.to_check", NULL);
				sret == SQLITE_ROW; sret=query_next(qry)) {
		query_row(qry, "bdd", &tag, &taglen, &offset, &len);
		examined_bytes += len;
		print_progress_mb(examined_bytes, total_bytes);
		if (taglen != expected_taglen) {
			/* XXX */
			pk_log(LOG_ERROR, "Found chunk with invalid tag "
						"length %d", taglen);
			hoard_invalidate_chunk(offset, tag, taglen);
			count++;
			continue;
		}
		/* check_hoard() already checked this, but buffer overflows
		   are bad */
		if (len > sizeof(buf)) {
			/* XXX */
			pk_log(LOG_ERROR, "Found chunk with invalid length %d",
						len);
			hoard_invalidate_chunk(offset, tag, taglen);
			count++;
			continue;
		}
		if (pread(state.hoard_fd, buf, len, ((off_t)offset) << 9)
					!= (off_t)len) {
			pk_log(LOG_ERROR, "Couldn't read chunk at offset %d",
						offset);
			hoard_invalidate_chunk(offset, tag, taglen);
			count++;
			continue;
		}

		if (digest(CRY_AES_SHA1, calctag, buf, len)) {
			pk_log(LOG_ERROR, "digest() failed");
			ret=PK_CALLFAIL;
			continue;
		}
		if (memcmp(tag, calctag, taglen)) {
			pk_log(LOG_ERROR, "Tag mismatch at offset %d", offset);
			log_tag_mismatch(tag, calctag, taglen);
			hoard_invalidate_chunk(offset, tag, taglen);
			count++;
		}
	}
	query_free(qry);
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't walk chunk list");
		ret=PK_IOERR;
	}
	if (query(NULL, state.db, "DROP TABLE temp.to_check", NULL)) {
		pk_log(LOG_ERROR, "Couldn't drop temporary table");
		ret=PK_IOERR;
	}
	if (count)
		pk_log(LOG_ERROR, "Removed %d invalid chunks", count);
	return ret;
}

int check_hoard(void)
{
	struct query *qry;
	const char *uuid;
	int offset;
	int next_offset;
	int count;
	int sret;
	int time;

	pk_log(LOG_INFO, "Validating hoard cache");
	printf("Validating hoard cache...\n");
	if (validate_db(state.db))
		return 1;
	if (begin_immediate(state.db))
		return 1;

	for (sret=query(&qry, state.db, "SELECT uuid FROM hoard.parcels",
				NULL), count=0; sret == SQLITE_ROW;
				sret=query_next(qry)) {
		query_row(qry, "s", &uuid);
		if (canonicalize_uuid(uuid, NULL) == PK_INVALID) {
			if (query(NULL, state.db, "DELETE FROM hoard.parcels "
						"WHERE uuid == ?", "s",
						uuid) != SQLITE_OK) {
				pk_log(LOG_ERROR, "Couldn't remove invalid "
							"parcel record "
							"from hoard index");
				goto bad;
			}
			count += sqlite3_changes(state.db);
		}
	}
	query_free(qry);
	if (count)
		pk_log(LOG_ERROR, "Removed %d invalid parcel records", count);
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't query parcel list");
		goto bad;
	}

	next_offset=0;
	for (sret=query(&qry, state.db, "SELECT offset FROM hoard.chunks "
				"ORDER BY offset", NULL); sret == SQLITE_ROW;
				sret=query_next(qry)) {
		query_row(qry, "d", &offset);
		if (offset != next_offset) {
			/* XXX how do we fix this? */
			pk_log(LOG_ERROR, "Expected offset %d, found %d",
						next_offset, offset);
			query_free(qry);
			goto bad;
		}
		/* XXX assumes 128 KB */
		next_offset += 256;
	}
	query_free(qry);
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't query chunk table");
		goto bad;
	}

	/* XXX assumes 128 KB */
	if (cleanup_action(state.db, "UPDATE hoard.chunks SET tag = NULL, "
				"length = 0, last_access = 0, referenced = 0 "
				"WHERE length < 0 OR length > 131072 OR "
				"(length == 0 AND tag NOTNULL)",
				LOG_ERROR,
				"chunks with invalid length"))
		goto bad;
	if (cleanup_action(state.db, "UPDATE hoard.chunks SET tag = NULL, "
				"length = 0, last_access = 0, referenced = 0 "
				"WHERE referenced != 0 AND referenced != 1",
				LOG_ERROR,
				"chunks with invalid referenced flag"))
		goto bad;
	if (cleanup_action(state.db, "DELETE FROM hoard.refs WHERE parcel "
				"NOT IN (SELECT parcel FROM hoard.parcels)",
				LOG_ERROR,
				"refs with dangling parcel ID"))
		goto bad;
	if (cleanup_action(state.db, "DELETE FROM hoard.refs WHERE tag NOT IN "
				"(SELECT tag FROM hoard.chunks)",
				LOG_ERROR,
				"refs with dangling tag"))
		goto bad;
	if (cleanup_action(state.db, "UPDATE hoard.chunks SET referenced = 0 "
				"WHERE referenced == 1 AND tag NOTNULL AND "
				"tag NOT IN (SELECT tag FROM hoard.refs)",
				LOG_ERROR,
				"chunks with spurious referenced flag"))
		goto bad;
	if (cleanup_action(state.db, "UPDATE hoard.chunks SET referenced = 1 "
				"WHERE referenced == 0 AND tag NOTNULL AND "
				"tag IN (SELECT tag FROM hoard.refs)",
				LOG_ERROR,
				"chunks with missing referenced flag"))
		goto bad;

	time=timestamp();
	if (query(NULL, state.db, "UPDATE hoard.chunks SET last_access = ? "
				"WHERE last_access > ?", "dd", time,
				time + 10)) {
		pk_log(LOG_ERROR, "Couldn't locate chunks with invalid "
					"timestamps");
		goto bad;
	}
	count=sqlite3_changes(state.db);
	if (count)
		pk_log(LOG_ERROR, "Repaired %d chunks with timestamps in the "
					"future", count);

	/* If we're going to do a FULL_CHECK, then get the necessary metadata
	   *now* while we still know it's consistent. */
	if (config.flags & WANT_FULL_CHECK) {
		if (query(NULL, state.db, "CREATE TEMP TABLE to_check AS "
					"SELECT tag, offset, length "
					"FROM hoard.chunks WHERE tag NOTNULL "
					"ORDER BY offset", NULL)) {
			pk_log(LOG_ERROR, "Couldn't enumerate hoarded chunks");
			goto bad;
		}
	}

	if (commit(state.db))
		goto bad;

	if (config.flags & WANT_FULL_CHECK)
		if (check_hoard_data())
			return 1;
	/* XXX compact */
	return 0;

bad:
	rollback(state.db);
	return 1;
}

int hoard_refresh(void)
{
	if (hoard_sync_refs(0))
		return 1;
	return 0;
}
