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

#include <string.h>
#include <stdlib.h>
#include "defs.h"

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
	unsigned taglen;
	int num_hoarded=0;
	int to_hoard;
	int ret=1;
	int sret;

	/* First, see how many unhoarded chunks there are */
	if (query(&stmt, state.db, "SELECT count(DISTINCT tag) FROM prev.keys "
				"WHERE tag NOT IN "
				"(SELECT tag FROM hoard.chunks)",
				NULL) != SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't count unhoarded chunks");
		return 1;
	}
	query_row(stmt, "d", &to_hoard);
	query_free(stmt);

	/* If WANT_CHECK, that's all we need to do */
	if (config.flags & WANT_CHECK)
		return to_hoard ? 1 : 0;

	buf=malloc(parcel.chunksize);
	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failure");
		return 1;
	}

	if (hoard_sync_refs(0)) {
		pk_log(LOG_ERROR, "Couldn't synchronize reference list");
		goto out;
	}

	while ((sret=query(&stmt, state.db, "SELECT chunk, tag FROM prev.keys "
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
	if (query(&stmt, state.db, "SELECT count(DISTINCT tag) FROM prev.keys",
				NULL) != SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query previous keyring");
		goto bad;
	}
	query_row(stmt, "d", &maxchunks);
	query_free(stmt);
	if (query(&stmt, state.db, "SELECT count(DISTINCT hoard.chunks.tag) "
				"FROM prev.keys JOIN hoard.chunks "
				"ON prev.keys.tag == hoard.chunks.tag", NULL)
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

int list_hoard(void)
{
	sqlite3_stmt *p_stmt;
	sqlite3_stmt *t_stmt;
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
	if (query(&t_stmt, state.db, "SELECT count(tag) FROM hoard.chunks "
				"WHERE referenced == 1", NULL) != SQLITE_ROW) {
		query_free(t_stmt);
		pk_log(LOG_ERROR, "Couldn't count referenced chunks");
		goto out;
	}
	query_row(t_stmt, "d", &shared);
	query_free(t_stmt);
	if (query(&t_stmt, state.db, "SELECT count(tag) FROM hoard.chunks "
				"WHERE referenced == 0", NULL) != SQLITE_ROW) {
		query_free(t_stmt);
		pk_log(LOG_ERROR, "Couldn't count unreferenced chunks");
		goto out;
	}
	query_row(t_stmt, "d", &unreferenced);
	query_free(t_stmt);
	if (query(&t_stmt, state.db, "SELECT count(*) FROM hoard.chunks "
				"WHERE tag ISNULL", NULL) != SQLITE_ROW) {
		query_free(t_stmt);
		pk_log(LOG_ERROR, "Couldn't count unused chunk slots");
		goto out;
	}
	query_row(t_stmt, "d", &unused);
	query_free(t_stmt);
	for (sret=query(&p_stmt, state.db, "SELECT parcel, uuid, server, "
				"user, name FROM hoard.parcels", NULL);
				sret == SQLITE_ROW; sret=query_next(p_stmt)) {
		query_row(p_stmt, "dssss", &parcel, &uuid, &server, &user,
					&name);
		if (query(&t_stmt, state.db, "SELECT count(*) FROM hoard.refs "
					"WHERE parcel == ?", "d", parcel)
					!= SQLITE_ROW) {
			query_free(t_stmt);
			pk_log(LOG_ERROR, "Couldn't query hoard index for "
						"parcel %s", name);
			break;
		}
		query_row(t_stmt, "d", &p_total);
		query_free(t_stmt);
		if (query(&t_stmt, state.db, "SELECT count(*) FROM hoard.refs "
					"WHERE parcel == ? AND tag NOT IN "
					"(SELECT tag FROM hoard.refs WHERE "
					"parcel != ?)", "dd", parcel, parcel)
					!= SQLITE_ROW) {
			query_free(t_stmt);
			pk_log(LOG_ERROR, "Couldn't query hoard index for "
						"parcel %s", name);
			break;
		}
		query_row(t_stmt, "d", &p_unique);
		query_free(t_stmt);
		printf("%s %s %s %s %d %d\n", uuid, server, user, name, p_total,
					p_unique);
		shared -= p_unique;
	}
	query_free(p_stmt);
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
	sqlite3_stmt *stmt;
	const char *server;
	const char *user;
	const char *name;
	char *desc;
	int parcel;
	int removed;

	if (begin_immediate(state.db))
		return 1;
	if (query(&stmt, state.db, "SELECT parcel, server, user, name "
				"FROM hoard.parcels WHERE uuid == ?", "S",
				config.uuid) != SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_INFO, "rmhoard: %s: No such parcel", config.uuid);
		rollback(state.db);
		return 0;
	}
	query_row(stmt, "dsss", &parcel, &server, &user, &name);
	/* server, user, and name expire when we free the query */
	if (asprintf(&desc, "%s/%s/%s", server, user, name) == -1) {
		query_free(stmt);
		pk_log(LOG_ERROR, "malloc failure");
		goto bad;
	}
	query_free(stmt);

	if (query(&stmt, state.db, "SELECT count(*) FROM hoard.refs WHERE "
				"parcel == ? AND tag NOT IN (SELECT tag "
				"FROM hoard.refs WHERE parcel != ?)", "dd",
				parcel, parcel) != SQLITE_ROW) {
		query_free(stmt);
		free(desc);
		pk_log(LOG_ERROR, "Couldn't enumerate unique parcel chunks");
		goto bad;
	}
	query_row(stmt, "d", &removed);
	query_free(stmt);

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

int check_hoard(void)
{
	sqlite3_stmt *stmt;
	const char *uuid;
	int count;
	int sret;

	pk_log(LOG_INFO, "Validating hoard cache");
	printf("Validating hoard cache...\n");
	if (validate_db(state.db))
		return 1;
	if (begin_immediate(state.db))
		return 1;

	for (sret=query(&stmt, state.db, "SELECT uuid FROM hoard.parcels",
				NULL), count=0; sret == SQLITE_ROW;
				sret=query_next(stmt)) {
		query_row(stmt, "s", &uuid);
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
	query_free(stmt);
	if (count)
		pk_log(LOG_INFO, "Removed %d invalid parcel records", count);
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't query parcel list");
		goto bad;
	}

	if (cleanup_action(state.db, "UPDATE hoard.chunks SET tag = NULL, "
				"length = 0, last_access = 0, referenced = 0 "
				"WHERE referenced != 0 AND referenced != 1",
				"chunks with invalid referenced flag"))
		goto bad;
	if (cleanup_action(state.db, "DELETE FROM hoard.refs WHERE parcel "
				"NOT IN (SELECT parcel FROM hoard.parcels)",
				"refs with dangling parcel ID"))
		goto bad;
	if (cleanup_action(state.db, "DELETE FROM hoard.refs WHERE tag NOT IN "
				"(SELECT tag FROM hoard.chunks)",
				"refs with dangling tag"))
		goto bad;
	if (cleanup_action(state.db, "UPDATE hoard.chunks SET referenced = 0 "
				"WHERE referenced == 1 AND tag NOTNULL AND "
				"tag NOT IN (SELECT tag FROM hoard.refs)",
				"chunks with spurious referenced flag"))
		goto bad;
	if (cleanup_action(state.db, "UPDATE hoard.chunks SET referenced = 1 "
				"WHERE referenced == 0 AND tag NOTNULL AND "
				"tag IN (SELECT tag FROM hoard.refs)",
				"chunks with missing referenced flag"))
		goto bad;

	/* XXX validate offsets and offset/length pairs */
	if (commit(state.db))
		return 1;
	/* XXX validate data */
	/* XXX gc */
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
