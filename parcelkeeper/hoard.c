/*
 * Parcelkeeper - support daemon for the OpenISR (R) system virtual disk
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "defs.h"

#define HOARD_INDEX_VERSION 7
#define EXPAND_CHUNKS 256

/* Generator for an transaction wrapper around a function which expects to be
   called within a state->hoard transaction.  The wrapper discards errors
   and must be defined to return void. */
#define TRANSACTION_WRAPPER				\
TRANSACTION_DECL					\
{							\
	gboolean retry;					\
again:							\
	if (!begin(state->hoard))			\
		return;					\
	if (TRANSACTION_CALL) {				\
		retry = query_busy(state->hoard);	\
		rollback(state->hoard);			\
		if (retry) {				\
			query_backoff(state->hoard);	\
			goto again;			\
		}					\
		return;					\
	}						\
	if (!commit(state->hoard))			\
		rollback(state->hoard);			\
}

static pk_err_t create_hoard_index(struct pk_state *state)
{
	/* XXX auto_vacuum */
	if (query(NULL, state->hoard, "PRAGMA user_version = "
				G_STRINGIFY(HOARD_INDEX_VERSION), NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't set schema version");
		return PK_IOERR;
	}

	if (query(NULL, state->hoard, "CREATE TABLE parcels ("
				"parcel INTEGER PRIMARY KEY NOT NULL, "
				"uuid TEXT UNIQUE NOT NULL, "
				"server TEXT NOT NULL, "
				"user TEXT NOT NULL, "
				"name TEXT NOT NULL)", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't create parcel table");
		return PK_IOERR;
	}

	if (query(NULL, state->hoard, "CREATE TABLE chunks ("
				"tag BLOB UNIQUE, "
				/* 512-byte sectors */
				"offset INTEGER UNIQUE NOT NULL, "
				"length INTEGER NOT NULL DEFAULT 0, "
				"crypto INTEGER NOT NULL DEFAULT 0, "
				"last_access INTEGER NOT NULL DEFAULT 0, "
				"referenced INTEGER NOT NULL DEFAULT 0)",
				NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't create chunk table");
		return PK_IOERR;
	}
	if (query(NULL, state->hoard, "CREATE INDEX chunks_lru ON "
				"chunks (referenced, last_access)", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't create chunk LRU index");
		return PK_IOERR;
	}

	if (query(NULL, state->hoard, "CREATE TABLE refs ("
				"parcel INTEGER NOT NULL, "
				"tag BLOB NOT NULL)", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't create reference table");
		return PK_IOERR;
	}
	if (query(NULL, state->hoard, "CREATE UNIQUE INDEX refs_constraint "
				"ON refs (parcel, tag)", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't create chunk LRU index");
		return PK_IOERR;
	}
	if (query(NULL, state->hoard, "CREATE INDEX refs_bytag ON refs "
				"(tag, parcel)", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't create chunk "
					"reverse index");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

static pk_err_t upgrade_hoard_index(struct pk_state *state, int ver)
{
	pk_log(LOG_INFO, "Upgrading hoard cache version %d to version %d",
				ver, HOARD_INDEX_VERSION);
	switch (ver) {
	default:
		pk_log(LOG_ERROR, "Unrecognized hoard cache version %d, "
					"bailing out", ver);
		return PK_BADFORMAT;
	case 5:
		if (query(NULL, state->hoard, "DROP INDEX chunks_lru", NULL)) {
			pk_log_sqlerr(state->hoard, "Couldn't drop old chunk "
						"LRU index");
			return PK_IOERR;
		}
		if (query(NULL, state->hoard, "CREATE INDEX chunks_lru ON "
					"chunks (referenced, last_access)",
					NULL)) {
			pk_log_sqlerr(state->hoard, "Couldn't create new "
						"chunk LRU index");
			return PK_IOERR;
		}
		/* Fall through */
	case 6:
		if (query(NULL, state->hoard, "CREATE INDEX refs_bytag ON refs "
					"(tag, parcel)", NULL)) {
			pk_log_sqlerr(state->hoard, "Couldn't create chunk "
						"reverse index");
			return PK_IOERR;
		}
	}
	if (query(NULL, state->hoard, "PRAGMA user_version = "
				G_STRINGIFY(HOARD_INDEX_VERSION), NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't update schema version");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

static pk_err_t create_slot_cache(struct pk_state *state)
{
	if (query(NULL, state->hoard, "CREATE TEMP TABLE slots ("
				"tag BLOB UNIQUE, "
				"offset INTEGER UNIQUE NOT NULL, "
				"length INTEGER NOT NULL DEFAULT 0, "
				"crypto INTEGER NOT NULL DEFAULT 0, "
				"last_access INTEGER NOT NULL DEFAULT 0)",
				NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't create slot cache");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

/* XXX cache chunks of different sizes */
/* must be within transaction */
static pk_err_t expand_slot_cache(struct pk_state *state)
{
	struct query *qry;
	int count;
	int start;
	int i;
	int step = state->parcel->chunksize >> 9;
	int hoarded=0;
	int needed=EXPAND_CHUNKS;
	int allowed;

	/* First, try to use existing unallocated slots */
	if (query(&qry, state->hoard, "INSERT OR IGNORE INTO temp.slots "
				"(offset) SELECT offset FROM chunks "
				"WHERE referenced == 0 AND tag ISNULL "
				"LIMIT ?", "d", needed)) {
		pk_log_sqlerr(state->hoard, "Error reclaiming hoard cache "
					"slots");
		return PK_IOERR;
	}
	query_row(qry, "d", &count);
	query_free(qry);
	needed -= count;

	/* Now try to reclaim existing, unreferenced chunks.  See how many
	   we're permitted to reclaim. */
	if (needed > 0 && state->conf->minsize > 0) {
		query(&qry, state->hoard, "SELECT count(tag) FROM chunks",
					NULL);
		if (!query_has_row(state->hoard)) {
			pk_log_sqlerr(state->hoard, "Error finding size of "
						"hoard cache");
			return PK_IOERR;
		}
		query_row(qry, "d", &hoarded);
		query_free(qry);
		/* XXX assumes 128 KB */
		allowed=MIN(hoarded - ((int)state->conf->minsize * 8), needed);
	} else {
		allowed=needed;
	}

	if (allowed > 0) {
		/* Try to reclaim LRU unreferenced chunks */
		if (query(&qry, state->hoard, "INSERT OR IGNORE INTO "
					"temp.slots (offset) "
					"SELECT offset FROM chunks "
					"WHERE referenced == 0 AND tag NOTNULL "
					"ORDER BY last_access LIMIT ?", "d",
					allowed)) {
			pk_log_sqlerr(state->hoard, "Error reclaiming hoard "
						"cache slots");
			return PK_IOERR;
		}
		query_row(qry, "d", &count);
		query_free(qry);
		needed -= count;
	}

	/* Now expand the hoard cache as necessary to meet our quota */
	if (needed > 0) {
		query(&qry, state->hoard, "SELECT count(*), max(offset) "
					"FROM chunks", NULL);
		if (!query_has_row(state->hoard)) {
			pk_log_sqlerr(state->hoard, "Couldn't find max hoard "
						"cache offset");
			return PK_IOERR;
		}
		query_row(qry, "dd", &count, &start);
		query_free(qry);
		if (count)
			start += step;
		for (i=0; i<needed; i++) {
			if (query(NULL, state->hoard, "INSERT INTO temp.slots "
						"(offset) VALUES (?)", "d",
						start + i * step)) {
				pk_log_sqlerr(state->hoard, "Couldn't add new "
							"offset %d to "
							"slot cache",
							start + i * step);
				return PK_IOERR;
			}
		}
		if (query(NULL, state->hoard, "INSERT OR IGNORE INTO chunks "
					"(offset) SELECT offset FROM "
					"temp.slots", NULL)) {
			pk_log_sqlerr(state->hoard, "Couldn't expand "
						"hoard cache");
			return PK_IOERR;
		}
	}

	/* Grab allocations for the slots we've chosen */
	if (query(NULL, state->hoard, "UPDATE chunks SET tag = NULL, "
				"length = 0, crypto = 0, last_access = 0, "
				"referenced = 1 WHERE offset IN "
				"(SELECT offset FROM temp.slots)", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't allocate chunk slots");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

/* must be within transaction */
static pk_err_t _flush_slot_cache(struct pk_state *state)
{
	struct query *qry;
	pk_err_t ret;
	void *tag;
	int taglen;
	int offset;
	int len;
	int crypto;
	int last_access;

	for (query(&qry, state->hoard, "SELECT tag, offset, length, crypto, "
				"last_access FROM temp.slots WHERE "
				"tag NOTNULL", NULL);
				query_has_row(state->hoard); query_next(qry)) {
		query_row(qry, "bdddd", &tag, &taglen, &offset, &len, &crypto,
					&last_access);
		query(NULL, state->hoard, "UPDATE chunks SET tag = ?, "
					"length = ?, crypto = ?, "
					"last_access = ?, referenced = 1 "
					"WHERE offset = ?", "bdddd", tag,
					taglen, len, crypto, last_access,
					offset);

		if (query_constrained(state->hoard)) {
			if (query(NULL, state->hoard, "UPDATE chunks "
						"SET referenced = 0 WHERE "
						"offset == ?", "d", offset)) {
				pk_log_sqlerr(state->hoard, "Couldn't release "
							"reference on offset "
							"%d", offset);
				ret=PK_IOERR;
				goto bad;
			}
		} else if (!query_has_row(state->hoard)) {
			pk_log_sqlerr(state->hoard, "Couldn't update chunks "
						"table for offset %d", offset);
			ret=PK_IOERR;
			goto bad;
		}
	}
	query_free(qry);
	if (!query_ok(state->hoard)) {
		pk_log_sqlerr(state->hoard, "Couldn't query slot cache");
		return PK_IOERR;
	}

	if (query(NULL, state->hoard, "INSERT OR IGNORE INTO refs (parcel, tag) "
				"SELECT ?, tag FROM temp.slots "
				"WHERE tag NOTNULL", "d", state->hoard_ident)) {
		pk_log_sqlerr(state->hoard, "Couldn't add chunk references");
		return PK_IOERR;
	}
	if (query(NULL, state->hoard, "UPDATE chunks SET referenced = 0 WHERE "
				"offset IN (SELECT offset FROM temp.slots "
				"WHERE tag ISNULL)", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't free unused cache slots");
		return PK_IOERR;
	}
	if (query(NULL, state->hoard, "DELETE FROM temp.slots", NULL)) {
		pk_log_sqlerr(state->hoard, "Couldn't clear slot cache");
		return PK_IOERR;
	}
	return PK_SUCCESS;

bad:
	query_free(qry);
	return ret;
}

#define TRANSACTION_DECL	static void flush_slot_cache( \
						struct pk_state *state)
#define TRANSACTION_CALL	_flush_slot_cache(state)
TRANSACTION_WRAPPER
#undef TRANSACTION_DECL
#undef TRANSACTION_CALL

/* must be within transaction */
static pk_err_t allocate_slot(struct pk_state *state, int *offset)
{
	struct query *qry;
	pk_err_t ret;

	while (1) {
		/* First, try to find an unused slot in the slot cache */
		query(&qry, state->hoard, "SELECT offset FROM temp.slots "
					"WHERE tag ISNULL LIMIT 1", NULL);
		if (query_has_row(state->hoard)) {
			query_row(qry, "d", offset);
			query_free(qry);
			break;
		} else if (!query_ok(state->hoard)) {
			pk_log_sqlerr(state->hoard, "Error finding unused "
						"hoard cache slot");
			return PK_IOERR;
		}

		/* There aren't any, so we have some work to do.  First,
		   flush the existing slot cache back to the chunks table. */
		ret=_flush_slot_cache(state);
		if (ret)
			return ret;

		/* Now populate the slot cache and try again. */
		ret=expand_slot_cache(state);
		if (ret)
			return ret;
	}
	return PK_SUCCESS;
}

static pk_err_t add_chunk_reference(struct pk_state *state, const void *tag)
{
	gchar *ftag;

	if (query(NULL, state->hoard, "INSERT OR IGNORE INTO refs "
				"(parcel, tag) VALUES (?, ?)", "db",
				state->hoard_ident, tag,
				state->parcel->hashlen)) {
		ftag=format_tag(tag, state->parcel->hashlen);
		pk_log_sqlerr(state->hoard, "Couldn't add chunk reference "
					"for tag %s", ftag);
		g_free(ftag);
		return PK_IOERR;
	}
	if (query(NULL, state->hoard, "UPDATE chunks SET referenced = 1 "
				" WHERE tag == ?", "b", tag,
				state->parcel->hashlen)) {
		ftag=format_tag(tag, state->parcel->hashlen);
		pk_log_sqlerr(state->hoard, "Couldn't set referenced flag "
					"for tag %s", ftag);
		g_free(ftag);
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
static pk_err_t _hoard_invalidate_chunk(struct pk_state *state, int offset,
			const void *tag, unsigned taglen)
{
	struct query *qry;
	char *ftag;

	query(&qry, state->hoard, "SELECT offset FROM chunks WHERE "
				"offset == ? AND tag == ?", "db",
				offset, tag, taglen);
	if (query_ok(state->hoard)) {
		/* Harmless: it's already not there.  But let's warn anyway. */
		ftag=format_tag(tag, taglen);
		pk_log(LOG_ERROR, "Attempted to invalidate tag %s at "
					"offset %d, but it does not exist "
					"(harmless)", ftag, offset);
		g_free(ftag);
		return PK_SUCCESS;
	} else if (!query_has_row(state->hoard)) {
		pk_log_sqlerr(state->hoard, "Could not query chunk list");
		return PK_IOERR;
	}
	query_free(qry);

	if (query(NULL, state->hoard, "UPDATE chunks SET tag = NULL, "
				"length = 0, crypto = 0, last_access = 0, "
				"referenced = 0 WHERE offset = ?", "d",
				offset)) {
		pk_log_sqlerr(state->hoard, "Couldn't deallocate hoard chunk "
					"at offset %d", offset);
		return PK_IOERR;
	}
	if (query(NULL, state->hoard, "DELETE FROM refs WHERE tag == ?", "b",
				tag, taglen)) {
		ftag=format_tag(tag, taglen);
		pk_log_sqlerr(state->hoard, "Couldn't invalidate references "
					"to tag %s", ftag);
		g_free(ftag);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

/* Same as _hoard_invalidate_chunk(), but for the slot cache.  We don't
   need to check that the row being deleted is still valid, since there's no
   contention for the slot cache. */
static pk_err_t _hoard_invalidate_slot_chunk(struct pk_state *state,
			int offset)
{
	if (query(NULL, state->hoard, "UPDATE temp.slots SET tag = NULL, "
				"length = 0, crypto = 0, last_access = 0 "
				"WHERE offset = ?", "d", offset)) {
		pk_log_sqlerr(state->hoard, "Couldn't deallocate hoard slot "
					"at offset %d", offset);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

#define TRANSACTION_DECL	void hoard_invalidate_chunk( \
					struct pk_state *state, int offset, \
					const void *tag, unsigned taglen)
#define TRANSACTION_CALL	_hoard_invalidate_chunk(state, offset, tag, \
					taglen)
TRANSACTION_WRAPPER
#undef TRANSACTION_DECL
#undef TRANSACTION_CALL

#define TRANSACTION_DECL	static void hoard_invalidate_slot_chunk( \
					struct pk_state *state, int offset)
#define TRANSACTION_CALL	_hoard_invalidate_slot_chunk(state, offset)
TRANSACTION_WRAPPER
#undef TRANSACTION_DECL
#undef TRANSACTION_CALL

pk_err_t hoard_get_chunk(struct pk_state *state, const void *tag, void *buf,
			unsigned *len)
{
	struct query *qry;
	char calctag[state->parcel->hashlen];
	int offset;
	int clen;
	pk_err_t ret;
	int slot_cache=0;
	const char *update_timestamp;
	gboolean retry;

	if (state->conf->hoard_dir == NULL)
		return PK_NOTFOUND;

again:
	if (!begin(state->hoard))
		return PK_IOERR;

	/* First query the slot cache */
	if (query(&qry, state->hoard, "SELECT offset, length FROM temp.slots "
				"WHERE tag == ?", "b", tag,
				state->parcel->hashlen)) {
		pk_log_sqlerr(state->hoard, "Couldn't query slot cache");
		ret=PK_IOERR;
		goto bad;
	}
	if (query_has_row(state->hoard)) {
		query_row(qry, "dd", &offset, &clen);
		query_free(qry);
		slot_cache=1;
		update_timestamp="UPDATE temp.slots SET last_access = ? "
					"WHERE tag == ?";
	} else {
		/* Now query the hoard cache */
		query(&qry, state->hoard, "SELECT offset, length FROM chunks "
					"WHERE tag == ?", "b", tag,
					state->parcel->hashlen);
		if (query_ok(state->hoard)) {
			if (!commit(state->hoard)) {
				ret=PK_IOERR;
				goto bad;
			}
			return PK_NOTFOUND;
		} else if (!query_has_row(state->hoard)) {
			pk_log_sqlerr(state->hoard, "Couldn't query hoard "
						"chunk index");
			ret=PK_IOERR;
			goto bad;
		}
		query_row(qry, "dd", &offset, &clen);
		query_free(qry);
		update_timestamp="UPDATE chunks SET last_access = ? "
					"WHERE tag == ?";
	}

	if (offset < 0 || clen <= 0 || (unsigned)clen >
				state->parcel->chunksize) {
		pk_log(LOG_ERROR, "Chunk has unreasonable offset/length "
					"%d/%d; invalidating", offset, clen);
		if (slot_cache)
			ret=_hoard_invalidate_slot_chunk(state, offset);
		else
			ret=_hoard_invalidate_chunk(state, offset, tag,
						state->parcel->hashlen);
		if (ret)
			goto bad;
		ret=PK_BADFORMAT;
		if (!commit(state->hoard))
			goto bad;
		return ret;
	}

	if (query(NULL, state->hoard, update_timestamp, "db", time(NULL), tag,
				state->parcel->hashlen)) {
		/* Not fatal, but if we got SQLITE_BUSY, retry anyway */
		pk_log_sqlerr(state->hoard, "Couldn't update chunk timestamp");
		ret=PK_SQLERR;
		if (query_busy(state->hoard))
			goto bad;
	}
	if (!slot_cache) {
		ret=add_chunk_reference(state, tag);
		if (ret)
			goto bad;
	}

	if (!commit(state->hoard)) {
		ret=PK_IOERR;
		goto bad;
	}

	if (pread(state->hoard_fd, buf, clen, ((off_t)offset) << 9) != clen) {
		pk_log(LOG_ERROR, "Couldn't read chunk at offset %d", offset);
		if (slot_cache)
			hoard_invalidate_slot_chunk(state, offset);
		else
			hoard_invalidate_chunk(state, offset, tag,
						state->parcel->hashlen);
		return PK_IOERR;
	}

	/* Make sure the stored hash matches the actual hash of the data.
	   If not, remove the chunk from the hoard cache.  If the reference
	   is released right now (e.g. by an rmhoard) and the chunk slot is
	   immediately reused, we'll find a hash mismatch, but we don't want
	   to blindly invalidate the slot because some other data has been
	   stored there in the interim.  Therefore, _hoard_invalidate_chunk()
	   checks that the tag/index pair is still present in the chunks
	   table before invalidating the slot.  If we're working from the
	   slot cache, this race does not apply. */

	ret=digest(state->parcel->crypto, calctag, buf, clen);
	if (ret)
		return ret;
	if (memcmp(tag, calctag, state->parcel->hashlen)) {
		pk_log(LOG_ERROR, "Tag mismatch reading hoard cache at "
					"offset %d", offset);
		log_tag_mismatch(tag, calctag, state->parcel->hashlen);
		if (slot_cache)
			hoard_invalidate_slot_chunk(state, offset);
		else
			hoard_invalidate_chunk(state, offset, tag,
						state->parcel->hashlen);
		return PK_TAGFAIL;
	}

	*len=clen;
	return PK_SUCCESS;

bad:
	retry = query_busy(state->hoard);
	rollback(state->hoard);
	if (retry) {
		query_backoff(state->hoard);
		goto again;
	}
	return ret;
}

pk_err_t hoard_put_chunk(struct pk_state *state, const void *tag,
			const void *buf, unsigned len)
{
	pk_err_t ret;
	int offset;
	gboolean retry;

	if (state->conf->hoard_dir == NULL)
		return PK_SUCCESS;

again:
	if (!begin(state->hoard))
		return PK_IOERR;

	/* See if the tag is already in the slot cache */
	query(NULL, state->hoard, "SELECT tag FROM temp.slots WHERE tag == ?",
				"b", tag, state->parcel->hashlen);
	if (query_has_row(state->hoard)) {
		if (!commit(state->hoard)) {
			ret=PK_IOERR;
			goto bad;
		}
		return PK_SUCCESS;
	} else if (!query_ok(state->hoard)) {
		pk_log_sqlerr(state->hoard, "Couldn't look up tag in "
					"slot cache");
		ret=PK_SQLERR;
		goto bad;
	}

	/* See if the tag is already in the hoard cache */
	query(NULL, state->hoard, "SELECT tag FROM chunks WHERE tag == ?",
				"b", tag, state->parcel->hashlen);
	if (query_has_row(state->hoard)) {
		ret=add_chunk_reference(state, tag);
		if (ret)
			goto bad;
		if (!commit(state->hoard)) {
			ret=PK_IOERR;
			goto bad;
		}
		return PK_SUCCESS;
	} else if (!query_ok(state->hoard)) {
		pk_log_sqlerr(state->hoard, "Couldn't look up tag in hoard "
					"cache index");
		ret=PK_SQLERR;
		goto bad;
	}

	ret=allocate_slot(state, &offset);
	if (ret)
		goto bad;
	if (query(NULL, state->hoard, "UPDATE temp.slots SET tag = ?, "
				"length = ?, crypto = ?, last_access = ? "
				"WHERE offset = ?", "bdddd", tag,
				state->parcel->hashlen, len,
				state->parcel->crypto, time(NULL), offset)) {
		pk_log_sqlerr(state->hoard, "Couldn't add metadata for hoard "
					"cache chunk");
		ret=PK_IOERR;
		goto bad;
	}

	if (pwrite(state->hoard_fd, buf, len, ((off_t)offset) << 9) !=
				(int)len) {
		pk_log(LOG_ERROR, "Couldn't write hoard cache: offset %d, "
					"length %d", offset, len);
		ret=PK_IOERR;
		goto bad;
	}

	if (!commit(state->hoard)) {
		pk_log(LOG_ERROR, "Couldn't commit hoard cache chunk");
		ret=PK_IOERR;
		goto bad;
	}
	return PK_SUCCESS;

bad:
	retry = query_busy(state->hoard);
	rollback(state->hoard);
	if (retry) {
		query_backoff(state->hoard);
		goto again;
	}
	return ret;
}

/* We use state->db rather than state->hoard in this function, since we need to
   compare to the previous or current keyring */
pk_err_t hoard_sync_refs(struct pk_state *state, gboolean from_cache)
{
	gboolean retry;

	if (state->conf->hoard_dir == NULL)
		return PK_SUCCESS;

again:
	if (!begin_immediate(state->db))
		return PK_IOERR;
	if (from_cache)
		query(NULL, state->db, "CREATE TEMP TABLE newrefs AS "
					"SELECT DISTINCT tag FROM keys", NULL);
	else
		query(NULL, state->db, "CREATE TEMP TABLE newrefs AS "
					"SELECT DISTINCT tag FROM prev.keys",
					NULL);
	if (!query_ok(state->db)) {
		pk_log_sqlerr(state->db, "Couldn't generate tag list");
		goto bad;
	}
	if (query(NULL, state->db, "CREATE INDEX temp.newrefs_tags ON "
				"newrefs (tag)", NULL)) {
		pk_log_sqlerr(state->db, "Couldn't create tag index");
		goto bad;
	}
	if (query(NULL, state->db, "UPDATE hoard.chunks SET referenced = 0 "
				"WHERE tag IN "
				"(SELECT tag FROM hoard.refs WHERE parcel == ? "
				"AND tag NOT IN (SELECT tag FROM temp.newrefs) "
				"AND tag NOT IN (SELECT tag FROM hoard.refs "
				"WHERE parcel != ?))", "dd", state->hoard_ident,
				state->hoard_ident)) {
		pk_log_sqlerr(state->db, "Couldn't garbage-collect referenced "
					"flags");
		goto bad;
	}
	if (query(NULL, state->db, "DELETE FROM hoard.refs WHERE parcel == ? "
				"AND tag NOT IN (SELECT tag FROM temp.newrefs)",
				"d", state->hoard_ident)) {
		pk_log_sqlerr(state->db, "Couldn't garbage-collect hoard refs");
		goto bad;
	}
	if (query(NULL, state->db, "INSERT OR IGNORE INTO hoard.refs "
				"(parcel, tag) SELECT ?, tag FROM temp.newrefs "
				"WHERE tag IN (SELECT tag FROM hoard.chunks)",
				"d", state->hoard_ident)) {
		pk_log_sqlerr(state->db, "Couldn't insert new hoard refs");
		goto bad;
	}
	if (query(NULL, state->db, "UPDATE hoard.chunks SET referenced = 1 "
				"WHERE referenced == 0 AND tag IN "
				"(SELECT tag FROM temp.newrefs)", NULL)) {
		pk_log_sqlerr(state->db, "Couldn't updated referenced flags");
		goto bad;
	}
	if (query(NULL, state->db, "DROP TABLE temp.newrefs", NULL)) {
		pk_log_sqlerr(state->db, "Couldn't drop temporary table");
		goto bad;
	}
	if (!commit(state->db))
		goto bad;
	return PK_SUCCESS;

bad:
	retry = query_busy(state->db);
	rollback(state->db);
	if (retry) {
		query_backoff(state->db);
		goto again;
	}
	return PK_IOERR;
}

static pk_err_t get_parcel_ident(struct pk_state *state)
{
	struct query *qry;
	gboolean retry;

again:
	if (!begin(state->hoard))
		return PK_IOERR;
	/* Add the row if it's not already there */
	if (query(NULL, state->hoard, "INSERT OR IGNORE INTO parcels "
				"(uuid, server, user, name) "
				"VALUES (?, ?, ?, ?)", "SSSS",
				state->parcel->uuid, state->parcel->server,
				state->parcel->user, state->parcel->parcel)) {
		pk_log_sqlerr(state->hoard, "Couldn't insert parcel record");
		goto bad;
	}
	/* Find out the parcel ID assigned by SQLite */
	query(&qry, state->hoard, "SELECT parcel FROM parcels WHERE uuid == ?",
				"S", state->parcel->uuid);
	if (!query_has_row(state->hoard)) {
		pk_log_sqlerr(state->hoard, "Couldn't query parcels table");
		goto bad;
	}
	query_row(qry, "d", &state->hoard_ident);
	query_free(qry);
	/* Make sure the row has current metadata in case it was already
	   present.  Don't promote the lock if no update is necessary. */
	if (query(NULL, state->hoard, "UPDATE parcels SET server = ?, "
				"user = ?, name = ? WHERE parcel == ? AND "
				"(server != ? OR user != ? OR name != ?)",
				"SSSdSSS", state->parcel->server,
				state->parcel->user, state->parcel->parcel,
				state->hoard_ident, state->parcel->server,
				state->parcel->user, state->parcel->parcel)) {
		pk_log_sqlerr(state->hoard, "Couldn't update parcel record");
		goto bad;
	}
	if (!commit(state->hoard))
		goto bad;
	return PK_SUCCESS;

bad:
	retry = query_busy(state->hoard);
	rollback(state->hoard);
	if (retry) {
		query_backoff(state->hoard);
		goto again;
	}
	return PK_IOERR;
}

static pk_err_t open_hoard_index(struct pk_state *state)
{
	struct query *qry;
	pk_err_t ret;
	int ver;
	gboolean retry;

	/* First open the dedicated hoard cache DB connection */
	ret=sql_conn_open(state->conf->hoard_index, &state->hoard);
	if (ret)
		return ret;

again:
	if (!begin(state->hoard)) {
		ret=PK_IOERR;
		goto bad;
	}
	query(&qry, state->hoard, "PRAGMA user_version", NULL);
	if (!query_has_row(state->hoard)) {
		pk_log_sqlerr(state->hoard, "Couldn't get hoard cache "
					"index version");
		ret=PK_IOERR;
		goto bad_rollback;
	}
	query_row(qry, "d", &ver);
	query_free(qry);
	if (ver == 0) {
		ret=create_hoard_index(state);
	} else if (ver < HOARD_INDEX_VERSION) {
		ret=upgrade_hoard_index(state, ver);
	} else if (ver > HOARD_INDEX_VERSION) {
		pk_log(LOG_ERROR, "Hoard cache version %d too new (expected "
					"%d)", ver, HOARD_INDEX_VERSION);
		ret=PK_BADFORMAT;
	}
	if (ret)
		goto bad_rollback;
	ret=create_slot_cache(state);
	if (ret)
		goto bad_rollback;
	if (!commit(state->hoard)) {
		ret=PK_IOERR;
		goto bad_rollback;
	}

	/* Now attach the hoard cache index to the primary DB connection
	   for cross-table queries */
	ret=attach(state->db, "hoard", state->conf->hoard_index);
	if (ret)
		goto bad;
	return PK_SUCCESS;

bad_rollback:
	retry = query_busy(state->hoard);
	rollback(state->hoard);
	if (retry) {
		query_backoff(state->hoard);
		goto again;
	}
bad:
	sql_conn_close(state->hoard);
	return ret;
}

/* Releases the hoard_fd lock before returning, including on error */
static pk_err_t hoard_try_cleanup(struct pk_state *state)
{
	struct query *qry;
	pk_err_t ret;
	int changes;
	int ident;
	gboolean retry;

	ret=get_file_lock(state->hoard_fd, FILE_LOCK_WRITE);
	if (ret == PK_BUSY) {
		pk_log(LOG_INFO, "Hoard cache in use; skipping cleanup");
		ret=PK_SUCCESS;
		goto out;
	} else if (ret) {
		goto out;
	}

	pk_log(LOG_INFO, "Cleaning up hoard cache...");
again:
	if (!begin(state->hoard)) {
		ret=PK_IOERR;
		goto out;
	}

	/* This was originally "DELETE FROM parcels WHERE parcel NOT IN
	   (SELECT DISTINCT parcel FROM refs)".  But the parcels table is
	   small and the refs table is large, and that query walked the entire
	   refs_constraint index.  Given the size of parcels table, the
	   below approach is much more efficient. */
	for (ret=query(&qry, state->hoard, "SELECT parcel FROM parcels", NULL),
				changes=0; query_has_row(state->hoard);
				ret=query_next(qry)) {
		query_row(qry, "d", &ident);
		ret=query(NULL, state->hoard, "SELECT parcel FROM refs WHERE "
					"parcel == ? LIMIT 1", "d", ident);
		if (ret) {
			pk_log_sqlerr(state->hoard, "Couldn't query refs table");
			query_free(qry);
			goto bad;
		}
		if (!query_has_row(state->hoard)) {
			ret=query(NULL, state->hoard, "DELETE FROM parcels "
						"WHERE parcel == ?", "d",
						ident);
			if (ret) {
				pk_log_sqlerr(state->hoard, "Couldn't delete "
						"unused parcel from hoard "
						"cache index");
				query_free(qry);
				goto bad;
			}
			changes++;
		}
	}
	query_free(qry);
	if (!query_ok(state->hoard)) {
		pk_log_sqlerr(state->hoard, "Couldn't query parcels table");
		goto bad;
	}
	if (changes > 0)
		pk_log(LOG_INFO, "Cleaned %d dangling parcel records",
					changes);

	ret=cleanup_action(state->hoard, "UPDATE chunks SET referenced = 0 "
				"WHERE referenced == 1 AND tag ISNULL",
				LOG_INFO, "orphaned cache slots");
	if (ret)
		goto bad;

	if (!commit(state->hoard)) {
		ret=PK_IOERR;
		goto bad;
	}
out:
	put_file_lock(state->hoard_fd);
	return ret;
bad:
	retry = query_busy(state->hoard);
	rollback(state->hoard);
	if (retry) {
		query_backoff(state->hoard);
		goto again;
	}
	goto out;
}

pk_err_t hoard_init(struct pk_state *state)
{
	pk_err_t ret;

	if (state->conf->hoard_dir == NULL)
		return PK_INVALID;
	if (state->parcel != NULL && state->parcel->chunksize != 131072) {
		pk_log(LOG_ERROR, "Hoard cache non-functional for chunk "
					"sizes != 128 KB");
		return PK_INVALID;
	}
	if (!g_file_test(state->conf->hoard_dir, G_FILE_TEST_IS_DIR) &&
				mkdir(state->conf->hoard_dir, 0777)) {
		pk_log(LOG_ERROR, "Couldn't create hoard directory %s",
					state->conf->hoard_dir);
		return PK_CALLFAIL;
	}

	state->hoard_fd=open(state->conf->hoard_file, O_RDWR|O_CREAT, 0666);
	if (state->hoard_fd == -1) {
		pk_log(LOG_ERROR, "Couldn't open %s", state->conf->hoard_file);
		return PK_IOERR;
	}
	ret=get_file_lock(state->hoard_fd, FILE_LOCK_READ|FILE_LOCK_WAIT);
	if (ret) {
		pk_log(LOG_ERROR, "Couldn't get read lock on %s",
					state->conf->hoard_file);
		goto bad;
	}

	ret=open_hoard_index(state);
	if (ret)
		goto bad;

	if (state->conf->parcel_dir != NULL) {
		ret=get_parcel_ident(state);
		if (ret)
			goto bad_close;
	}
	return PK_SUCCESS;

bad_close:
	sql_conn_close(state->hoard);
bad:
	close(state->hoard_fd);
	return ret;
}

void hoard_shutdown(struct pk_state *state)
{
	flush_slot_cache(state);
	hoard_try_cleanup(state);
	sql_conn_close(state->hoard);
	close(state->hoard_fd);
}
