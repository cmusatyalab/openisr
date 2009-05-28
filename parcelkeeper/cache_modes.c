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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "defs.h"

static pk_err_t make_upload_dirs(void)
{
	gchar *path;
	unsigned dir;
	unsigned numdirs;

	if (!g_file_test(config.dest_dir, G_FILE_TEST_IS_DIR) &&
				mkdir(config.dest_dir, 0700)) {
		pk_log(LOG_ERROR, "Unable to make directory %s",
					config.dest_dir);
		return PK_IOERR;
	}
	numdirs = (parcel.chunks + parcel.chunks_per_dir - 1) /
				parcel.chunks_per_dir;
	for (dir=0; dir < numdirs; dir++) {
		path = g_strdup_printf("%s/%.4d", config.dest_dir, dir);
		if (!g_file_test(path, G_FILE_TEST_IS_DIR) &&
					mkdir(path, 0700)) {
			pk_log(LOG_ERROR, "Unable to make directory %s", path);
			free(path);
			return PK_IOERR;
		}
		g_free(path);
	}
	return PK_SUCCESS;
}

int copy_for_upload(void)
{
	struct query *qry;
	void *buf;
	unsigned chunk;
	void *tag;
	unsigned taglen;
	unsigned length;
	char calctag[parcel.hashlen];
	gchar *path;
	int fd;
	unsigned modified_chunks;
	off64_t modified_bytes;
	int64_t total_modified_bytes;
	int ret=1;

	if (cache_test_flag(CA_F_DAMAGED)) {
		pk_log(LOG_WARNING, "Local cache marked as damaged; "
					"upload disallowed");
		return 1;
	}
	if (cache_test_flag(CA_F_DIRTY)) {
		pk_log(LOG_WARNING, "Local cache marked as dirty");
		pk_log(LOG_WARNING, "Will not upload until the cache has "
					"been validated");
		return 1;
	}

	pk_log(LOG_INFO, "Copying chunks to upload directory %s",
				config.dest_dir);
	if (make_upload_dirs())
		return 1;
	printf("Updating hoard cache...\n");
	if (hoard_sync_refs(1))
		return 1;
	printf("Vacuuming keyring...\n");
	if (vacuum(state.db))
		return 1;
	buf=g_malloc(parcel.chunksize);

	printf("Collecting modified disk state...\n");
again:
	modified_chunks=0;
	modified_bytes=0;
	if (begin(state.db)) {
		g_free(buf);
		return 1;
	}
	if (query(NULL, state.db, "CREATE TEMP TABLE to_upload AS "
				"SELECT main.keys.chunk AS chunk, "
				"main.keys.tag AS tag, "
				"cache.chunks.length AS length FROM "
				"main.keys JOIN prev.keys ON "
				"main.keys.chunk == prev.keys.chunk "
				"LEFT JOIN cache.chunks ON "
				"main.keys.chunk == cache.chunks.chunk WHERE "
				"main.keys.tag != prev.keys.tag", NULL)) {
		pk_log_sqlerr(state.db, "Couldn't enumerate modified chunks");
		goto bad;
	}
	query(&qry, state.db, "SELECT sum(length) FROM temp.to_upload", NULL);
	if (!query_has_row(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't find size of modified "
					"chunks");
		goto bad;
	}
	query_row(qry, "D", &total_modified_bytes);
	query_free(qry);
	for (query(&qry, state.db, "SELECT chunk, tag, length FROM "
				"temp.to_upload", NULL);
				query_has_row(state.db); query_next(qry)) {
		query_row(qry, "dbd", &chunk, &tag, &taglen, &length);
		print_progress_mb(modified_bytes, total_modified_bytes);
		if (chunk > parcel.chunks) {
			pk_log(LOG_WARNING, "Chunk %u: greater than parcel "
						"size %u", chunk,
						parcel.chunks);
			goto damaged;
		}
		if (taglen != parcel.hashlen) {
			pk_log(LOG_WARNING, "Chunk %u: expected tag length "
						"%u, found %u", chunk,
						parcel.hashlen, taglen);
			goto damaged;
		}
		if (length == 0) {
			/* No cache index record */
			pk_log(LOG_WARNING, "Chunk %u: modified but not "
						"present", chunk);
			goto damaged;
		}
		if (length > parcel.chunksize) {
			pk_log(LOG_WARNING, "Chunk %u: absurd length %u",
						chunk, length);
			goto damaged;
		}
		if (pread(state.cache_fd, buf, length,
					cache_chunk_to_offset(chunk))
					!= (int)length) {
			pk_log(LOG_ERROR, "Couldn't read chunk from "
						"local cache: %u", chunk);
			goto out;
		}
		digest(parcel.crypto, calctag, buf, length);
		if (memcmp(tag, calctag, parcel.hashlen)) {
			pk_log(LOG_WARNING, "Chunk %u: tag mismatch.  "
					"Data corruption has occurred", chunk);
			log_tag_mismatch(tag, calctag, parcel.hashlen);
			goto damaged;
		}
		path=form_chunk_path(config.dest_dir, chunk);
		fd=open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
		if (fd == -1) {
			pk_log(LOG_ERROR, "Couldn't open chunk file %s", path);
			g_free(path);
			goto out;
		}
		if (write(fd, buf, length) != (int)length) {
			pk_log(LOG_ERROR, "Couldn't write chunk file %s",
						path);
			g_free(path);
			goto out;
		}
		if (close(fd) && errno != EINTR) {
			pk_log(LOG_ERROR, "Couldn't write chunk file %s",
						path);
			g_free(path);
			goto out;
		}
		g_free(path);
		hoard_put_chunk(tag, buf, length);
		modified_chunks++;
		modified_bytes += length;
	}
	if (!query_ok(state.db))
		pk_log_sqlerr(state.db, "Database query failed");
	else
		ret=0;
out:
	query_free(qry);
bad:
	rollback(state.db);
	if (query_retry(state.db))
		goto again;
	g_free(buf);
	if (ret == 0)
		pk_log(LOG_STATS, "Copied %u modified chunks, %llu bytes",
					modified_chunks,
					(unsigned long long) modified_bytes);
	return ret;

damaged:
	cache_set_flag(CA_F_DAMAGED);
	goto out;
}

static pk_err_t validate_keyring(void)
{
	struct query *qry;
	unsigned expected_chunk;
	unsigned chunk;
	unsigned taglen;
	unsigned keylen;
	unsigned compress;
	pk_err_t ret;

again:
	expected_chunk=0;
	ret=PK_SUCCESS;
	for (query(&qry, state.db, "SELECT chunk, tag, key, compression "
				"FROM keys ORDER BY chunk ASC", NULL);
				query_has_row(state.db); query_next(qry)) {
		query_row(qry, "dnnd", &chunk, &taglen, &keylen, &compress);
		if (chunk >= parcel.chunks) {
			pk_log(LOG_WARNING, "Found keyring entry %u greater "
						"than parcel size %u", chunk,
						parcel.chunks);
			ret=PK_INVALID;
			continue;
		}
		if (chunk < expected_chunk) {
			pk_log(LOG_WARNING, "Found unexpected keyring entry "
						"for chunk %u", chunk);
			ret=PK_INVALID;
			continue;
		}
		while (expected_chunk < chunk) {
			pk_log(LOG_WARNING, "Missing keyring entry for chunk "
						"%u", expected_chunk);
			ret=PK_INVALID;
			expected_chunk++;
		}
		expected_chunk++;
		if (taglen != parcel.hashlen) {
			pk_log(LOG_WARNING, "Chunk %u: expected tag length "
						"%u, found %u", chunk,
						parcel.hashlen, taglen);
			ret=PK_INVALID;
		}
		if (keylen != parcel.hashlen) {
			pk_log(LOG_WARNING, "Chunk %u: expected key length "
						"%u, found %u", chunk,
						parcel.hashlen, keylen);
			ret=PK_INVALID;
		}
		if (!compress_is_valid(compress)) {
			pk_log(LOG_WARNING, "Chunk %u: invalid or unsupported "
						"compression type %u", chunk,
						compress);
			ret=PK_INVALID;
		}
	}
	query_free(qry);
	if (query_retry(state.db))
		goto again;
	if (!query_ok(state.db)) {
		pk_log_sqlerr(state.db, "Keyring query failed");
		ret=PK_IOERR;
	}
	return ret;
}

/* Must be within transaction */
static pk_err_t revert_chunk(int chunk)
{
	pk_log(LOG_WARNING, "Reverting chunk %d", chunk);
	if (query(NULL, state.db, "INSERT OR REPLACE INTO main.keys "
				"(chunk, tag, key, compression) "
				"SELECT chunk, tag, key, compression FROM "
				"prev.keys WHERE chunk == ?", "d", chunk)) {
		pk_log_sqlerr(state.db, "Couldn't revert keyring entry for "
					"chunk %d", chunk);
		return PK_IOERR;
	}
	if (query(NULL, state.db, "DELETE FROM cache.chunks WHERE chunk == ?",
				"d", chunk)) {
		pk_log_sqlerr(state.db, "Couldn't delete cache entry for "
					"chunk %d", chunk);
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

static pk_err_t validate_cachefile(void)
{
	struct query *qry;
	void *buf;
	void *tag;
	char calctag[parcel.hashlen];
	unsigned chunk;
	unsigned taglen;
	unsigned chunklen;
	int64_t processed_bytes;
	int64_t valid_bytes;
	pk_err_t ret;
	pk_err_t ret2;

	buf=g_malloc(parcel.chunksize);

again:
	processed_bytes=0;
	ret=PK_SUCCESS;
	if (begin(state.db))
		return PK_IOERR;
	query(&qry, state.db, "SELECT sum(length) FROM cache.chunks", NULL);
	if (!query_has_row(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't get total size of valid "
					"chunks");
		ret=PK_IOERR;
		goto bad;
	}
	query_row(qry, "D", &valid_bytes);
	query_free(qry);

	for (query(&qry, state.db, "SELECT main.keys.chunk FROM "
				"main.keys JOIN prev.keys ON "
				"main.keys.chunk == prev.keys.chunk "
				"LEFT JOIN cache.chunks ON "
				"main.keys.chunk == cache.chunks.chunk "
				"WHERE main.keys.tag != prev.keys.tag AND "
				"cache.chunks.chunk ISNULL", NULL);
				query_has_row(state.db); query_next(qry)) {
		query_row(qry, "d", &chunk);
		pk_log(LOG_WARNING, "Chunk %u: modified but not present",
					chunk);
		ret=PK_INVALID;
	}
	query_free(qry);
	if (!query_ok(state.db)) {
		pk_log_sqlerr(state.db, "Error checking modified chunks");
		ret=PK_IOERR;
		goto bad;
	}

	for (query(&qry, state.db, "SELECT cache.chunks.chunk, "
				"cache.chunks.length, keys.tag FROM "
				"cache.chunks LEFT JOIN keys ON "
				"cache.chunks.chunk == keys.chunk", NULL);
				query_has_row(state.db); query_next(qry)) {
		query_row(qry, "ddb", &chunk, &chunklen, &tag, &taglen);
		processed_bytes += chunklen;
		print_progress_mb(processed_bytes, valid_bytes);

		if (chunk > parcel.chunks) {
			pk_log(LOG_WARNING, "Found chunk %u greater than "
						"parcel size %u", chunk,
						parcel.chunks);
			ret=PK_INVALID;
			continue;
		}
		if (chunklen > parcel.chunksize || chunklen == 0) {
			pk_log(LOG_WARNING, "Chunk %u: absurd size %u",
						chunk, chunklen);
			ret=PK_INVALID;
			continue;
		}
		if (tag == NULL) {
			pk_log(LOG_WARNING, "Found valid chunk %u with no "
						"keyring entry", chunk);
			ret=PK_INVALID;
			continue;
		}
		if (taglen != parcel.hashlen) {
			pk_log(LOG_WARNING, "Chunk %u: expected tag length "
						"%u, found %u", chunk,
						parcel.hashlen, taglen);
			ret=PK_INVALID;
			continue;
		}

		if (config.flags & WANT_FULL_CHECK) {
			if (pread(state.cache_fd, buf, chunklen,
						cache_chunk_to_offset(chunk))
						!= (int)chunklen) {
				pk_log(LOG_ERROR, "Chunk %u: couldn't read "
							"from local cache",
							chunk);
				ret=PK_IOERR;
				continue;
			}
			digest(parcel.crypto, calctag, buf, chunklen);
			if (memcmp(tag, calctag, taglen)) {
				pk_log(LOG_WARNING, "Chunk %u: tag check "
							"failure", chunk);
				log_tag_mismatch(tag, calctag, taglen);
				if (config.flags & WANT_SPLICE) {
					ret=revert_chunk(chunk);
					if (ret)
						goto bad;
				}
				ret=PK_TAGFAIL;
			}
		}
	}
	query_free(qry);
	if (!query_ok(state.db)) {
		pk_log_sqlerr(state.db, "Error querying cache index");
		ret=PK_IOERR;
		goto bad;
	}
	ret2=commit(state.db);
	if (ret2) {
		ret=ret2;
		goto bad;
	}
	g_free(buf);
	return ret;

bad:
	rollback(state.db);
	if (query_retry(state.db))
		goto again;
	g_free(buf);
	return ret;
}

int validate_cache(void)
{
	int ret=0;
	pk_err_t err;

	if (config.flags & WANT_CHECK) {
		/* Don't actually do any validation; just see where we are */
		if (cache_test_flag(CA_F_DIRTY))
			ret |= 2;
		if (cache_test_flag(CA_F_DAMAGED))
			ret |= 4;
		return ret;
	}

	pk_log(LOG_INFO, "Validating databases");
	printf("Validating databases...\n");
	err=validate_db(state.db);
	if (err)
		goto bad;

	pk_log(LOG_INFO, "Validating keyring");
	printf("Validating keyring...\n");
	err=validate_keyring();
	if (err)
		goto bad;

	pk_log(LOG_INFO, "Checking cache consistency");
	printf("Checking local cache for internal consistency...\n");
	err=validate_cachefile();
	if (err)
		goto bad;

	if (cache_test_flag(CA_F_DIRTY)) {
		if (config.flags & WANT_FULL_CHECK) {
			cache_clear_flag(CA_F_DIRTY);
		} else {
			pk_log(LOG_INFO, "Not clearing dirty flag: full check "
						"not requested");
			printf("Not clearing dirty flag: full check "
						"not requested\n");
		}
	}
	return 0;

bad:
	if (err == PK_BADFORMAT || err == PK_INVALID || err == PK_TAGFAIL) {
		if (cache_set_flag(CA_F_DAMAGED) == PK_SUCCESS)
			cache_clear_flag(CA_F_DIRTY);
	}
	return 1;
}

int examine_cache(void)
{
	struct query *qry;
	unsigned validchunks;
	unsigned dirtychunks;
	unsigned max_mb;
	unsigned valid_mb;
	unsigned dirty_mb;
	unsigned valid_pct;
	unsigned dirty_pct;

again:
	if (begin(state.db))
		return 1;
	query(&qry, state.db, "SELECT count(*) from cache.chunks", NULL);
	if (!query_has_row(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't query cache index");
		goto bad;
	}
	query_row(qry, "d", &validchunks);
	query_free(qry);
	query(&qry, state.db, "SELECT count(*) FROM main.keys "
				"JOIN prev.keys ON "
				"main.keys.chunk == prev.keys.chunk WHERE "
				"main.keys.tag != prev.keys.tag", NULL);
	if (!query_has_row(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't compare keyrings");
		goto bad;
	}
	query_row(qry, "d", &dirtychunks);
	query_free(qry);
	/* We didn't make any changes; we just need to release the locks */
	rollback(state.db);

	max_mb=(((off64_t)parcel.chunks) * parcel.chunksize) >> 20;
	valid_mb=(((off64_t)validchunks) * parcel.chunksize) >> 20;
	dirty_mb=(((off64_t)dirtychunks) * parcel.chunksize) >> 20;
	valid_pct=(100 * validchunks) / parcel.chunks;
	if (validchunks)
		dirty_pct=(100 * dirtychunks) / validchunks;
	else
		dirty_pct=0;
	printf("Local cache : %u%% populated (%u/%u MB), %u%% modified "
				"(%u/%u MB)\n", valid_pct, valid_mb, max_mb,
				dirty_pct, dirty_mb, valid_mb);
	return 0;

bad:
	rollback(state.db);
	if (query_retry(state.db))
		goto again;
	return 1;
}
