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
	char *path;
	unsigned dir;
	unsigned numdirs;

	if (!is_dir(config.dest_dir) && mkdir(config.dest_dir, 0700)) {
		pk_log(LOG_ERROR, "Unable to make directory %s",
					config.dest_dir);
		return PK_IOERR;
	}
	numdirs = (parcel.chunks + parcel.chunks_per_dir - 1) /
				parcel.chunks_per_dir;
	for (dir=0; dir < numdirs; dir++) {
		if (asprintf(&path, "%s/%.4d", config.dest_dir, dir) == -1) {
			pk_log(LOG_ERROR, "malloc failure");
			return PK_NOMEM;
		}
		if (!is_dir(path) && mkdir(path, 0700)) {
			pk_log(LOG_ERROR, "Unable to make directory %s", path);
			free(path);
			return PK_IOERR;
		}
		free(path);
	}
	return PK_SUCCESS;
}

static pk_err_t write_upload_stats(unsigned chunks, off64_t bytes)
{
	FILE *fp;

	fp=fopen(config.dest_stats, "w");
	if (fp == NULL) {
		pk_log(LOG_ERROR, "Couldn't open stats file %s",
					config.dest_stats);
		return PK_IOERR;
	}
	fprintf(fp, "%u\n%llu\n", chunks, bytes);
	fclose(fp);
	pk_log(LOG_STATS, "Copied %u modified chunks, %llu bytes",
				chunks, bytes);
	return PK_SUCCESS;
}

int copy_for_upload(void)
{
	sqlite3_stmt *stmt;
	char *buf;
	unsigned chunk;
	void *tag;
	unsigned taglen;
	unsigned length;
	char calctag[parcel.hashlen];
	char *path;
	int fd;
	unsigned modified_chunks=0;
	off64_t modified_bytes=0;
	unsigned total_modified;
	int sret;
	int ret=1;

	pk_log(LOG_INFO, "Copying chunks to upload directory %s",
				config.dest_dir);
	if (make_upload_dirs())
		return 1;
	if (hoard_sync_refs(1))
		return 1;
	if (begin(state.db))
		return 1;
	if (query(&stmt, state.db, "SELECT count(*) FROM "
				"main.keys JOIN prev.keys "
				"ON main.keys.chunk == prev.keys.chunk "
				"WHERE main.keys.tag != prev.keys.tag", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Query failed");
		rollback(state.db);
		return 1;
	}
	query_row(stmt, "d", &total_modified);
	query_free(stmt);
	buf=malloc(parcel.chunksize);
	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failed");
		rollback(state.db);
		return 1;
	}
	for (sret=query(&stmt, state.db, "SELECT main.keys.chunk, "
				"main.keys.tag, cache.chunks.length FROM "
				"main.keys JOIN prev.keys ON "
				"main.keys.chunk == prev.keys.chunk "
				"LEFT JOIN cache.chunks ON "
				"main.keys.chunk == cache.chunks.chunk WHERE "
				"main.keys.tag != prev.keys.tag", NULL);
				sret == SQLITE_ROW; sret=query_next(stmt)) {
		query_row(stmt, "dbd", &chunk, &tag, &taglen, &length);
		print_progress(modified_chunks, total_modified);
		if (chunk > parcel.chunks) {
			pk_log(LOG_ERROR, "Chunk %u: greater than parcel size "
						"%u", chunk, parcel.chunks);
			goto out;
		}
		if (taglen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected tag length %u, "
						"found %u", parcel.hashlen,
						taglen);
			goto out;
		}
		if (length == 0) {
			/* No cache index record */
			pk_log(LOG_ERROR, "Chunk %u: modified but not present",
						chunk);
			goto out;
		}
		if (length > parcel.chunksize) {
			pk_log(LOG_ERROR, "Chunk %u: absurd length %u", chunk,
						length);
			goto out;
		}
		if (pread(state.cache_fd, buf, length,
					cache_chunk_to_offset(chunk))
					!= (int)length) {
			pk_log(LOG_ERROR, "Couldn't read chunk from "
						"local cache: %u", chunk);
			goto out;
		}
		digest(calctag, buf, length);
		if (memcmp(tag, calctag, parcel.hashlen)) {
			pk_log(LOG_ERROR, "Chunk %u: tag mismatch.  "
					"Data corruption has occurred", chunk);
			log_tag_mismatch(tag, calctag);
			goto out;
		}
		path=form_chunk_path(config.dest_dir, chunk);
		if (path == NULL) {
			pk_log(LOG_ERROR, "malloc failure");
			goto out;
		}
		fd=open(path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
		if (fd == -1) {
			pk_log(LOG_ERROR, "Couldn't open chunk file %s", path);
			free(path);
			goto out;
		}
		if (write(fd, buf, length) != (int)length) {
			pk_log(LOG_ERROR, "Couldn't write chunk file %s",
						path);
			free(path);
			goto out;
		}
		if (close(fd) && errno != EINTR) {
			pk_log(LOG_ERROR, "Couldn't write chunk file %s",
						path);
			free(path);
			goto out;
		}
		free(path);
		hoard_put_chunk(tag, buf, length);
		modified_chunks++;
		modified_bytes += length;
	}
	if (sret != SQLITE_OK)
		pk_log(LOG_ERROR, "Database query failed");
	else
		ret=0;
out:
	free(buf);
	query_free(stmt);
	/* We didn't make any changes; we just need to release the locks */
	rollback(state.db);
	if (ret == 0)
		if (write_upload_stats(modified_chunks, modified_bytes))
			ret=1;
	return ret;
}

static pk_err_t validate_keyring(void)
{
	sqlite3_stmt *stmt;
	unsigned expected_chunk=0;
	unsigned chunk;
	unsigned taglen;
	unsigned keylen;
	unsigned compress;
	int sret;
	pk_err_t ret=PK_SUCCESS;

	for (sret=query(&stmt, state.db, "SELECT chunk, tag, key, compression "
				"FROM keys ORDER BY chunk ASC", NULL);
				sret == SQLITE_ROW; sret=query_next(stmt)) {
		query_row(stmt, "dnnd", &chunk, &taglen, &keylen, &compress);
		if (chunk >= parcel.chunks) {
			pk_log(LOG_ERROR, "Found keyring entry %u greater than"
						" parcel size %u", chunk,
						parcel.chunks);
			ret=PK_INVALID;
			continue;
		}
		if (chunk < expected_chunk) {
			pk_log(LOG_ERROR, "Found unexpected keyring entry for "
						"chunk %u", chunk);
			ret=PK_INVALID;
			continue;
		}
		while (expected_chunk < chunk) {
			pk_log(LOG_ERROR, "Missing keyring entry for chunk %u",
						expected_chunk);
			ret=PK_INVALID;
			expected_chunk++;
		}
		expected_chunk++;
		if (taglen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected tag length %u, "
						"found %u", chunk,
						parcel.hashlen, taglen);
			ret=PK_INVALID;
		}
		if (keylen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected key length %u, "
						"found %u", chunk,
						parcel.hashlen, keylen);
			ret=PK_INVALID;
		}
		if (!compress_is_valid(compress)) {
			pk_log(LOG_ERROR, "Chunk %u: invalid or unsupported "
						"compression type %u", chunk,
						compress);
			ret=PK_INVALID;
		}
	}
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Keyring query failed");
		ret=PK_IOERR;
	}
	query_free(stmt);
	return ret;
}

static pk_err_t validate_cachefile(void)
{
	sqlite3_stmt *stmt;
	void *buf;
	void *tag;
	char calctag[parcel.hashlen];
	unsigned chunk;
	unsigned taglen;
	unsigned chunklen;
	unsigned processed=0;
	unsigned valid;
	pk_err_t ret=PK_SUCCESS;
	int sret;

	if (begin(state.db))
		return PK_IOERR;
	if (query(&stmt, state.db, "SELECT count(*) FROM cache.chunks", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't enumerate valid chunks");
		rollback(state.db);
		return PK_IOERR;
	}
	query_row(stmt, "d", &valid);
	query_free(stmt);

	buf=malloc(parcel.chunksize);
	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failed");
		rollback(state.db);
		return PK_NOMEM;
	}

	for (sret=query(&stmt, state.db, "SELECT cache.chunks.chunk, "
				"cache.chunks.length, keys.tag FROM "
				"cache.chunks LEFT JOIN keys ON "
				"cache.chunks.chunk == keys.chunk", NULL);
				sret == SQLITE_ROW; sret=query_next(stmt)) {
		query_row(stmt, "ddb", &chunk, &chunklen, &tag, &taglen);
		print_progress(++processed, valid);

		if (chunk > parcel.chunks) {
			pk_log(LOG_ERROR, "Found chunk %u greater than "
						"parcel size %u", chunk,
						parcel.chunks);
			ret=PK_INVALID;
			continue;
		}
		if (chunklen > parcel.chunksize || chunklen == 0) {
			pk_log(LOG_ERROR, "Chunk %u: absurd size %u",
						chunk, chunklen);
			ret=PK_INVALID;
			continue;
		}
		if (tag == NULL) {
			pk_log(LOG_ERROR, "Found valid chunk %u with no "
						"keyring entry", chunk);
			ret=PK_INVALID;
			continue;
		}
		if (taglen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected tag length "
						"%u, found %u", chunk,
						parcel.hashlen, taglen);
			ret=PK_INVALID;
			continue;
		}

		if (pread(state.cache_fd, buf, chunklen,
					cache_chunk_to_offset(chunk)) !=
					(int)chunklen) {
			pk_log(LOG_ERROR, "Chunk %u: couldn't read from "
						"local cache", chunk);
			ret=PK_IOERR;
			continue;
		}
		digest(calctag, buf, chunklen);
		if (memcmp(tag, calctag, taglen)) {
			pk_log(LOG_ERROR, "Chunk %u: tag check failure",
						chunk);
			log_tag_mismatch(tag, calctag);
			ret=PK_TAGFAIL;
		}
	}
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Error querying cache index");
		ret=PK_IOERR;
	}
	query_free(stmt);
	free(buf);
	/* We didn't make any changes; we just need to release the locks */
	rollback(state.db);
	return ret;
}

int validate_cache(void)
{
	pk_log(LOG_INFO, "Validating databases");
	printf("Validating databases...\n");
	if (validate_db(state.db))
		return 1;
	pk_log(LOG_INFO, "Validating keyring");
	printf("Validating keyring...\n");
	if (validate_keyring())
		return 1;
	pk_log(LOG_INFO, "Checking cache consistency");
	printf("Checking local cache for internal consistency...\n");
	if (validate_cachefile())
		return 1;
	return 0;
}

int examine_cache(void)
{
	sqlite3_stmt *stmt;
	unsigned validchunks;
	unsigned dirtychunks;
	unsigned max_mb;
	unsigned valid_mb;
	unsigned dirty_mb;
	unsigned valid_pct;
	unsigned dirty_pct=0;

	if (begin(state.db))
		return 1;
	if (query(&stmt, state.db, "SELECT count(*) from cache.chunks", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query cache index");
		rollback(state.db);
		return 1;
	}
	query_row(stmt, "d", &validchunks);
	query_free(stmt);
	if (query(&stmt, state.db, "SELECT count(*) FROM main.keys "
				"JOIN prev.keys ON "
				"main.keys.chunk == prev.keys.chunk WHERE "
				"main.keys.tag != prev.keys.tag", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't compare keyrings");
		rollback(state.db);
		return 1;
	}
	query_row(stmt, "d", &dirtychunks);
	query_free(stmt);
	/* We didn't make any changes; we just need to release the locks */
	rollback(state.db);

	max_mb=(((off64_t)parcel.chunks) * parcel.chunksize) >> 20;
	valid_mb=(((off64_t)validchunks) * parcel.chunksize) >> 20;
	dirty_mb=(((off64_t)dirtychunks) * parcel.chunksize) >> 20;
	valid_pct=(100 * validchunks) / parcel.chunks;
	if (validchunks)
		dirty_pct=(100 * dirtychunks) / validchunks;
	printf("Local cache : %u%% populated (%u/%u MB), %u%% modified "
				"(%u/%u MB)\n", valid_pct, valid_mb, max_mb,
				dirty_pct, dirty_mb, valid_mb);
	return 0;
}
