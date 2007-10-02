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
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include "defs.h"

#define CA_MAGIC 0x51528038
#define CA_VERSION 1
#define CA_INDEX_VERSION 1

/* All u32's in network byte order */
struct ca_header {
	uint32_t magic;
	uint32_t entries;
	uint32_t offset;  /* beginning of data, in 512-byte blocks */
	uint32_t reserved_1[2];
	uint8_t version;
	uint8_t reserved_2[491];
};

static off64_t chunk_to_offset(unsigned chunk)
{
	return (off64_t)parcel.chunksize * chunk + state.offset;
}

static pk_err_t create_cache_file(long page_size)
{
	struct ca_header hdr = {0};
	int fd;

	fd=open(config.cache_file, O_CREAT|O_EXCL|O_RDWR, 0600);
	if (fd == -1) {
		pk_log(LOG_ERROR, "couldn't create cache file");
		return PK_IOERR;
	}
	/* There's a race condition in the way the loop driver
	   interacts with the memory management system for (at least)
	   underlying file systems that provide the prepare_write and
	   commit_write address space operations.  This can cause data
	   not to be properly written to disk if I/O submitted to the
	   loop driver spans multiple page-cache pages and is not
	   aligned on page cache boundaries.  We therefore need to
	   make sure that our header is a multiple of the page size.
	   We assume that the page size is at least sizeof(hdr) bytes. */
	state.offset=page_size;
	hdr.magic=htonl(CA_MAGIC);
	hdr.entries=htonl(parcel.chunks);
	hdr.offset=htonl(state.offset >> 9);
	hdr.version=CA_VERSION;
	if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		pk_log(LOG_ERROR, "Couldn't write cache file header");
		return PK_IOERR;
	}
	if (ftruncate(fd, chunk_to_offset(parcel.chunks))) {
		pk_log(LOG_ERROR, "couldn't extend cache file");
		return PK_IOERR;
	}

	pk_log(LOG_INFO, "Created cache file");
	state.cache_fd=fd;
	return PK_SUCCESS;
}

static pk_err_t open_cache_file(long page_size)
{
	struct ca_header hdr;
	int fd;

	fd=open(config.cache_file, O_RDWR);
	if (fd == -1) {
		pk_log(LOG_ERROR, "couldn't open cache file");
		return PK_IOERR;
	}
	if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		pk_log(LOG_ERROR, "Couldn't read cache file header");
		return PK_IOERR;
	}
	if (ntohl(hdr.magic) != CA_MAGIC) {
		pk_log(LOG_ERROR, "Invalid magic number reading cache file");
		return PK_BADFORMAT;
	}
	if (hdr.version != CA_VERSION) {
		pk_log(LOG_ERROR, "Invalid version reading cache file: "
					"expected %d, found %d", CA_VERSION,
					hdr.version);
		return PK_BADFORMAT;
	}
	if (ntohl(hdr.entries) != parcel.chunks) {
		pk_log(LOG_ERROR, "Invalid chunk count reading cache file: "
					"expected %u, found %u",
					parcel.chunks, ntohl(hdr.entries));
		return PK_BADFORMAT;
	}
	state.offset=ntohl(hdr.offset) << 9;
	if (state.offset % page_size != 0) {
		/* This may occur with old cache files, or with cache files
		   copied from another system with a different page size. */
		pk_log(LOG_ERROR, "Cache file's header length %u is not "
					"a multiple of the page size %u",
					state.offset, page_size);
		pk_log(LOG_ERROR, "Data corruption may occur.  If it does, "
					"checkin will be disallowed");
	}

	pk_log(LOG_INFO, "Read cache header");
	state.cache_fd=fd;
	return PK_SUCCESS;
}

static pk_err_t create_cache_index(void)
{
	if (query(NULL, state.db, "CREATE TABLE cache.chunks ("
				"chunk INTEGER PRIMARY KEY NOT NULL, "
				"length INTEGER NOT NULL)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create cache index");
		return PK_IOERR;
	}
	if (query(NULL, state.db, "PRAGMA cache.user_version = "
				stringify(CA_INDEX_VERSION), NULL)) {
		pk_log(LOG_ERROR, "Couldn't set cache index version");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

static pk_err_t verify_cache_index(void)
{
	sqlite3_stmt *stmt;
	int found;

	if (query(&stmt, state.db, "PRAGMA cache.user_version", NULL) !=
				SQLITE_ROW) {
		query_free(stmt);  /* in case the query produced no rows */
		pk_log(LOG_ERROR, "Couldn't query cache index version");
		return PK_IOERR;
	}
	query_row(stmt, "d", &found);
	query_free(stmt);
	if (found != CA_INDEX_VERSION) {
		pk_log(LOG_ERROR, "Invalid version reading cache index: "
					"expected %d, found %d",
					CA_INDEX_VERSION, found);
		return PK_BADFORMAT;
	}
	return PK_SUCCESS;
}

void cache_shutdown(void)
{
	if (state.cache_fd)
		close(state.cache_fd);
	if (state.db && sqlite3_close(state.db))
		pk_log(LOG_ERROR, "Couldn't close keyring: %s",
					sqlite3_errmsg(state.db));
}

static pk_err_t open_cachedir(long page_size)
{
	pk_err_t ret;

	if (sqlite3_open(config.keyring, &state.db)) {
		pk_log(LOG_ERROR, "Couldn't open keyring %s: %s",
					config.keyring,
					sqlite3_errmsg(state.db));
		return PK_IOERR;
	}
	if (is_file(config.cache_file) && is_file(config.cache_index)) {
		ret=attach(state.db, "cache", config.cache_index);
		if (ret)
			return ret;
		ret=open_cache_file(page_size);
		if (ret)
			return ret;
		ret=verify_cache_index();
		if (ret)
			return ret;
	} else if (!is_file(config.cache_file) &&
				!is_file(config.cache_index)) {
		ret=attach(state.db, "cache", config.cache_index);
		if (ret)
			return ret;
		ret=create_cache_file(page_size);
		if (ret)
			return ret;
		ret=create_cache_index();
		if (ret)
			return ret;
	} else {
		pk_log(LOG_ERROR, "Cache and index in inconsistent state");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

pk_err_t cache_init(void)
{
	pk_err_t ret;
	long page_size;

	page_size=sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		pk_log(LOG_ERROR, "Couldn't get system page size");
		return PK_CALLFAIL;
	}

	if (config.flags & WANT_CACHE) {
		ret=open_cachedir(page_size);
		if (ret)
			goto bad;
	} else {
		if (sqlite3_open(":memory:", &state.db)) {
			pk_log(LOG_ERROR, "Couldn't open database handle: %s",
						sqlite3_errmsg(state.db));
			ret=PK_IOERR;
			goto bad;
		}
	}

	if (config.flags & WANT_PREV) {
		ret=attach(state.db, "last", config.last_keyring);
		if (ret)
			goto bad;
	}
	return PK_SUCCESS;

bad:
	cache_shutdown();
	return ret;
}

static pk_err_t obtain_chunk(unsigned chunk, const void *tag, unsigned *length)
{
	void *buf=malloc(parcel.chunksize);
	char *ftag;
	unsigned len;
	pk_err_t ret;
	ssize_t count;

	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failure");
		return PK_NOMEM;
	}
	if (hoard_get_chunk(tag, buf, &len)) {
		ftag=format_tag(tag);
		pk_log(LOG_INFO, "Tag %s not in hoard cache", ftag);
		free(ftag);
		ret=transport_fetch_chunk(buf, chunk, tag, &len);
		if (ret) {
			free(buf);
			return ret;
		}
	} else {
		pk_log(LOG_INFO, "Fetched chunk %u from hoard cache", chunk);
	}
	count=pwrite(state.loopdev_fd, buf, len, chunk_to_offset(chunk));
	free(buf);
	if (count != len) {
		pk_log(LOG_ERROR, "Couldn't write chunk %u to backing store",
					chunk);
		return PK_IOERR;
	}

	if (query(NULL, state.db, "INSERT INTO cache.chunks (chunk, length) "
				"VALUES(?, ?)", "dd", chunk, (int)len)) {
		pk_log(LOG_ERROR, "Couldn't insert chunk %u into cache index",
					chunk);
		return PK_IOERR;
	}
	*length=len;
	return PK_SUCCESS;
}

pk_err_t cache_get(unsigned chunk, void *tag, void *key,
			enum compresstype *compress, unsigned *length)
{
	sqlite3_stmt *stmt;
	int ret;
	void *rowtag;
	void *rowkey;
	int taglen;
	int keylen;
	pk_err_t err;

	/* XXX transaction */
	if (query(&stmt, state.db, "SELECT tag, key, compression FROM keys "
				"WHERE chunk == ?", "d", chunk)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query keyring");
		return PK_IOERR;
	}
	query_row(stmt, "bbd", &rowtag, &taglen, &rowkey, &keylen, compress);
	if (taglen != parcel.hashlen || keylen != parcel.hashlen) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Invalid hash length for chunk %u: "
					"expected %d, tag %d, key %d",
					chunk, parcel.hashlen, taglen, keylen);
		return PK_INVALID;
	}
	memcpy(tag, rowtag, parcel.hashlen);
	memcpy(key, rowkey, parcel.hashlen);
	query_free(stmt);

	ret=query(&stmt, state.db, "SELECT length FROM cache.chunks "
				"WHERE chunk == ?", "d", chunk);
	if (ret == SQLITE_OK) {
		/* Chunk is not in the local cache */
		query_free(stmt);
		err=obtain_chunk(chunk, tag, length);
		if (err)
			return err;
	} else if (ret == SQLITE_ROW) {
		query_row(stmt, "d", length);
		query_free(stmt);
	} else {
		pk_log(LOG_ERROR, "Couldn't query cache index");
		return PK_IOERR;
	}

	if (*length > parcel.chunksize) {
		pk_log(LOG_ERROR, "Invalid chunk length for chunk %u: %u",
					chunk, *length);
		return PK_INVALID;
	}
	if (!compress_is_valid(*compress)) {
		pk_log(LOG_ERROR, "Invalid or unsupported compression type "
					"for chunk %u: %u", chunk, *compress);
		return PK_INVALID;
	}
	return PK_SUCCESS;
}

pk_err_t cache_update(unsigned chunk, const void *tag, const void *key,
			enum compresstype compress, unsigned length)
{
	/* XXX transaction */
	if (query(NULL, state.db, "INSERT OR REPLACE INTO cache.chunks "
				"(chunk, length) VALUES(?, ?)", "dd",
				chunk, length)) {
		pk_log(LOG_ERROR, "Couldn't update cache index");
		return PK_IOERR;
	}
	/* XXX transient? */
	if (query(NULL, state.db, "UPDATE keys SET tag = ?, key = ?, "
				"compression = ? WHERE chunk == ?", "bbdd",
				tag, parcel.hashlen, key, parcel.hashlen,
				compress, chunk)) {
		pk_log(LOG_ERROR, "Couldn't update keyring");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

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
	/* XXX transaction */
	if (query(&stmt, state.db, "SELECT count(*) FROM "
				"main.keys JOIN last.keys "
				"ON main.keys.chunk == last.keys.chunk "
				"WHERE main.keys.tag != last.keys.tag", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Query failed");
		return 1;
	}
	query_row(stmt, "d", &total_modified);
	query_free(stmt);
	buf=malloc(parcel.chunksize);
	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failed");
		return 1;
	}
	for (sret=query(&stmt, state.db, "SELECT main.keys.chunk, "
				"main.keys.tag, cache.chunks.length FROM "
				"main.keys JOIN last.keys ON "
				"main.keys.chunk == last.keys.chunk "
				"LEFT JOIN cache.chunks ON "
				"main.keys.chunk == cache.chunks.chunk WHERE "
				"main.keys.tag != last.keys.tag", NULL);
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
		if (pread(state.cache_fd, buf, length, chunk_to_offset(chunk))
					!= length) {
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
		if (write(fd, buf, length) != length) {
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
	if (ret == 0)
		if (write_upload_stats(modified_chunks, modified_bytes))
			ret=1;
	return ret;
}

int validate_keyring(void)
{
	sqlite3_stmt *stmt;
	const char *result;
	unsigned expected_chunk=0;
	unsigned chunk;
	unsigned taglen;
	unsigned keylen;
	unsigned compress;
	int sret;
	int ret=0;

	pk_log(LOG_INFO, "Validating keyring");
	printf("Validating keyring...\n");
	if (query(&stmt, state.db, "PRAGMA integrity_check", NULL) !=
				SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't run SQLite integrity check");
		return 1;
	}
	query_row(stmt, "s", &result);
	sret=strcmp(result, "ok");
	query_free(stmt);
	if (sret) {
		pk_log(LOG_ERROR, "SQLite integrity check failed");
		return 1;
	}
	for (sret=query(&stmt, state.db, "SELECT chunk, tag, key, compression "
				"FROM keys ORDER BY chunk ASC", NULL);
				sret == SQLITE_ROW; sret=query_next(stmt)) {
		query_row(stmt, "dnnd", &chunk, &taglen, &keylen, &compress);
		if (chunk >= parcel.chunks) {
			pk_log(LOG_ERROR, "Found keyring entry %u greater than"
						" parcel size %u", chunk,
						parcel.chunks);
			ret=1;
			continue;
		}
		if (chunk < expected_chunk) {
			pk_log(LOG_ERROR, "Found unexpected keyring entry for "
						"chunk %u", chunk);
			ret=1;
			continue;
		}
		while (expected_chunk < chunk) {
			pk_log(LOG_ERROR, "Missing keyring entry for chunk %u",
						expected_chunk);
			ret=1;
			expected_chunk++;
		}
		expected_chunk++;
		if (taglen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected tag length %u, "
						"found %u", chunk,
						parcel.hashlen, taglen);
			ret=1;
		}
		if (keylen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected key length %u, "
						"found %u", chunk,
						parcel.hashlen, keylen);
			ret=1;
		}
		if (!compress_is_valid(compress)) {
			pk_log(LOG_ERROR, "Chunk %u: invalid or unsupported "
						"compression type %u", chunk,
						compress);
			ret=1;
		}
	}
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Keyring query failed");
		ret=1;
	}
	query_free(stmt);
	return ret;
}

int validate_cache(void)
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
	int ret=0;
	int sret;

	pk_log(LOG_INFO, "Checking cache consistency");
	printf("Checking local cache for internal consistency...\n");

	/* XXX PRAGMA integrity_check on attached database? */
	/* XXX transaction? */
	if (query(&stmt, state.db, "SELECT count(*) FROM cache.chunks", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't enumerate valid chunks");
		return 1;
	}
	query_row(stmt, "d", &valid);
	query_free(stmt);

	buf=malloc(parcel.chunksize);
	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failed");
		return 1;
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
			ret=1;
			continue;
		}
		if (chunklen > parcel.chunksize || chunklen == 0) {
			pk_log(LOG_ERROR, "Chunk %u: absurd size %u",
						chunk, chunklen);
			ret=1;
			continue;
		}
		if (tag == NULL) {
			pk_log(LOG_ERROR, "Found valid chunk %u with no "
						"keyring entry", chunk);
			ret=1;
			continue;
		}
		if (taglen != parcel.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected tag length "
						"%u, found %u", chunk,
						parcel.hashlen, taglen);
			ret=1;
			continue;
		}

		if (pread(state.cache_fd, buf, chunklen,
					chunk_to_offset(chunk)) != chunklen) {
			pk_log(LOG_ERROR, "Chunk %u: couldn't read from "
						"local cache", chunk);
			ret=1;
			continue;
		}
		digest(calctag, buf, chunklen);
		if (memcmp(tag, calctag, taglen)) {
			pk_log(LOG_ERROR, "Chunk %u: tag check failure",
						chunk);
			log_tag_mismatch(tag, calctag);
		}
	}
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Error querying cache index");
		ret=1;
	}
	query_free(stmt);
	free(buf);
	return ret;
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

	/* XXX transaction? */
	if (query(&stmt, state.db, "SELECT count(*) from cache.chunks", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query cache index");
		return 1;
	}
	query_row(stmt, "d", &validchunks);
	query_free(stmt);
	if (query(&stmt, state.db, "SELECT count(*) FROM main.keys "
				"JOIN last.keys ON "
				"main.keys.chunk == last.keys.chunk WHERE "
				"main.keys.tag != last.keys.tag", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't compare keyrings");
		return 1;
	}
	query_row(stmt, "d", &dirtychunks);
	query_free(stmt);

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
