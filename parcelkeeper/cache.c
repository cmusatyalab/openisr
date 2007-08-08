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
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include "defs.h"

#define TRANSPORT_TRIES 5
#define TRANSPORT_RETRY_DELAY 5
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
	return (off64_t)state.chunksize * chunk + state.offset;
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
	hdr.entries=htonl(state.chunks);
	hdr.offset=htonl(state.offset >> 9);
	hdr.version=CA_VERSION;
	if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		pk_log(LOG_ERROR, "Couldn't write cache file header");
		return PK_IOERR;
	}
	if (ftruncate(fd, chunk_to_offset(state.chunks))) {
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
	if (ntohl(hdr.entries) != state.chunks) {
		pk_log(LOG_ERROR, "Invalid chunk count reading cache file: "
					"expected %u, found %u",
					state.chunks, ntohl(hdr.entries));
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

pk_err_t cache_init(void)
{
	pk_err_t ret=PK_IOERR;
	long page_size;

	page_size=sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		pk_log(LOG_ERROR, "Couldn't get system page size");
		return PK_CALLFAIL;
	}
	if (sqlite3_open(config.keyring, &state.db)) {
		pk_log(LOG_ERROR, "Couldn't open keyring %s: %s",
					config.keyring,
					sqlite3_errmsg(state.db));
		goto bad;
	}
	if (is_file(config.cache_file) && is_file(config.cache_index)) {
		ret=attach(state.db, "cache", config.cache_index);
		if (ret)
			goto bad;
		ret=open_cache_file(page_size);
		if (ret)
			goto bad;
		ret=verify_cache_index();
		if (ret)
			goto bad;
	} else if (!is_file(config.cache_file) &&
				!is_file(config.cache_index)) {
		ret=attach(state.db, "cache", config.cache_index);
		if (ret)
			goto bad;
		ret=create_cache_file(page_size);
		if (ret)
			goto bad;
		ret=create_cache_index();
		if (ret)
			goto bad;
	} else {
		pk_log(LOG_ERROR, "Cache and index in inconsistent state");
		goto bad;
	}
	return PK_SUCCESS;

bad:
	cache_shutdown();
	return ret;
}

static pk_err_t fetch_chunk(unsigned chunk, unsigned *length)
{
	void *buf=malloc(state.chunksize);
	size_t len;
	int i;
	pk_err_t err;
	ssize_t count;

	if (buf == NULL) {
		pk_log(LOG_ERROR, "malloc failure");
		return PK_NOMEM;
	}

	for (i=0; i<TRANSPORT_TRIES; i++) {
		err=transport_get(buf, chunk, &len);
		if (err != PK_NETFAIL)
			break;
		pk_log(LOG_ERROR, "Fetching chunk %u failed; retrying in %d "
					"seconds", chunk,
					TRANSPORT_RETRY_DELAY);
		sleep(TRANSPORT_RETRY_DELAY);
	}
	if (err != PK_SUCCESS) {
		pk_log(LOG_ERROR, "Couldn't fetch chunk %u", chunk);
		free(buf);
		return err;
	}
	/* XXX check tag */

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
	ret=query(&stmt, state.db, "SELECT length FROM cache.chunks "
				"WHERE chunk == ?", "d", chunk);
	if (ret == SQLITE_OK) {
		/* Chunk is not in the local cache */
		query_free(stmt);
		err=fetch_chunk(chunk, length);
		if (err)
			return err;
	} else if (ret == SQLITE_ROW) {
		query_row(stmt, "d", length);
		query_free(stmt);
	} else {
		pk_log(LOG_ERROR, "Couldn't query cache index");
		return PK_IOERR;
	}

	if (query(&stmt, state.db, "SELECT tag, key, compression FROM keys "
				"WHERE chunk == ?", "d", chunk)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't query keyring");
		return PK_IOERR;
	}
	query_row(stmt, "bbd", &rowtag, &taglen, &rowkey, &keylen, compress);
	if (taglen != state.hashlen || keylen != state.hashlen) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Invalid hash length for chunk %u: "
					"expected %d, tag %d, key %d",
					chunk, state.hashlen, taglen, keylen);
		return PK_INVALID;
	}
	memcpy(tag, rowtag, state.hashlen);
	memcpy(key, rowkey, state.hashlen);
	query_free(stmt);

	if (*length > state.chunksize) {
		pk_log(LOG_ERROR, "Invalid chunk length for chunk %u: %u",
					chunk, *length);
		return PK_INVALID;
	}
	/* XXX validate compresstype */
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
				tag, state.hashlen, key, state.hashlen,
				compress, chunk)) {
		pk_log(LOG_ERROR, "Couldn't update keyring");
		return PK_IOERR;
	}
	return PK_SUCCESS;
}

#if 0
int copy_for_upload(void)
{
	char name[MAX_PATH_LENGTH];
	char *buf;
	unsigned u;
	struct chunk_data *cdp;
	int fd;
	unsigned examined_chunks=0;
	unsigned modified_chunks=0;
	unsigned long long modified_bytes=0;
	FILE *fp;
	char calc_tag[HASH_LEN];
	unsigned dirty_count;

	pk_log(LOG_BASIC, "Copying chunks to upload directory %s",
				config.dest_dir_name);
	if (update_modified_flags(&dirty_count)) {
		pk_log(LOG_ERRORS, "Couldn't compare keyrings");
		return 1;
	}
	buf=malloc(state.chunksize_bytes);
	if (buf == NULL) {
		pk_log(LOG_ERRORS, "malloc failed");
		return 1;
	}
	/* check the subdirectories  -- create if needed */
	for (u = 0; u < state.numdirs; u++) {
		if (form_dir_name(name, sizeof(name), config.dest_dir_name,
					u)) {
			pk_log(LOG_ERRORS, "Couldn't form directory name: %u",
						u);
			return 1;
		}
		if (!is_dir(name)) {
			if (mkdir(name, 0770)) {
				pk_log(LOG_ERRORS, "unable to mkdir: %s", name);
				return 1;
			}
		}
	}
	foreach_chunk(u, cdp) {
		if (cdp_is_modified(cdp)) {
			print_progress(++examined_chunks, dirty_count);
			if (!cdp_present(cdp)) {
				/* XXX damaged cache file; we need to be able
				   to recover */
				pk_log(LOG_ERRORS, "Chunk modified but not "
							"present: %u",u);
				return 1;
			}
			if (form_chunk_file_name(name, sizeof(name),
						config.dest_dir_name, u)) {
				pk_log(LOG_ERRORS, "Couldn't form chunk "
							"filename: %u",u);
				return 1;
			}
			if (pread(state.cachefile_fd, buf, cdp->length,
					get_image_offset_from_chunk_num(u))
					!= cdp->length) {
				pk_log(LOG_ERRORS, "Couldn't read chunk from "
							"local cache: %u", u);
				return 1;
			}
			digest(buf, cdp->length, calc_tag);
			if (check_tag(cdp, calc_tag) == PK_TAGFAIL) {
				pk_log(LOG_ERRORS, "Chunk %u: tag mismatch."
						" Data corruption has occurred;"
						" skipping chunk", u);
				print_tag_check_error(cdp->tag, calc_tag);
				return 1;
			}
			fd=open(name, O_WRONLY|O_CREAT|O_TRUNC, 0600);
			if (fd == -1) {
				pk_log(LOG_ERRORS, "Couldn't open chunk file: "
							"%s", name);
				return 1;
			}
			if (write(fd, buf, cdp->length) != cdp->length) {
				pk_log(LOG_ERRORS, "Couldn't write chunk file: "
							"%s", name);
				return 1;
			}
			if (close(fd) && errno != EINTR) {
				pk_log(LOG_ERRORS, "Couldn't write chunk file: "
							"%s", name);
				return 1;
			}
			modified_chunks++;
			modified_bytes += cdp->length;
		}
	}
	printf("\n");
	free(buf);
	/* Write statistics */
	snprintf(name, sizeof(name), "%s/stats", config.dest_dir_name);
	fp=fopen(name, "w");
	if (fp == NULL) {
		pk_log(LOG_ERRORS, "Couldn't open stats file: %s", name);
		return 1;
	}
	fprintf(fp, "%u\n%llu\n", modified_chunks, modified_bytes);
	fclose(fp);
	pk_log(LOG_STATS, "Copied %u modified chunks, %llu bytes",
				modified_chunks, modified_bytes);
	return 0;
}
#endif

/* XXX should also validate keyring: one key for every chunk; valid
       compression */
int validate_cache(void)
{
	sqlite3_stmt *stmt;
	void *buf;
	void *tag;
	char calctag[state.hashlen];
	unsigned chunk;
	unsigned taglen;
	unsigned chunklen;
	unsigned processed=0;
	unsigned valid;
	int ret=0;
	int sret;

	pk_log(LOG_INFO, "Checking cache consistency");
	printf("Checking local cache for internal consistency...\n");

	/* XXX transaction? */
	if (query(&stmt, state.db, "SELECT count(*) FROM cache.chunks", NULL)
				!= SQLITE_ROW) {
		query_free(stmt);
		pk_log(LOG_ERROR, "Couldn't enumerate valid chunks");
		return 1;
	}
	query_row(stmt, "d", &valid);
	query_free(stmt);

	buf=malloc(state.chunksize);
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

		if (chunk > state.chunks) {
			pk_log(LOG_ERROR, "Found chunk %u greater than "
						"parcel size %u", chunk,
						state.chunks);
			ret=1;
			continue;
		}
		if (chunklen > state.chunksize) {
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
		if (taglen != state.hashlen) {
			pk_log(LOG_ERROR, "Chunk %u: expected tag length "
						"%u, found %u", chunk,
						state.hashlen, taglen);
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

	if (attach(state.db, "last", config.last_keyring))
		return 1;
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

	max_mb=(((off64_t)state.chunks) * state.chunksize) >> 20;
	valid_mb=(((off64_t)validchunks) * state.chunksize) >> 20;
	dirty_mb=(((off64_t)dirtychunks) * state.chunksize) >> 20;
	valid_pct=(100 * validchunks) / state.chunks;
	if (validchunks)
		dirty_pct=(100 * dirtychunks) / validchunks;
	printf("Local cache : %u%% populated (%u/%u MB), %u%% modified "
				"(%u/%u MB)\n", valid_pct, valid_mb, max_mb,
				dirty_pct, dirty_mb, valid_mb);
	return 0;
}
