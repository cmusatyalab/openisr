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
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include "defs.h"

#define CA_MAGIC 0x51528038
#define CA_VERSION 1
#define CA_INDEX_VERSION 1

/* All u32's in network byte order */
struct ca_header {
	uint32_t magic;
	uint32_t entries;
	uint32_t offset;  /* beginning of data, in 512-byte blocks */
	uint32_t flags;
	uint32_t reserved_1;
	uint8_t version;
	uint8_t reserved_2[491];
};

enum shm_chunk_status {
	SHM_PRESENT		= 0x1,
	SHM_DIRTY		= 0x2,
	SHM_ACCESSED_SESSION	= 0x4,
	SHM_DIRTY_SESSION	= 0x8,
};

off64_t cache_chunk_to_offset(unsigned chunk)
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
	state.cache_flags=0;
	hdr.magic=htonl(CA_MAGIC);
	hdr.entries=htonl(parcel.chunks);
	hdr.offset=htonl(state.offset >> 9);
	hdr.flags=htonl(state.cache_flags);
	hdr.version=CA_VERSION;
	if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		pk_log(LOG_ERROR, "Couldn't write cache file header");
		return PK_IOERR;
	}
	if (ftruncate(fd, cache_chunk_to_offset(parcel.chunks))) {
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
	state.cache_flags=ntohl(hdr.flags);
	state.offset=ntohl(hdr.offset) << 9;
	if (state.offset % page_size != 0) {
		/* This may occur with old cache files, or with cache files
		   copied from another system with a different page size. */
		pk_log(LOG_ERROR, "Cache file's header length %u is not "
					"a multiple of the page size %ld",
					state.offset, page_size);
		pk_log(LOG_ERROR, "Data corruption may occur.  If it does, "
					"checkin will be disallowed");
	}

	pk_log(LOG_INFO, "Read cache header");
	state.cache_fd=fd;
	return PK_SUCCESS;
}

static pk_err_t cache_set_flags(unsigned flags)
{
	unsigned tmp;

	if (!(config.flags & WANT_LOCK)) {
		/* Catch misuse of this function */
		pk_log(LOG_ERROR, "Refusing to set cache flags when lock "
					"not held");
		return PK_BUSY;
	}
	if (!state.cache_fd) {
		pk_log(LOG_ERROR, "Cache file not open; can't set flags");
		return PK_IOERR;
	}

	tmp=htonl(flags);
	if (pwrite(state.cache_fd, &tmp, sizeof(tmp),
				offsetof(struct ca_header, flags))
				!= sizeof(tmp)) {
		pk_log(LOG_ERROR, "Couldn't write new flags to cache file");
		return PK_IOERR;
	}
	if (fdatasync(state.cache_fd)) {
		pk_log(LOG_ERROR, "Couldn't sync cache file");
		return PK_IOERR;
	}
	state.cache_flags=flags;
	return PK_SUCCESS;
}

pk_err_t cache_set_flag(unsigned flag)
{
	if ((flag & CA_F_DAMAGED) == CA_F_DAMAGED)
		pk_log(LOG_WARNING, "Setting damaged flag on local cache");
	return cache_set_flags(state.cache_flags | flag);
}

pk_err_t cache_clear_flag(unsigned flag)
{
	return cache_set_flags(state.cache_flags & ~flag);
}

int cache_test_flag(unsigned flag)
{
	return ((state.cache_flags & flag) == flag);
}

static pk_err_t create_cache_index(void)
{
	pk_err_t ret;

again:
	ret=begin(state.db);
	if (ret)
		return ret;
	ret=PK_IOERR;
	if (query(NULL, state.db, "CREATE TABLE cache.chunks ("
				"chunk INTEGER PRIMARY KEY NOT NULL, "
				"length INTEGER NOT NULL)", NULL)) {
		pk_log_sqlerr(state.db, "Couldn't create cache index");
		goto bad;
	}
	if (query(NULL, state.db, "PRAGMA cache.user_version = "
				stringify(CA_INDEX_VERSION), NULL)) {
		pk_log_sqlerr(state.db, "Couldn't set cache index version");
		goto bad;
	}
	ret=commit(state.db);
	if (ret)
		goto bad;
	return PK_SUCCESS;

bad:
	rollback(state.db);
	if (query_retry(state.db))
		goto again;
	return ret;
}

static pk_err_t verify_cache_index(void)
{
	struct query *qry;
	int found;

again:
	query(&qry, state.db, "PRAGMA cache.user_version", NULL);
	if (query_retry(state.db))
		goto again;
	else if (!query_has_row(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't query cache index version");
		return PK_IOERR;
	}
	query_row(qry, "d", &found);
	query_free(qry);
	if (found != CA_INDEX_VERSION) {
		pk_log(LOG_ERROR, "Invalid version reading cache index: "
					"expected %d, found %d",
					CA_INDEX_VERSION, found);
		return PK_BADFORMAT;
	}
	return PK_SUCCESS;
}

static void shm_set(unsigned chunk, unsigned status)
{
	if (state.shm_base == NULL)
		return;
	if (chunk > parcel.chunks) {
		pk_log(LOG_ERROR, "Invalid chunk %u", chunk);
		return;
	}
	state.shm_base[chunk] |= status;
}

static pk_err_t shm_init(void)
{
	int fd;
	struct query *qry;
	unsigned chunk;
	pk_err_t ret;

	state.shm_len = parcel.chunks;
	state.shm_name = g_strdup_printf("/openisr-chunkmap-%s", parcel.uuid);
	/* If there's a segment by that name, it's leftover and should be
	   killed.  (Or else we have a UUID collision, which will prevent
	   Nexus registration from succeeding in any case.)  This is racy
	   with regard to someone else deleting and recreating the segment,
	   but we do this under the PK lock so it shouldn't be a problem. */
	shm_unlink(state.shm_name);
	fd=shm_open(state.shm_name, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd == -1) {
		pk_log(LOG_ERROR, "Couldn't create shared memory segment: %s",
					strerror(errno));
		ret=PK_IOERR;
		goto bad_open;
	}
	if (ftruncate(fd, state.shm_len)) {
		pk_log(LOG_ERROR, "Couldn't set shared memory segment to "
					"%u bytes", state.shm_len);
		close(fd);
		ret=PK_IOERR;
		goto bad_truncate;
	}
	state.shm_base=mmap(NULL, state.shm_len, PROT_READ|PROT_WRITE,
				MAP_SHARED, fd, 0);
	close(fd);
	if (state.shm_base == MAP_FAILED) {
		pk_log(LOG_ERROR, "Couldn't map shared memory segment");
		ret=PK_CALLFAIL;
		goto bad_map;
	}

again:
	for (query(&qry, state.db, "SELECT chunk FROM cache.chunks", NULL);
				query_has_row(state.db); query_next(qry)) {
		query_row(qry, "d", &chunk);
		shm_set(chunk, SHM_PRESENT);
	}
	query_free(qry);
	if (query_retry(state.db)) {
		goto again;
	} else if (!query_ok(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't query cache index");
		ret=PK_SQLERR;
		goto bad_populate;
	}

	for (query(&qry, state.db, "SELECT main.keys.chunk "
				"FROM main.keys JOIN prev.keys "
				"ON main.keys.chunk == prev.keys.chunk "
				"WHERE main.keys.tag != prev.keys.tag", NULL);
				query_has_row(state.db); query_next(qry)) {
		query_row(qry, "d", &chunk);
		shm_set(chunk, SHM_DIRTY);
	}
	query_free(qry);
	if (query_retry(state.db)) {
		goto again;
	} else if (!query_ok(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't find modified chunks");
		ret=PK_SQLERR;
		goto bad_populate;
	}
	return PK_SUCCESS;

bad_populate:
	munmap(state.shm_base, state.shm_len);
bad_map:
	state.shm_base=NULL;
bad_truncate:
	shm_unlink(state.shm_name);
bad_open:
	g_free(state.shm_name);
	return ret;
}

void cache_shutdown(void)
{
	if (state.shm_base) {
		munmap(state.shm_base, state.shm_len);
		shm_unlink(state.shm_name);
		g_free(state.shm_name);
	}
	if (state.cache_fd)
		close(state.cache_fd);
	sql_conn_close(state.db);
}

static pk_err_t open_cachedir(long page_size)
{
	pk_err_t ret;
	gboolean have_image;
	gboolean have_index;

	ret=sql_conn_open(config.keyring, &state.db);
	if (ret)
		return ret;

	have_image=g_file_test(config.cache_file, G_FILE_TEST_IS_REGULAR);
	have_index=g_file_test(config.cache_index, G_FILE_TEST_IS_REGULAR);
	if (have_image && have_index) {
		ret=attach(state.db, "cache", config.cache_index);
		if (ret)
			return ret;
		ret=open_cache_file(page_size);
		if (ret)
			return ret;
		ret=verify_cache_index();
		if (ret)
			return ret;
	} else if ((config.flags & WANT_LOCK) && ((have_image && !have_index)
				|| (!have_image && have_index))) {
		/* We don't complain about this unless we have the PK lock,
		   since otherwise we're open to race conditions with another
		   process that does.  If we don't have the PK lock, we just
		   treat this case as though neither image nor index exists. */
		pk_log(LOG_ERROR, "Cache and index in inconsistent state");
		return PK_IOERR;
	} else {
		if (config.flags & WANT_LOCK) {
			ret=attach(state.db, "cache", config.cache_index);
			if (ret)
				return ret;
			ret=create_cache_file(page_size);
			if (ret)
				return ret;
		} else {
			/* If we WANT_CACHE but don't WANT_LOCK, we need to
			   make sure not to create the image and index files
			   to avoid race conditions.  (Right now this only
			   affects examine mode.)  Create a fake cache index
			   to simplify queries elsewhere. */
			ret=attach(state.db, "cache", ":memory:");
			if (ret)
				return ret;
		}
		ret=create_cache_index();
		if (ret)
			return ret;
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

	if (config.flags & WANT_CACHE)
		ret=open_cachedir(page_size);
	else
		ret=sql_conn_open(":memory:", &state.db);
	if (ret)
		goto bad;

	if (config.flags & WANT_PREV) {
		ret=attach(state.db, "prev", config.prev_keyring);
		if (ret)
			goto bad;
	}

	if (config.flags & WANT_SHM)
		if (shm_init())
			pk_log(LOG_ERROR, "Couldn't set up shared memory "
						"segment; continuing");

	return PK_SUCCESS;

bad:
	cache_shutdown();
	return ret;
}

static pk_err_t obtain_chunk(unsigned chunk, const void *tag, unsigned *length)
{
	void *buf;
	gchar *ftag;
	unsigned len;
	pk_err_t ret;
	ssize_t count;

	buf = g_malloc(parcel.chunksize);
	if (hoard_get_chunk(tag, buf, &len)) {
		ftag=format_tag(tag, parcel.hashlen);
		pk_log(LOG_CHUNK, "Tag %s not in hoard cache", ftag);
		g_free(ftag);
		ret=transport_fetch_chunk(buf, chunk, tag, &len);
		if (ret) {
			g_free(buf);
			return ret;
		}
	} else {
		pk_log(LOG_CHUNK, "Fetched chunk %u from hoard cache", chunk);
	}
	count=pwrite(state.cache_fd, buf, len, cache_chunk_to_offset(chunk));
	g_free(buf);
	if (count != (int)len) {
		pk_log(LOG_ERROR, "Couldn't write chunk %u to backing store",
					chunk);
		return PK_IOERR;
	}

	if (query(NULL, state.db, "INSERT INTO cache.chunks (chunk, length) "
				"VALUES(?, ?)", "dd", chunk, (int)len)) {
		pk_log_sqlerr(state.db, "Couldn't insert chunk %u into "
					"cache index", chunk);
		return PK_IOERR;
	}
	shm_set(chunk, SHM_PRESENT);
	*length=len;
	return PK_SUCCESS;
}

pk_err_t cache_get(unsigned chunk, void *tag, void *key,
			enum compresstype *compress, unsigned *length)
{
	struct query *qry;
	void *rowtag;
	void *rowkey;
	unsigned taglen;
	unsigned keylen;
	pk_err_t ret;

	pk_log(LOG_CHUNK, "Get: %u", chunk);
again:
	ret=begin(state.db);
	if (ret)
		return ret;
	query(&qry, state.db, "SELECT tag, key, compression FROM keys "
				"WHERE chunk == ?", "d", chunk);
	if (!query_has_row(state.db)) {
		pk_log_sqlerr(state.db, "Couldn't query keyring");
		ret=PK_IOERR;
		goto bad;
	}
	query_row(qry, "bbd", &rowtag, &taglen, &rowkey, &keylen, compress);
	if (taglen != parcel.hashlen || keylen != parcel.hashlen) {
		query_free(qry);
		pk_log(LOG_ERROR, "Invalid hash length for chunk %u: "
					"expected %d, tag %d, key %d",
					chunk, parcel.hashlen, taglen, keylen);
		ret=PK_INVALID;
		goto bad;
	}
	memcpy(tag, rowtag, parcel.hashlen);
	memcpy(key, rowkey, parcel.hashlen);
	query_free(qry);

	query(&qry, state.db, "SELECT length FROM cache.chunks "
				"WHERE chunk == ?", "d", chunk);
	if (query_ok(state.db)) {
		/* Chunk is not in the local cache */
		ret=obtain_chunk(chunk, tag, length);
		if (ret)
			goto bad;
	} else if (query_has_row(state.db)) {
		query_row(qry, "d", length);
		query_free(qry);
	} else {
		pk_log_sqlerr(state.db, "Couldn't query cache index");
		ret=PK_IOERR;
		goto bad;
	}

	if (*length > parcel.chunksize) {
		pk_log(LOG_ERROR, "Invalid chunk length for chunk %u: %u",
					chunk, *length);
		ret=PK_INVALID;
		goto bad;
	}
	if (!compress_is_valid(*compress)) {
		pk_log(LOG_ERROR, "Invalid or unsupported compression type "
					"for chunk %u: %u", chunk, *compress);
		ret=PK_INVALID;
		goto bad;
	}
	ret=commit(state.db);
	if (ret)
		goto bad;
	shm_set(chunk, SHM_ACCESSED_SESSION);
	return PK_SUCCESS;

bad:
	rollback(state.db);
	if (query_retry(state.db))
		goto again;
	return ret;
}

pk_err_t cache_update(unsigned chunk, const void *tag, const void *key,
			enum compresstype compress, unsigned length)
{
	pk_err_t ret;

	pk_log(LOG_CHUNK, "Update: %u", chunk);
again:
	ret=begin(state.db);
	if (ret)
		return ret;
	ret=PK_IOERR;
	if (query(NULL, state.db, "INSERT OR REPLACE INTO cache.chunks "
				"(chunk, length) VALUES(?, ?)", "dd",
				chunk, length)) {
		pk_log_sqlerr(state.db, "Couldn't update cache index");
		goto bad;
	}
	if (query(NULL, state.db, "UPDATE keys SET tag = ?, key = ?, "
				"compression = ? WHERE chunk == ?", "bbdd",
				tag, parcel.hashlen, key, parcel.hashlen,
				compress, chunk)) {
		pk_log_sqlerr(state.db, "Couldn't update keyring");
		goto bad;
	}
	ret=commit(state.db);
	if (ret)
		goto bad;
	shm_set(chunk, SHM_PRESENT | SHM_ACCESSED_SESSION | SHM_DIRTY |
				SHM_DIRTY_SESSION);
	return PK_SUCCESS;

bad:
	rollback(state.db);
	if (query_retry(state.db))
		goto again;
	return ret;
}
