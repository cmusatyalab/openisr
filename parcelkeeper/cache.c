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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
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
	uint32_t reserved_1[2];
	uint8_t version;
	uint8_t reserved_2[491];
};

enum shm_chunk_status {
	SHM_NOT_PRESENT,
	SHM_PRESENT,
	SHM_ACCESSED,
	SHM_DIRTY
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
	hdr.magic=htonl(CA_MAGIC);
	hdr.entries=htonl(parcel.chunks);
	hdr.offset=htonl(state.offset >> 9);
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
	pk_err_t ret;

	ret=begin(state.db);
	if (ret)
		return ret;
	ret=PK_IOERR;
	if (query(NULL, state.db, "CREATE TABLE cache.chunks ("
				"chunk INTEGER PRIMARY KEY NOT NULL, "
				"length INTEGER NOT NULL)", NULL)) {
		pk_log(LOG_ERROR, "Couldn't create cache index");
		goto bad;
	}
	if (query(NULL, state.db, "PRAGMA cache.user_version = "
				stringify(CA_INDEX_VERSION), NULL)) {
		pk_log(LOG_ERROR, "Couldn't set cache index version");
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

static pk_err_t verify_cache_index(void)
{
	struct query *qry;
	int found;

	if (query(&qry, state.db, "PRAGMA cache.user_version", NULL) !=
				SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't query cache index version");
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

static void shm_set(unsigned chunk, enum shm_chunk_status status)
{
	int offset;
	int shift;
	unsigned char curbyte;
	unsigned char curbits;
	unsigned char newbits;

	if (state.shm_base == NULL)
		return;
	if (chunk > parcel.chunks) {
		pk_log(LOG_ERROR, "Invalid chunk %u", chunk);
		return;
	}
	offset = chunk / 4;
	shift = 2 * (3 - (chunk % 4));
	curbyte = state.shm_base[offset];
	curbits = (curbyte >> shift) & 0x3;
	newbits = status & 0x3;
	if (curbits < newbits) {
		curbyte &= ~(0x3 << shift);
		curbyte |= newbits << shift;
		state.shm_base[offset]=curbyte;
	}
}

static pk_err_t shm_init(void)
{
	int fd;
	struct query *qry;
	unsigned chunk;
	int sret;

	state.shm_len = (parcel.chunks + 3) / 4;
	if (asprintf(&state.shm_name, "/openisr-chunkmap-%s", parcel.uuid)
					== -1) {
		pk_log(LOG_ERROR, "malloc failed");
		return PK_NOMEM;
	}
	fd=shm_open(state.shm_name, O_RDWR|O_CREAT|O_EXCL, 0600);
	if (fd == -1) {
		pk_log(LOG_ERROR, "Couldn't create shared memory segment: %s",
					strerror(errno));
		free(state.shm_name);
		return PK_IOERR;
	}
	if (ftruncate(fd, state.shm_len)) {
		pk_log(LOG_ERROR, "Couldn't set shared memory segment to "
					"%u bytes", state.shm_len);
		close(fd);
		shm_unlink(state.shm_name);
		free(state.shm_name);
		return PK_IOERR;
	}
	state.shm_base=mmap(NULL, state.shm_len, PROT_READ|PROT_WRITE,
				MAP_SHARED, fd, 0);
	close(fd);
	if (state.shm_base == MAP_FAILED) {
		pk_log(LOG_ERROR, "Couldn't map shared memory segment");
		state.shm_base=NULL;
		shm_unlink(state.shm_name);
		free(state.shm_name);
		return PK_CALLFAIL;
	}

	for (sret=query(&qry, state.db, "SELECT chunk FROM cache.chunks", NULL);
				sret == SQLITE_ROW; sret=query_next(qry)) {
		query_row(qry, "d", &chunk);
		shm_set(chunk, SHM_PRESENT);
	}
	query_free(qry);
	if (sret != SQLITE_OK) {
		pk_log(LOG_ERROR, "Couldn't query cache index");
		munmap(state.shm_base, state.shm_len);
		state.shm_base=NULL;
		shm_unlink(state.shm_name);
		free(state.shm_name);
		return PK_CALLFAIL;
	}
	return PK_SUCCESS;
}

void cache_shutdown(void)
{
	if (state.shm_base) {
		munmap(state.shm_base, state.shm_len);
		shm_unlink(state.shm_name);
		free(state.shm_name);
	}
	if (state.cache_fd)
		close(state.cache_fd);
	query_flush();
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
	ret=set_busy_handler(state.db);
	if (ret)
		return ret;
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
		ret=set_busy_handler(state.db);
		if (ret)
			goto bad;
	}

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
	count=pwrite(state.loopdev_fd, buf, len, cache_chunk_to_offset(chunk));
	free(buf);
	if (count != (int)len) {
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
	shm_set(chunk, SHM_PRESENT);
	*length=len;
	return PK_SUCCESS;
}

pk_err_t cache_get(unsigned chunk, void *tag, void *key,
			enum compresstype *compress, unsigned *length)
{
	struct query *qry;
	int ret;
	void *rowtag;
	void *rowkey;
	unsigned taglen;
	unsigned keylen;
	pk_err_t err;

	/* XXX does not use transaction.  do we need to?  might introduce
	   conflicts in obtain_chunk() */
	if (query(&qry, state.db, "SELECT tag, key, compression FROM keys "
				"WHERE chunk == ?", "d", chunk)
				!= SQLITE_ROW) {
		pk_log(LOG_ERROR, "Couldn't query keyring");
		return PK_IOERR;
	}
	query_row(qry, "bbd", &rowtag, &taglen, &rowkey, &keylen, compress);
	if (taglen != parcel.hashlen || keylen != parcel.hashlen) {
		query_free(qry);
		pk_log(LOG_ERROR, "Invalid hash length for chunk %u: "
					"expected %d, tag %d, key %d",
					chunk, parcel.hashlen, taglen, keylen);
		return PK_INVALID;
	}
	memcpy(tag, rowtag, parcel.hashlen);
	memcpy(key, rowkey, parcel.hashlen);
	query_free(qry);

	ret=query(&qry, state.db, "SELECT length FROM cache.chunks "
				"WHERE chunk == ?", "d", chunk);
	if (ret == SQLITE_OK) {
		/* Chunk is not in the local cache */
		err=obtain_chunk(chunk, tag, length);
		if (err)
			return err;
	} else if (ret == SQLITE_ROW) {
		query_row(qry, "d", length);
		query_free(qry);
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
	shm_set(chunk, SHM_ACCESSED);
	return PK_SUCCESS;
}

pk_err_t cache_update(unsigned chunk, const void *tag, const void *key,
			enum compresstype compress, unsigned length)
{
	pk_err_t ret;

	ret=begin(state.db);
	if (ret)
		return ret;
	ret=PK_IOERR;
	if (query(NULL, state.db, "INSERT OR REPLACE INTO cache.chunks "
				"(chunk, length) VALUES(?, ?)", "dd",
				chunk, length)) {
		pk_log(LOG_ERROR, "Couldn't update cache index");
		goto bad;
	}
	if (query(NULL, state.db, "UPDATE keys SET tag = ?, key = ?, "
				"compression = ? WHERE chunk == ?", "bbdd",
				tag, parcel.hashlen, key, parcel.hashlen,
				compress, chunk)) {
		pk_log(LOG_ERROR, "Couldn't update keyring");
		goto bad;
	}
	ret=commit(state.db);
	if (ret)
		goto bad;
	shm_set(chunk, SHM_DIRTY);
	return PK_SUCCESS;

bad:
	rollback(state.db);
	return ret;
}
