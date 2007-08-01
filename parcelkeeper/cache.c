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
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include "defs.h"

#define CA_MAGIC 0x51528038
#define CA_VERSION 1

/* All u32's in network byte order */
struct ca_header {
	uint32_t magic;
	uint32_t entries;
	uint32_t offset;  /* beginning of data, in 512-byte blocks */
	uint32_t reserved_1[2];
	uint8_t version;
	uint8_t reserved_2[491];
};

static pk_err_t create_cache_file(long page_size)
{
	struct ca_header hdr = {0};
	int fd;

	pk_log(LOG_INFO, "No existing local cache; creating");
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
	if (ftruncate(fd, state.chunks * state.chunksize + state.offset)) {
		pk_log(LOG_ERROR, "couldn't extend cache file");
		return PK_IOERR;
	}

	pk_log(LOG_INFO, "Created cache file");
	state.cache_fd=fd;
	return PK_SUCCESS;
}

static pk_err_t open_cache_file(void)
{
	struct ca_header hdr;
	int fd;
	long page_size;

	page_size=sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		pk_log(LOG_ERROR, "couldn't get system page size");
		return PK_CALLFAIL;
	}

	fd=open(config.cache_file, O_RDWR);
	if (fd == -1 && errno == ENOENT) {
		return create_cache_file(page_size);
	} else if (fd == -1) {
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

int validate_cache(void)
{
	void *buf;
	unsigned chunk_num;
	char tag[HASH_LEN];
	struct chunk_data *cdp;
	unsigned processed=0;

	pk_log(LOG_BASIC, "Checking cache consistency");
	printf("Checking local cache for internal consistency...\n");
	buf=malloc(state.chunksize_bytes);
	if (buf == NULL) {
		pk_log(LOG_ERRORS, "malloc failed");
		return 1;
	}
	foreach_chunk(chunk_num, cdp) {
		if (!cdp_present(cdp)) {
			continue;
		}
		if (pread(state.cachefile_fd, buf, cdp->length,
				get_image_offset_from_chunk_num(chunk_num))
				!= cdp->length) {
			pk_log(LOG_ERRORS, "Couldn't read chunk from "
						"local cache: %u", chunk_num);
			return 1;
		}
		digest(buf, cdp->length, tag);
		if (check_tag(cdp, tag) == PK_TAGFAIL) {
			pk_log(LOG_ERRORS, "Chunk %u: tag check failure",
						chunk_num);
			print_tag_check_error(cdp->tag, tag);
		}
		print_progress(++processed, state.valid_chunks);
	}
	free(buf);
	printf("\n");
	return 0;
}

int examine_cache(void)
{
	unsigned dirtychunks;
	unsigned max_mb;
	unsigned valid_mb;
	unsigned dirty_mb;
	unsigned valid_pct=0;
	unsigned dirty_pct=0;

	if (update_modified_flags(&dirtychunks)) {
		pk_log(LOG_ERRORS, "Couldn't compare keyrings");
		return 1;
	}
	max_mb=(((unsigned long long)state.numchunks) *
				state.chunksize_bytes) >> 20;
	valid_mb=(((unsigned long long)state.valid_chunks) *
				state.chunksize_bytes) >> 20;
	dirty_mb=(((unsigned long long)dirtychunks) *
				state.chunksize_bytes) >> 20;
	if (state.numchunks)
		valid_pct=(100 * state.valid_chunks) / state.numchunks;
	if (state.valid_chunks)
		dirty_pct=(100 * dirtychunks) / state.valid_chunks;
		printf("Local cache : %u%% populated (%u/%u MB), "
					"%u%% modified (%u/%u MB)\n",
					valid_pct, valid_mb, max_mb, dirty_pct,
					dirty_mb, valid_mb);
	return 0;
}
#endif