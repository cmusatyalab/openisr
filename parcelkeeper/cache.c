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

static vulpes_err_t write_cache_header(int fd)
{
	struct chunk_data *cdp;
	struct ca_header hdr;
	struct ca_entry entry;
	unsigned chunk_num;

	if (lseek(fd, sizeof(hdr), SEEK_SET) != sizeof(hdr)) {
		vulpes_log(LOG_ERRORS, "Couldn't seek cache file");
		return VULPES_IOERR;
	}

	foreach_chunk(chunk_num, cdp) {
		memset(&entry, 0, sizeof(entry));
		if (cdp_present(cdp)) {
			entry.flags |= CA_VALID;
			entry.length=htonl(cdp->length);
		}
		if (write(fd, &entry, sizeof(entry)) != sizeof(entry)) {
			vulpes_log(LOG_ERRORS, "Couldn't write cache file "
						"record: %u", chunk_num);
			return VULPES_IOERR;
		}
	}

	if (lseek(fd, 0, SEEK_SET)) {
		vulpes_log(LOG_ERRORS, "Couldn't seek cache file");
		return VULPES_IOERR;
	}
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic=htonl(CA_MAGIC);
	hdr.entries=htonl(state.numchunks);
	hdr.version=CA_VERSION;
	hdr.offset=htonl(state.offset_bytes / 512);
	hdr.valid_chunks=htonl(state.valid_chunks);
	if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr) || fsync(fd)) {
		vulpes_log(LOG_ERRORS, "Couldn't write cache file header");
		return VULPES_IOERR;
	}

	vulpes_log(LOG_BASIC, "Wrote cache header");
	return VULPES_SUCCESS;
}

static vulpes_err_t open_cache_file(const char *path)
{
	struct chunk_data *cdp;
	struct ca_header hdr;
	struct ca_entry entry;
	unsigned chunk_num;
	int fd;
	long page_size;

	page_size=sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		vulpes_log(LOG_ERRORS, "couldn't get system page size");
		return VULPES_CALLFAIL;
	}
	fd=open(path, O_RDWR);
	if (fd == -1 && errno == ENOENT) {
		vulpes_log(LOG_BASIC, "No existing local cache; creating");
		fd=open(path, O_CREAT|O_RDWR, 0600);
		if (fd == -1) {
			vulpes_log(LOG_ERRORS, "couldn't create cache file");
			return VULPES_IOERR;
		}
		/* There's a race condition in the way the loop driver
		   interacts with the memory management system for (at least)
		   underlying file systems that provide the prepare_write and
		   commit_write address space operations.  This can cause data
		   not to be properly written to disk if I/O submitted to the
		   loop driver spans multiple page-cache pages and is not
		   aligned on page cache boundaries.  We therefore need to
		   make sure that our header is a multiple of the page size. */
		state.offset_bytes=((sizeof(hdr) + state.numchunks *
					sizeof(entry)) + page_size - 1) &
					~(page_size - 1);
		write_cache_header(fd);
		if (ftruncate(fd, state.volsize * SECTOR_SIZE +
						state.offset_bytes)) {
			vulpes_log(LOG_ERRORS, "couldn't extend cache file");
			return VULPES_IOERR;
		}
		state.cachefile_fd=fd;
		return VULPES_SUCCESS;
	} else if (fd == -1) {
		vulpes_log(LOG_ERRORS, "couldn't open cache file");
		return VULPES_IOERR;
	}

	if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
		vulpes_log(LOG_ERRORS, "Couldn't read cache file header");
		return VULPES_IOERR;
	}
	if (ntohl(hdr.magic) != CA_MAGIC) {
		vulpes_log(LOG_ERRORS, "Invalid magic number reading cache "
					"file");
		return VULPES_BADFORMAT;
	}
	if (hdr.version != CA_VERSION) {
		vulpes_log(LOG_ERRORS, "Invalid version reading cache file: "
					"expected %d, found %d", CA_VERSION,
					hdr.version);
		return VULPES_BADFORMAT;
	}
	if (ntohl(hdr.entries) != state.numchunks) {
		vulpes_log(LOG_ERRORS, "Invalid chunk count reading cache "
					"file: expected %u, found %u",
					state.numchunks, htonl(hdr.entries));
		return VULPES_BADFORMAT;
	}
	state.offset_bytes=ntohl(hdr.offset) * SECTOR_SIZE;
	if (state.offset_bytes % page_size != 0) {
		/* This may occur with old cache files, or with cache files
		   copied from another system with a different page size. */
		vulpes_log(LOG_ERRORS, "Cache file's header length %u is not "
					"a multiple of the page size %u",
					state.offset_bytes, page_size);
		vulpes_log(LOG_ERRORS, "Data corruption may occur.  If it "
					"does, checkin will be disallowed");
	}
	/* Don't trust valid_chunks field; it's informational only */

	foreach_chunk(chunk_num, cdp) {
		if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
			vulpes_log(LOG_ERRORS, "Couldn't read cache file "
						"record: %u", chunk_num);
			return VULPES_IOERR;
		}
		if (entry.flags & CA_VALID) {
			mark_cdp_present(cdp);
			cdp->length=ntohl(entry.length);
		}
	}
	vulpes_log(LOG_BASIC, "Read cache header");
	state.cachefile_fd=fd;
	return VULPES_SUCCESS;
}

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

	vulpes_log(LOG_BASIC, "Copying chunks to upload directory %s",
				config.dest_dir_name);
	if (update_modified_flags(&dirty_count)) {
		vulpes_log(LOG_ERRORS, "Couldn't compare keyrings");
		return 1;
	}
	buf=malloc(state.chunksize_bytes);
	if (buf == NULL) {
		vulpes_log(LOG_ERRORS, "malloc failed");
		return 1;
	}
	/* check the subdirectories  -- create if needed */
	for (u = 0; u < state.numdirs; u++) {
		if (form_dir_name(name, sizeof(name), config.dest_dir_name,
					u)) {
			vulpes_log(LOG_ERRORS, "Couldn't form directory name: "
						"%u", u);
			return 1;
		}
		if (!is_dir(name)) {
			if (mkdir(name, 0770)) {
				vulpes_log(LOG_ERRORS, "unable to mkdir: %s",
							name);
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
				vulpes_log(LOG_ERRORS, "Chunk modified but "
							"not present: %u",u);
				return 1;
			}
			if (form_chunk_file_name(name, sizeof(name),
						config.dest_dir_name, u)) {
				vulpes_log(LOG_ERRORS, "Couldn't form chunk "
							"filename: %u",u);
				return 1;
			}
			if (pread(state.cachefile_fd, buf, cdp->length,
					get_image_offset_from_chunk_num(u))
					!= cdp->length) {
				vulpes_log(LOG_ERRORS, "Couldn't read chunk "
							"from local cache: %u",
							u);
				return 1;
			}
			digest(buf, cdp->length, calc_tag);
			if (check_tag(cdp, calc_tag) == VULPES_TAGFAIL) {
				vulpes_log(LOG_ERRORS, "Chunk %u: tag mismatch."
						" Data corruption has occurred;"
						" skipping chunk", u);
				print_tag_check_error(cdp->tag, calc_tag);
				return 1;
			}
			fd=open(name, O_WRONLY|O_CREAT|O_TRUNC, 0600);
			if (fd == -1) {
				vulpes_log(LOG_ERRORS, "Couldn't open chunk "
							"file: %s", name);
				return 1;
			}
			if (write(fd, buf, cdp->length) != cdp->length) {
				vulpes_log(LOG_ERRORS, "Couldn't write chunk "
							"file: %s", name);
				return 1;
			}
			if (close(fd) && errno != EINTR) {
				vulpes_log(LOG_ERRORS, "Couldn't write chunk "
							"file: %s", name);
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
		vulpes_log(LOG_ERRORS, "Couldn't open stats file: %s", name);
		return 1;
	}
	fprintf(fp, "%u\n%llu\n", modified_chunks, modified_bytes);
	fclose(fp);
	vulpes_log(LOG_STATS, "Copied %u modified chunks, %llu bytes",
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

	vulpes_log(LOG_BASIC, "Checking cache consistency");
	printf("Checking local cache for internal consistency...\n");
	buf=malloc(state.chunksize_bytes);
	if (buf == NULL) {
		vulpes_log(LOG_ERRORS, "malloc failed");
		return 1;
	}
	foreach_chunk(chunk_num, cdp) {
		if (!cdp_present(cdp)) {
			continue;
		}
		if (pread(state.cachefile_fd, buf, cdp->length,
				get_image_offset_from_chunk_num(chunk_num))
				!= cdp->length) {
			vulpes_log(LOG_ERRORS, "Couldn't read chunk from "
						"local cache: %u", chunk_num);
			return 1;
		}
		digest(buf, cdp->length, tag);
		if (check_tag(cdp, tag) == VULPES_TAGFAIL) {
			vulpes_log(LOG_ERRORS, "Chunk %u: tag check failure",
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
		vulpes_log(LOG_ERRORS, "Couldn't compare keyrings");
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
