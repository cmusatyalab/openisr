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

#include <unistd.h>
#include "defs.h"

struct pk_config config = {
	.log_file_mask = (1 << LOG_INFO) | (1 << LOG_ERROR) | (1 << LOG_STATS),
	.log_stderr_mask = 1 << LOG_ERROR,
	.compress = COMP_NONE
};
struct pk_parcel parcel;
struct pk_state state;

int main(int argc, char **argv)
{
	enum mode mode;
	int completion_fd=-1;
	char ret=1;
	int have_sql=0;
	int have_cache=0;
	int have_hoard=0;
	int have_transport=0;
	int have_nexus=0;
	int have_lock=0;
	pk_err_t err;

	mode=parse_cmdline(argc, argv);
	/* Trivial modes (usage, version) have already been handled by
	   parse_cmdline() */

	log_start();

	/* We can't take the lock until we fork (if we're going to do that) */
	if (config.flags & WANT_BACKGROUND)
		if (fork_and_wait(&completion_fd))
			goto shutdown;

	/* Now take the lock */
	if (config.flags & WANT_LOCK) {
		err=acquire_lockfile();
		if (err) {
			pk_log(LOG_ERROR, "Couldn't acquire parcel lock: %s",
						pk_strerror(err));
			goto shutdown;
		} else {
			have_lock=1;
		}
	}

	/* Now that we have the lock, it's safe to create the pidfile */
	if (config.flags & WANT_BACKGROUND)
		if (create_pidfile())
			goto shutdown;

	if (config.parcel_dir != NULL)
		if (parse_parcel_cfg())
			goto shutdown;

	sql_init();
	have_sql=1;

	if (cache_init())
		goto shutdown;
	else
		have_cache=1;

	if (config.hoard_index != NULL) {
		if (hoard_init())
			goto shutdown;
		else
			have_hoard=1;
	}

	if (config.flags & WANT_TRANSPORT) {
		if (transport_init())
			goto shutdown;
		else
			have_transport=1;
	}

	if (mode == MODE_RUN) {
		if (nexus_init())
			goto shutdown;
		else
			have_nexus=1;
	}

	/* Release our parent, if we've forked */
	if (completion_fd != -1) {
		close(completion_fd);
		completion_fd=-1;
	}

	if (mode == MODE_RUN) {
		nexus_run();
		ret=0;
	} else if (mode == MODE_UPLOAD) {
		ret=copy_for_upload();
	} else if (mode == MODE_VALIDATE) {
		ret=validate_cache();
	} else if (mode == MODE_EXAMINE) {
		ret=examine_cache();
		if (config.hoard_dir && !ret)
			ret=examine_hoard();
	} else if (mode == MODE_HOARD) {
		ret=hoard();
	} else if (mode == MODE_LISTHOARD) {
		ret=list_hoard();
	} else if (mode == MODE_RMHOARD) {
		ret=rmhoard();
	} else if (mode == MODE_CHECKHOARD) {
		ret=check_hoard();
	} else if (mode == MODE_REFRESH) {
		ret=hoard_refresh();
	} else {
		pk_log(LOG_ERROR, "Unknown mode");
	}

shutdown:
	if (have_nexus)
		nexus_shutdown();
	if (have_transport)
		transport_shutdown();
	if (have_hoard)
		hoard_shutdown();
	if (have_cache)
		cache_shutdown();
	if (have_sql)
		sql_shutdown();
	if (have_lock) {
		remove_pidfile();  /* safe if lock held */
		release_lockfile();
	}
	log_shutdown();  /* safe to call unconditionally */
	if (completion_fd != -1)
		write(completion_fd, &ret, 1);
	return ret;
}
