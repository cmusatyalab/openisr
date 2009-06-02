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

#include <unistd.h>
#include <signal.h>
#include "defs.h"

struct pk_config config = {
	/* WARNING implies ERROR */
	.log_file_mask = (1 << LOG_INFO) | (1 << LOG_WARNING) |
				(1 << LOG_STATS),
	.log_stderr_mask = 1 << LOG_WARNING,
	.compress = COMP_NONE,
	.nexus_cache = 32, /* MB */
};
struct pk_parcel parcel;
struct pk_state state;

static const int ignored_signals[]={SIGUSR1, SIGUSR2, 0};
static const int caught_signals[]={SIGINT, SIGTERM, SIGHUP, 0};

int main(int argc, char **argv)
{
	gchar *progname;
	enum mode mode;
	int completion_fd=-1;
	char ret=1;
	int sig;
	int have_cache=0;
	int have_hoard=0;
	int have_transport=0;
	int have_nexus=0;
	int have_lock=0;
	pk_err_t err;

	if (!g_thread_supported())
		g_thread_init(NULL);

	if (setup_signal_handlers(generic_signal_handler, caught_signals,
				ignored_signals)) {
		/* Logging isn't up yet */
		printf("Couldn't set up signal handlers\n");
		return 1;
	}

	progname = g_path_get_basename(argv[0]);
	g_set_prgname(progname);
	g_free(progname);
	mode=parse_cmdline(&config, argc - 1, argv + 1);
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
		if (parse_parcel_cfg(&parcel))
			goto shutdown;

	sql_init();

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

	if (pending_signal())
		goto shutdown;

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
	state.override_signal=1;
	if (have_nexus)
		nexus_shutdown();
	if (have_transport)
		transport_shutdown();
	if (have_hoard)
		hoard_shutdown();
	if (have_cache)
		cache_shutdown();
	if (have_lock) {
		remove_pidfile();  /* safe if lock held */
		release_lockfile();
	}
	log_shutdown();  /* safe to call unconditionally */
	if (completion_fd != -1)
		write(completion_fd, &ret, 1);
	sig=state.signal;
	if (sig) {
		/* Make sure our exit status reflects the fact that we died
		   on a signal.  If we're backgrounded, the parent will pick
		   this up in fork_and_wait(). */
		set_signal_handler(sig, SIG_DFL);
		raise(sig);
	}
	return ret;
}
