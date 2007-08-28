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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "defs.h"

struct pk_mode {
	char *name;
	enum mode type;
	char *desc;
};

static struct pk_mode pk_modes[] = {
	{"run",       MODE_RUN,     "Bind and service a virtual disk"},
	{"upload",    MODE_UPLOAD,  "Split a cache file into individual chunks for upload"},
	{"hoard",     MODE_HOARD,   "Download all chunks into hoard cache"},
	{"examine",   MODE_EXAMINE, "Print cache statistics"},
	{"validate",  MODE_VALIDATE,"Validate cache against keyring"},
	{"help",      MODE_HELP,    "Show usage summary"},
	{"version",   MODE_VERSION, "Show version information"},
	{0}
};

enum arg_type {
	REQUIRED,
	OPTIONAL,
	ANY,  /* any number permitted, including zero */
};

#define MAXPARAMS 4
static char *optparams[MAXPARAMS];
static char *progname;
static struct pk_mode *curmode;

struct pk_option {
	char *name;
	unsigned retval;
	enum arg_type type;
	unsigned mask;
	char *args[MAXPARAMS];
	char *comment;
	unsigned _seen;  /* internal use by pk_getopt() */
};

enum option {
	OPT_USER,
	OPT_PARCEL,
	OPT_PARCELDIR,
	OPT_CACHE,
	OPT_LAST,
	OPT_DESTDIR,
	OPT_COMPRESSION,
	OPT_HOARD,
	OPT_LOG,
	OPT_FOREGROUND,
	OPT_MODE,
};

#define POSTPROCESS_MODES (MODE_UPLOAD|MODE_EXAMINE|MODE_VALIDATE)
#define NONRUN_MODES (POSTPROCESS_MODES|MODE_HOARD)
#define NONTRIVIAL_MODES (MODE_RUN|NONRUN_MODES)
static struct pk_option pk_options[] = {
	{"user",           OPT_USER,           REQUIRED, NONTRIVIAL_MODES               , {"user_name"}},
	{"parcel",         OPT_PARCEL,         REQUIRED, NONTRIVIAL_MODES               , {"parcel_name"}},
	{"parceldir",      OPT_PARCELDIR,      REQUIRED, NONTRIVIAL_MODES               , {"parcel_dir"}},
	{"cache",          OPT_CACHE,          REQUIRED, POSTPROCESS_MODES|MODE_RUN     , {"local_cache_dir"}},
	{"last",           OPT_LAST,           REQUIRED, NONRUN_MODES                   , {"last_cache_dir"}},
	{"destdir",        OPT_DESTDIR,        REQUIRED, MODE_UPLOAD                    , {"dir"}},
	{"hoard",          OPT_HOARD,          REQUIRED, MODE_HOARD                     , {"hoard_dir"}},
	{"hoard",          OPT_HOARD,          OPTIONAL, POSTPROCESS_MODES|MODE_RUN     , {"hoard_dir"}},
	{"compression",    OPT_COMPRESSION,    OPTIONAL, MODE_RUN                       , {"algorithm"},                                           "Accepted algorithms: none (default), zlib, lzf"},
	{"log",            OPT_LOG,            OPTIONAL, NONTRIVIAL_MODES               , {"logfile", "info_str", "filemask", "stderrmask"}},
	{"foreground",     OPT_FOREGROUND,     OPTIONAL, MODE_RUN                       , {},                                                      "Don't run in the background"},
	{"mode",           OPT_MODE,           OPTIONAL, MODE_HELP                      , {"mode"},                                                "Print detailed usage message about the given mode"},
	{0}
};

static void usage(struct pk_mode *mode) __attribute__ ((noreturn));
static void usage(struct pk_mode *mode)
{
	struct pk_mode *mtmp;
	struct pk_option *otmp;
	char *str_start=NULL;
	char *str_end=NULL;
	int i;
	int have_options=0;

	if (mode == NULL) {
		printf("Usage: %s <mode> <options>\n", progname);
		printf("Available modes:\n");
		for (mtmp=pk_modes; mtmp->name != NULL; mtmp++) {
			printf("     %-11s %s\n", mtmp->name, mtmp->desc);
		}
		printf("Run \"%s help --mode <mode>\" for more information.\n",
					progname);
	} else {
		for (otmp=pk_options; otmp->name != NULL; otmp++) {
			if ((otmp->mask & mode->type) != mode->type)
				continue;
			if (!have_options) {
				have_options=1;
				printf("Usage: %s %s <options>\n", progname,
							mode->name);
				printf("Available options:\n");
			}
			switch (otmp->type) {
			case REQUIRED:
				str_start=" ";
				str_end="";
				break;
			case OPTIONAL:
				str_start="[";
				str_end="]";
				break;
			case ANY:
				str_start="[";
				str_end="]+";
				break;
			}
			printf("    %s--%s", str_start, otmp->name);
			for (i=0; i<MAXPARAMS; i++) {
				if (otmp->args[i] == NULL)
					break;
				printf(" <%s>", otmp->args[i]);
			}
			printf("%s\n", str_end);
			if (otmp->comment != NULL)
				printf("          %s\n", otmp->comment);
		}
		if (!have_options)
			printf("Usage: %s %s\n", progname, mode->name);
	}
	exit(1);
}

#define PARSE_ERROR(str, args...) do { \
		printf("ERROR: " str "\n\n" , ## args); \
		usage(curmode); \
	} while (0)

/* Instead of using getopt_long() we roll our own.  getopt_long doesn't support
   several things we need:
   - More than one parameter per option
   - Checking for required or once-only options
   - Different permissible parameters depending on circumstances (mode)
*/
static int pk_getopt(int argc, char *argv[], struct pk_option *opts)
{
	static int optind=2;  /* ignore argv[0] and argv[1] */
	struct pk_option *orig_opts=opts;
	char *arg;
	int i;

	if (optind == argc) {
		/* We've read the entire command line; make sure all required
		   arguments have been handled */
		for (; opts->name != NULL; opts++) {
			if ((opts->mask & curmode->type) != curmode->type)
				continue;
			if (opts->type == REQUIRED && !opts->_seen)
				PARSE_ERROR("missing required option --%s",
							opts->name);
		}
		return -1;
	}

	arg=argv[optind++];
	if (arg[0] != '-' || arg[1] != '-')
		PARSE_ERROR("\"%s\" is not an option element", arg);
	arg += 2;

	for (; opts->name != NULL; opts++) {
		if ((opts->mask & curmode->type) != curmode->type)
			continue;
		if (strcmp(opts->name, arg))
			continue;
		if (opts->type != ANY && opts->_seen)
			PARSE_ERROR("--%s may only be specified once", arg);
		opts->_seen++;
		for (i=0; i < MAXPARAMS && opts->args[i] != NULL; i++) {
			if (optind == argc)
				PARSE_ERROR("wrong number of arguments to --%s",
							arg);
			optparams[i]=argv[optind++];
			if (optparams[i][0] == '-' &&
						optparams[i][1] == '-')
				PARSE_ERROR("wrong number of arguments to --%s",
							arg);
		}
		return opts->retval;
	}

	/* This option is invalid.  See if it would have been valid for a
	   different mode. */
	for (opts=orig_opts; opts->name != NULL; opts++)
		if (!strcmp(opts->name, arg))
			PARSE_ERROR("--%s not valid in this mode", arg);
	PARSE_ERROR("unknown option --%s", arg);
}

static struct pk_mode *parse_mode(char *name)
{
	struct pk_mode *cur;

	for (cur=pk_modes; cur->name != NULL; cur++) {
		if (!strcmp(name, cur->name))
			return cur;
	}
	return NULL;
}

static void check_dir(char *dir)
{
	if (!is_dir(dir))
		PARSE_ERROR("%s is not a valid directory", dir);
}

static char *filepath(char *dir, char *file, int must_exist)
{
	char *ret;
	if (asprintf(&ret, "%s/%s", dir, file) == -1)
		PARSE_ERROR("malloc failure");  /* XXX? */
	if (must_exist && !is_file(ret))
		PARSE_ERROR("%s does not exist", ret);
	return ret;
}

enum mode parse_cmdline(int argc, char **argv)
{
	struct pk_mode *helpmode=NULL;
	enum option opt;
	char *cp;

	progname=argv[0];
	if (argc < 2)
		usage(NULL);
	curmode=parse_mode(argv[1]);
	if (curmode == NULL)
		PARSE_ERROR("unknown mode %s", argv[1]);

	while ((opt=pk_getopt(argc, argv, pk_options)) != -1) {
		switch (opt) {
		case OPT_USER:
			config.user=optparams[0];
			break;
		case OPT_PARCEL:
			config.parcel=optparams[0];
			break;
		case OPT_PARCELDIR:
			config.parcel_dir=optparams[0];
			check_dir(config.parcel_dir);
			config.parcel_cfg=filepath(optparams[0], "parcel.cfg",
						1);
			break;
		case OPT_CACHE:
			config.cache_dir=optparams[0];
			check_dir(config.cache_dir);
			cp=config.cache_dir;
			config.keyring=filepath(cp, "keyring", 1);
			config.cache_file=filepath(cp, "disk", 0);
			config.cache_index=filepath(cp, "disk.idx", 0);
			config.devfile=filepath(cp, "parcelkeeper.dev", 0);
			config.lockfile=filepath(cp, "parcelkeeper.lock", 0);
			config.pidfile=filepath(cp, "parcelkeeper.pid", 0);
			break;
		case OPT_LAST:
			config.last_dir=optparams[0];
			check_dir(config.last_dir);
			config.last_keyring=filepath(optparams[0], "keyring",
						1);
			break;
		case OPT_DESTDIR:
			config.dest_dir=optparams[0];
			config.dest_stats=filepath(optparams[0], "stats", 0);
			break;
		case OPT_COMPRESSION:
			config.compress=parse_compress(optparams[0]);
			if (config.compress == COMP_UNKNOWN)
				PARSE_ERROR("invalid compression type: %s",
							optparams[0]);
			break;
		case OPT_HOARD:
			config.hoard_dir=optparams[0];
			config.hoard_file=filepath(optparams[0], "hoard", 0);
			config.hoard_index=filepath(optparams[0], "hoard.idx",
						0);
			break;
		case OPT_LOG:
			config.log_file=optparams[0];
			config.log_info_str=optparams[1];
			if (parseuint(&config.log_file_mask, optparams[2], 0))
				PARSE_ERROR("invalid integer value: %s",
							optparams[2]);
			if (parseuint(&config.log_stderr_mask, optparams[3], 0))
				PARSE_ERROR("invalid integer value: %s",
							optparams[3]);
			break;
		case OPT_FOREGROUND:
			config.foreground=1;
			break;
		case OPT_MODE:
			helpmode=parse_mode(optparams[0]);
			if (helpmode == NULL)
				PARSE_ERROR("unknown mode %s; try \"%s help\"",
							optparams[0],
							progname);
			break;
		}
	}

	if (curmode->type == MODE_HELP) {
		usage(helpmode);
	} else if (curmode->type == MODE_VERSION) {
		printf("OpenISR %s, Parcelkeeper revision %s\n", isr_release,
					rcs_revision);
		exit(0);
	}
	return curmode->type;
}
