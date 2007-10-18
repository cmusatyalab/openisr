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

#define MAXPARAMS 4

enum arg_type {
	REQUIRED,
	OPTIONAL,
	ANY,  /* any number permitted, including zero */
};

enum option {
	OPT_PARCEL,
	OPT_HOARD,
	OPT_UUID,
	OPT_DESTDIR,
	OPT_MINSIZE,
	OPT_COMPRESSION,
	OPT_LOG,
	OPT_FOREGROUND,
	OPT_MODE,
	END_OPTS = -1
};

struct pk_option {
	char *name;
	enum option opt;
	char *args[MAXPARAMS];
	char *comment;
};

struct pk_option_record {
	enum option opt;
	enum arg_type type;
	char *comment;
	unsigned _seen;  /* internal use by pk_getopt() */
};

struct pk_mode {
	char *name;
	enum mode type;
	unsigned flags;
	struct pk_option_record *opts;
	char *desc;
};

static struct pk_option pk_options[] = {
	{"parcel",         OPT_PARCEL,         {"parcel_dir"}},
	{"hoard",          OPT_HOARD,          {"hoard_dir"}},
	{"uuid",           OPT_UUID,           {"uuid"}},
	{"destdir",        OPT_DESTDIR,        {"dir"}},
	{"minsize",        OPT_MINSIZE,        {"MB"},                                                  "Don't garbage-collect hoard cache below this size"},
	{"compression",    OPT_COMPRESSION,    {"algorithm"},                                           "Accepted algorithms: none (default), zlib, lzf"},
	{"log",            OPT_LOG,            {"logfile", "info_str", "filemask", "stderrmask"}},
	{"foreground",     OPT_FOREGROUND,     {},                                                      "Don't run in the background"},
	{"mode",           OPT_MODE,           {"mode"},                                                "Print detailed usage message about the given mode"},
	{0}
};

#define mode(sym) static struct pk_option_record sym ## _opts[]

mode(RUN) = {
	{OPT_PARCEL,        REQUIRED},
	{OPT_HOARD,         OPTIONAL},
	{OPT_COMPRESSION,   OPTIONAL},
	{OPT_LOG,           OPTIONAL},
	{OPT_FOREGROUND,    OPTIONAL},
	{END_OPTS}
};

mode(UPLOAD) = {
	{OPT_PARCEL,        REQUIRED},
	{OPT_DESTDIR,       REQUIRED},
	{OPT_HOARD,         OPTIONAL, "Also update the specified hoard cache"},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(HOARD) = {
	{OPT_PARCEL,        REQUIRED},
	{OPT_HOARD,         REQUIRED},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(EXAMINE) = {
	{OPT_PARCEL,        REQUIRED},
	{OPT_HOARD,         OPTIONAL, "Print statistics on the specified hoard cache"},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(VALIDATE) = {
	{OPT_PARCEL,        REQUIRED},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(LISTHOARD) = {
	{OPT_HOARD,         REQUIRED},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(CHECKHOARD) = {
	{OPT_HOARD,         REQUIRED},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(RMHOARD) = {
	{OPT_HOARD,         REQUIRED},
	{OPT_UUID,          REQUIRED, "UUID of parcel to remove from hoard cache"},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(REFRESH) = {
	{OPT_PARCEL,        REQUIRED},
	{OPT_HOARD,         REQUIRED},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(GC) = {
	{OPT_HOARD,         REQUIRED},
	{OPT_MINSIZE,       OPTIONAL},
	{OPT_LOG,           OPTIONAL},
	{END_OPTS}
};

mode(HELP) = {
	{OPT_MODE,          OPTIONAL},
	{END_OPTS}
};

mode(VERSION) = {
	{END_OPTS}
};

#undef mode

#define RUN_flags		WANT_LOCK|WANT_CACHE|WANT_BACKGROUND|WANT_TRANSPORT
#define UPLOAD_flags		WANT_LOCK|WANT_CACHE|WANT_PREV
#define HOARD_flags		WANT_PREV|WANT_TRANSPORT
#define EXAMINE_flags		WANT_CACHE|WANT_PREV
#define VALIDATE_flags		WANT_LOCK|WANT_CACHE|WANT_PREV
#define LISTHOARD_flags		0
#define CHECKHOARD_flags	0
#define RMHOARD_flags		0
#define REFRESH_flags		WANT_PREV
#define GC_flags		0
#define HELP_flags		0
#define VERSION_flags		0

#define sym(str) MODE_ ## str, str ## _flags, str ## _opts
static struct pk_mode pk_modes[] = {
	{"run",         sym(RUN),        "Bind and service a virtual disk"},
	{"upload",      sym(UPLOAD),     "Split a local cache into individual chunks for upload"},
	{"hoard",       sym(HOARD),      "Download all chunks into hoard cache"},
	{"examine",     sym(EXAMINE),    "Print cache statistics"},
	{"validate",    sym(VALIDATE),   "Validate local cache against keyring"},
	{"listhoard",   sym(LISTHOARD),  "List parcels in hoard cache"},
	{"checkhoard",  sym(CHECKHOARD), "Validate hoard cache"},
	{"rmhoard",     sym(RMHOARD),    "Remove parcel from hoard cache"},
	{"refresh",     sym(REFRESH),    "Update hoard cache reference list"},
	{"gc",          sym(GC),         "Garbage-collect hoard cache"},
	{"help",        sym(HELP),       "Show usage summary"},
	{"version",     sym(VERSION),    "Show version information"},
	{0}
};
#undef sym

static char *optparams[MAXPARAMS];
static char *progname;
static struct pk_mode *curmode;

static struct pk_option *get_option(enum option opt)
{
	struct pk_option *curopt;

	for (curopt=pk_options; curopt->name != NULL; curopt++) {
		if (curopt->opt == opt)
			return curopt;
	}
	printf("BUG: Unknown option %d\n", opt);
	return NULL;
}

static void usage(struct pk_mode *mode) __attribute__ ((noreturn));
static void usage(struct pk_mode *mode)
{
	struct pk_mode *mtmp;
	struct pk_option_record *rtmp;
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
		for (rtmp=mode->opts; rtmp->opt != END_OPTS; rtmp++) {
			otmp=get_option(rtmp->opt);
			if (!have_options) {
				have_options=1;
				printf("Usage: %s %s <options>\n", progname,
							mode->name);
				printf("Available options:\n");
			}
			switch (rtmp->type) {
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
			if (rtmp->comment != NULL)
				printf("          %s\n", rtmp->comment);
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
static enum option pk_getopt(int argc, char *argv[])
{
	static int optind=2;  /* ignore argv[0] and argv[1] */
	struct pk_option_record *opts;
	struct pk_option *curopt;
	char *arg;
	int i;

	if (optind == argc) {
		/* We've read the entire command line; make sure all required
		   arguments have been handled */
		for (opts=curmode->opts; opts->opt != END_OPTS; opts++) {
			if (opts->type == REQUIRED && !opts->_seen)
				PARSE_ERROR("missing required option --%s",
						get_option(opts->opt)->name);
		}
		return -1;
	}

	arg=argv[optind++];
	if (arg[0] != '-' || arg[1] != '-')
		PARSE_ERROR("\"%s\" is not an option element", arg);
	arg += 2;

	for (opts=curmode->opts; opts->opt != END_OPTS; opts++) {
		curopt=get_option(opts->opt);
		if (strcmp(curopt->name, arg))
			continue;
		if (opts->type != ANY && opts->_seen)
			PARSE_ERROR("--%s may only be specified once", arg);
		opts->_seen++;
		for (i=0; i < MAXPARAMS && curopt->args[i] != NULL; i++) {
			if (optind == argc)
				PARSE_ERROR("wrong number of arguments to --%s",
							arg);
			optparams[i]=argv[optind++];
			if (optparams[i][0] == '-' &&
						optparams[i][1] == '-')
				PARSE_ERROR("wrong number of arguments to --%s",
							arg);
		}
		return opts->opt;
	}

	/* This option is invalid.  See if it would have been valid for a
	   different mode. */
	for (curopt=pk_options; curopt->name != NULL; curopt++)
		if (!strcmp(curopt->name, arg))
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
	config.flags=curmode->flags;

	while ((opt=pk_getopt(argc, argv)) != END_OPTS) {
		switch (opt) {
		case OPT_PARCEL:
			config.parcel_dir=optparams[0];
			check_dir(config.parcel_dir);
			cp=config.parcel_dir;
			config.parcel_cfg=filepath(cp, "parcel.cfg", 1);
			config.keyring=filepath(cp, "keyring",
						config.flags & WANT_CACHE);
			config.prev_keyring=filepath(cp, "prev-keyring",
						config.flags & WANT_PREV);
			config.cache_file=filepath(cp, "disk", 0);
			config.cache_index=filepath(cp, "disk.idx", 0);
			config.devfile=filepath(cp, "parcelkeeper.dev", 0);
			config.lockfile=filepath(cp, "parcelkeeper.lock", 0);
			config.pidfile=filepath(cp, "parcelkeeper.pid", 0);
			break;
		case OPT_UUID:
			if (canonicalize_uuid(optparams[0], &config.uuid))
				PARSE_ERROR("invalid uuid: %s", optparams[0]);
			break;
		case OPT_DESTDIR:
			config.dest_dir=optparams[0];
			config.dest_stats=filepath(optparams[0], "stats", 0);
			break;
		case OPT_MINSIZE:
			if (parseuint(&config.minsize, optparams[0], 10))
				PARSE_ERROR("invalid integer value: %s",
							optparams[0]);
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
			config.flags &= ~WANT_BACKGROUND;
			break;
		case OPT_MODE:
			helpmode=parse_mode(optparams[0]);
			if (helpmode == NULL)
				PARSE_ERROR("unknown mode %s; try \"%s help\"",
							optparams[0],
							progname);
			break;
		case END_OPTS:
			/* Silence compiler warning */
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
