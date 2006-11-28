/*
                               Fauxide

		      A virtual disk drive tool
 
               Copyright (c) 2002-2004, Intel Corporation
                          All Rights Reserved

This software is distributed under the terms of the Eclipse Public License, 
Version 1.0 which can be found in the file named LICENSE.  ANY USE, 
REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
ACCEPTANCE OF THIS AGREEMENT

*/

/* INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "vulpes.h"
#include "vulpes_log.h"
#include "vulpes_lka.h"
#include "vulpes_util.h"

/* GLOBALS */

struct vulpes_config config;
struct vulpes_state state;

/* LOCALS */

/* vulpes_getopt() requires this to be a bitmask */
enum mode_type {
  MODE_RUN      = 0x01,
  MODE_UPLOAD   = 0x02,
  MODE_EXAMINE  = 0x04,
  MODE_HELP     = 0x08,
  MODE_VERSION  = 0x10,
};

struct vulpes_mode {
  char *name;
  enum mode_type type;
  char *desc;
};

static struct vulpes_mode vulpes_modes[] = {
  {"run",       MODE_RUN,     "Bind and service a virtual disk"},
  {"upload",    MODE_UPLOAD,  "Split a cache file into individual chunks for upload"},
  {"examine",   MODE_EXAMINE, "Print cache statistics and optionally validate vs. keyring"},
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
static struct vulpes_mode *curmode;

struct vulpes_option {
  char *name;
  unsigned retval;
  enum arg_type type;
  unsigned mask;
  char *args[MAXPARAMS];
  char *comment;
  unsigned _seen;  /* internal use by vulpes_getopt() */
};

enum option {
  OPT_CACHE,
  OPT_MASTER,
  OPT_KEYRING,
  OPT_PREV_KEYRING,
  OPT_LKA,
  OPT_LOG,
  OPT_PROXY,
  OPT_DESTDIR,
  OPT_FOREGROUND,
  OPT_PID,
  OPT_MODE,
  OPT_VALIDATE,
};

#define NONTRIVIAL_MODES (MODE_RUN|MODE_UPLOAD|MODE_EXAMINE)
static struct vulpes_option vulpes_options[] = {
  {"cache",          OPT_CACHE,          REQUIRED, NONTRIVIAL_MODES               , {"local_cache_dir"}},
  {"master",         OPT_MASTER,         REQUIRED, MODE_RUN                       , {"transfertype", "master_disk_location/url"},            "transfertype is one of: local http"},
  {"keyring",        OPT_KEYRING,        REQUIRED, NONTRIVIAL_MODES               , {"hex_keyring_file", "binary_keyring_file"}},
  {"prev-keyring",   OPT_PREV_KEYRING,   REQUIRED, NONTRIVIAL_MODES               , {"old_hex_keyring_file", "old_bin_keyring_file"}},
  {"lka",            OPT_LKA,            ANY,      MODE_RUN                       , {"lkatype", "lkadir"},                                   "lkatype must be hfs-sha-1"},
  {"destdir",        OPT_DESTDIR,        REQUIRED, MODE_UPLOAD                    , {"dir"}},
  {"validate",       OPT_VALIDATE,       OPTIONAL, MODE_EXAMINE                   , {}},
  {"log",            OPT_LOG,            OPTIONAL, NONTRIVIAL_MODES               , {"logfile", "info_str", "filemask", "stdoutmask"}},
  {"proxy",          OPT_PROXY,          OPTIONAL, MODE_RUN                       , {"proxy_server", "port_number"},                         "proxy_server is the ip address or the hostname of the proxy"},
  {"foreground",     OPT_FOREGROUND,     OPTIONAL, MODE_RUN                       , {},                                                      "Don't run in the background"},
  {"pid",            OPT_PID,            OPTIONAL, MODE_RUN                       , {},                                                      "Print process ID at startup"},
  {"mode",           OPT_MODE,           OPTIONAL, MODE_HELP                      , {"mode"},                                                "Print detailed usage message about the given mode"},
  {0}
};

/* FUNCTIONS */
static void usage(struct vulpes_mode *mode) __attribute__ ((noreturn));
static void usage(struct vulpes_mode *mode)
{
  struct vulpes_mode *mtmp;
  struct vulpes_option *otmp;
  char *str_start=NULL;
  char *str_end=NULL;
  int i;
  int have_options=0;
  
  if (mode == NULL) {
    printf("Usage: %s <mode> <options>\n", progname);
    printf("Available modes:\n");
    for (mtmp=vulpes_modes; mtmp->name != NULL; mtmp++) {
      printf("     %-11s %s\n", mtmp->name, mtmp->desc);
    }
    printf("Run \"%s help --mode <mode>\" for more information.\n", progname);
  } else {
    for (otmp=vulpes_options; otmp->name != NULL; otmp++) {
      if ((otmp->mask & mode->type) != mode->type)
	continue;
      if (!have_options) {
	have_options=1;
	printf("Usage: %s %s <options>\n", progname, mode->name);
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
static int vulpes_getopt(int argc, char *argv[], struct vulpes_option *opts)
{
  static int optind=2;  /* ignore argv[0] and argv[1] */
  char *arg;
  int i;
  
  if (optind == argc) {
    /* We've read the entire command line; make sure all required arguments
       have been handled */
    for (; opts->name != NULL; opts++) {
      if ((opts->mask & curmode->type) != curmode->type)
	continue;
      if (opts->type == REQUIRED && !opts->_seen)
	PARSE_ERROR("missing required option --%s", opts->name);
    }
    return -1;
  }
  
  arg=argv[optind++];
  if (arg[0] != '-' || arg[1] != '-')
    PARSE_ERROR("\"%s\" is not an option element", arg);
  arg += 2;
  
  for (; opts->name != NULL; opts++) {
    if (!strcmp(opts->name, arg)) {
      if ((opts->mask & curmode->type) != curmode->type)
	PARSE_ERROR("--%s not valid in this mode", arg);
      if (opts->type != ANY && opts->_seen)
	PARSE_ERROR("--%s may only be specified once", arg);
      opts->_seen++;
      for (i=0; i < MAXPARAMS && opts->args[i] != NULL; i++) {
	if (optind == argc)
	  PARSE_ERROR("wrong number of arguments to --%s", arg);
	optparams[i]=argv[optind++];
	if (optparams[i][0] == '-' && optparams[i][1] == '-')
	  PARSE_ERROR("wrong number of arguments to --%s", arg);
      }
      return opts->retval;
    }
  }
  PARSE_ERROR("unknown option --%s", arg);
}

static struct vulpes_mode *parse_mode(char *name)
{
  struct vulpes_mode *cur;
  
  for (cur=vulpes_modes; cur->name != NULL; cur++) {
    if (!strcmp(name, cur->name))
      return cur;
  }
  return NULL;
}

static unsigned long parseul(char *arg, int base)
{
  unsigned long val;
  char *endptr;
  val=strtoul(arg, &endptr, base);
  if (*arg == 0 || *endptr != 0)
    PARSE_ERROR("invalid integer value: %s", arg);
  return val;
}

int main(int argc, char *argv[])
{
  struct vulpes_mode *help_mode=NULL;
  int opt;
  int foreground;
  char ret=1;
  int ret_fd=-1;
  vulpes_err_t err;
  
  /* Parse mode */
  progname=argv[0];
  if (argc < 2) {
    usage(NULL);
  }
  curmode=parse_mode(argv[1]);
  if (curmode == NULL)
    PARSE_ERROR("Unknown subcommand %s", argv[1]);
  
  /* Set defaults */
  /* If --log is not specified, log errors to stdout */
  config.log_infostr=":";
  config.log_stdout_mask=0x1;
  /* Run in foreground except in run mode */
  foreground=(curmode->type != MODE_RUN);
  
  /* Parse command line */
  while ((opt=vulpes_getopt(argc, argv, vulpes_options)) != -1) {
    switch (opt) {
    case OPT_FOREGROUND:
      foreground=1;
      break;
    case OPT_PID:
      printf("VULPES: pid = %u\n", (unsigned) getpid());
      break;
    case OPT_CACHE:
      config.cache_name=optparams[0];
      break;
    case OPT_MASTER:
      if (strcmp("http", optparams[0])==0)
	config.trxfer=HTTP_TRANSPORT;
      else if (strcmp("local", optparams[0])==0)
	config.trxfer=LOCAL_TRANSPORT;
      else
	PARSE_ERROR("unknown transport type.");
      config.master_name=optparams[1];
      break;
    case OPT_KEYRING:
      config.hex_keyring_name=optparams[0];
      config.bin_keyring_name=optparams[1];
      break;
    case OPT_PREV_KEYRING:
      config.old_hex_keyring_name=optparams[0];
      config.old_bin_keyring_name=optparams[1];
      break;
    case OPT_DESTDIR:
      config.dest_dir_name=optparams[0];
      break;
    case OPT_VALIDATE:
      config.check_consistency=1;
      break;
    case OPT_LOG:
      config.log_file_name=optparams[0];
      config.log_infostr=optparams[1];
      config.log_file_mask=parseul(optparams[2], 0);
      config.log_stdout_mask=parseul(optparams[3], 0);
      break;
    case OPT_PROXY:
      config.proxy_name=optparams[0];
      config.proxy_port=parseul(optparams[1], 10);
      break;
    case OPT_LKA:
      /* XXX this is lame */
      if (strcmp("hfs-sha-1", optparams[0]))
	PARSE_ERROR("invalid LKA type.");
      if(config.lka_svc == NULL)
	if(vulpes_lka_open())
	  vulpes_log(LOG_ERRORS,"unable to open lka service");
      if(config.lka_svc != NULL)
	if(vulpes_lka_add(LKA_HFS, LKA_TAG_SHA1, optparams[1]))
	  vulpes_log(LOG_ERRORS,"unable to add lka database %s",optparams[1]);
      break;
    case OPT_MODE:
      help_mode=parse_mode(optparams[0]);
      if (help_mode == NULL)
	PARSE_ERROR("Unknown subcommand %s; try \"%s help\"", optparams[0], progname);
      break;
    }
  }
  
  /* Handle trivial modes here so we don't have to go through the
     startup sequence. */
  switch (curmode->type) {
  case MODE_HELP:
    usage(help_mode);
    /* Does not return */
  case MODE_VERSION:
    printf("OpenISR Vulpes revision %s (%s)\n", svn_revision, svn_branch);
    return 1;
  default:
    break;
  }
  
  /* If we're going to run in the background, fork. */
  if (!foreground && fork_and_wait(&ret_fd))
    goto vulpes_exit;
  
  /* Start vulpes log */
  if (vulpes_log_init())
    goto vulpes_exit;
  vulpes_log(LOG_BASIC,"Starting. Revision: %s (%s), PID: %u",
             svn_revision, svn_branch, (unsigned)getpid());
  
  /* Initialize the cache */
  err=cache_init();
  if (err) {
    vulpes_log(LOG_ERRORS,"unable to initialize cache: %s",vulpes_strerror(err));
    goto vulpes_exit;
  }
  
  /* XXX we don't do proper cleanup in the error paths */
  
  switch (curmode->type) {
  case MODE_UPLOAD:
    ret=copy_for_upload();
    break;
  case MODE_EXAMINE:
    ret=examine_cache();
    break;
  case MODE_RUN:
    /* Initialize transport */
    if (transport_init()) {
      vulpes_log(LOG_ERRORS,"unable to initialize transport");
      goto vulpes_exit;
    }
    
    /* Set up kernel driver */
    if (driver_init()) {
      /* driver_init() has already complained to the log */
      goto vulpes_exit;
    }
    
    /* Okay, now we're running.  Notify the parent, if any. */
    vulpes_log(LOG_BASIC,"Initialization complete");
    if (ret_fd != -1) {
      close(ret_fd);
      ret_fd=-1;
    }
    ret=0;
    
    /* Enter main loop */
    driver_run();
    
    vulpes_log(LOG_BASIC,"Beginning vulpes shutdown sequence");
  
    /* Shut down kernel driver */
    driver_shutdown();
    
    /* Shut down transport */
    transport_shutdown();
    break;
  default:
    break;
  }
  
  /* Shut down cache */
  err=cache_shutdown();
  if (err) {
    vulpes_log(LOG_ERRORS,"cache shutdown failed: %s",vulpes_strerror(err));
    ret=1;
  }

  /* Close the LKA service */
  if(config.lka_svc != NULL)
    if(vulpes_lka_close())
      vulpes_log(LOG_ERRORS,"failure during lka_close().");    
  
 vulpes_exit:
  vulpes_log(LOG_BASIC,"Exiting: status %d",ret);
  vulpes_log_close();
  if (ret_fd != -1)
    write(ret_fd, &ret, sizeof(ret));
  return ret;
}
