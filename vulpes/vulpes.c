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

const char *vulpes_version = "0.60";

struct vulpes_config config;
struct vulpes_state state;
static char *progname;


/* FUNCTIONS */
static void version(void)
{
  printf("Version: %s (%s, rev %s)\n", vulpes_version, svn_branch, svn_revision);
}

static void usage(void) __attribute__ ((noreturn));
static void usage(void)
{
  version();
  printf("Usage: %s <options>\n", progname);
  printf("Options:\n");
  printf("\t--cache <local_cache_dir>\n");
  printf("\t--master <transfertype> <master_disk_location/url>\n");
    printf("\t\ttransfertype is one of: local http\n");
  printf("\t--keyring <hex_keyring_file> <binary_keyring_file>\n");
  printf("\t[--log <logfile> <info_str> <filemask> <stdoutmask>]\n");
  printf("\t[--debug]\n");
    printf("\t\tIf debug is chosen, then log messages for chosen loglevel(s)\n");
    printf("\t\twill be written out to the logfile without any buffering\n");
  printf("\t[--pid]\n");
  printf("\t[--lka <lkatype> <lkadir>]\n");
    printf("\t\tlkatype must be hfs-sha-1\n");
  printf("\t[--proxy proxy_server port-number]\n");
    printf("\t\tproxy_server is the ip address or the hostname of the proxy\n");
  printf("\t[--foreground]\n");
    printf("\t\tDon't run in the background\n");
  printf("Usage: %s --help                  Print usage summary and exit.\n", progname);
  printf("Usage: %s --version               Print version information and exit.\n", progname);
  exit(1);
}

#define PARSE_ERROR(str, args...) do { \
    printf("ERROR: " str "\n\n" , ## args); \
    usage(); \
  } while (0)

enum arg_type {
  REQUIRED,
  OPTIONAL,
  ANY,  /* any number permitted, including zero */
};

struct vulpes_option {
  char *name;
  unsigned retval;
  enum arg_type type;
  unsigned params;
  unsigned mask;
  unsigned _seen;  /* internal use by vulpes_getopt() */
};

#define MAXPARAMS 8
static char *optparams[MAXPARAMS];

/* Instead of using getopt_long() we roll our own.  getopt_long doesn't support
   several things we need:
   - More than one parameter per option
   - Checking for required or once-only options
   - Different permissible parameters depending on circumstances (mode)
 */
static int vulpes_getopt(int argc, char *argv[], struct vulpes_option *opts, unsigned mask)
{
  static int optind=2;  /* ignore argv[0] and argv[1] */
  char *arg;
  int i;
  
  if (optind == argc) {
    /* We've read the entire command line; make sure all required argument have
       been handled */
    for (; opts->name != NULL; opts++) {
      if ((opts->mask & mask) != mask)
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
      if ((opts->mask & mask) != mask)
	PARSE_ERROR("--%s not valid in this mode", arg);
      if (opts->type != ANY && opts->_seen)
	PARSE_ERROR("--%s may only be specified once", arg);
      opts->_seen++;
      if (opts->params > MAXPARAMS)
	PARSE_ERROR("BUG: option %s expects more than %d parameters", arg, MAXPARAMS);
      for (i=0; i<opts->params; i++) {
	if (optind == argc)
	  PARSE_ERROR("wrong number of arguments to --%s: should be %d", arg, opts->params);
	optparams[i]=argv[optind++];
	if (optparams[i][0] == '-' && optparams[i][1] == '-')
	  PARSE_ERROR("wrong number of arguments to --%s: should be %d", arg, opts->params);
      }
      return opts->retval;
    }
  }
  PARSE_ERROR("unknown option --%s", arg);
}

enum mode {
  MODE_RUN      = 0x01,
  MODE_UPLOAD   = 0x02,
  MODE_CHECK    = 0x04,
  MODE_HELP     = 0x08,
  MODE_VERSION  = 0x10,
};

enum option {
  OPT_CACHE,
  OPT_MASTER,
  OPT_KEYRING,
  OPT_LKA,
  OPT_LOG,
  OPT_PROXY,
  OPT_UPLOAD,
  OPT_FOREGROUND,
  OPT_PID,
};

static struct vulpes_option cmdline_options[] = {
  {"foreground", OPT_FOREGROUND, OPTIONAL,  0, MODE_RUN},
  {"pid",        OPT_PID,        OPTIONAL,  0, MODE_RUN},
  {"cache",      OPT_CACHE,      REQUIRED,  1, MODE_RUN|MODE_UPLOAD|MODE_CHECK},
  {"master",     OPT_MASTER,     REQUIRED,  2, MODE_RUN},
  {"keyring",    OPT_KEYRING,    REQUIRED,  2, MODE_RUN|MODE_UPLOAD|MODE_CHECK},
  {"upload",     OPT_UPLOAD,     REQUIRED,  2, MODE_UPLOAD},
  {"log",        OPT_LOG,        OPTIONAL,  4, MODE_RUN|MODE_UPLOAD|MODE_CHECK},
  {"proxy",      OPT_PROXY,      OPTIONAL,  2, MODE_RUN},
  {"lka",        OPT_LKA,        ANY,       2, MODE_RUN},
  {0}
};

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
  enum mode mode;
  int opt;
  int foreground=0;
  pid_t pid;
  int ret=1;
  
  progname=argv[0];
  /* parse command line */
  if (argc < 2) {
    usage();
  }
  
  if (!strcmp(argv[1], "run"))
    mode=MODE_RUN;
  else if (!strcmp(argv[1], "upload"))
    mode=MODE_UPLOAD;
  else if (!strcmp(argv[1], "check"))
    mode=MODE_CHECK;
  else if (!strcmp(argv[1], "help"))
    mode=MODE_HELP;
  else if (!strcmp(argv[1], "version"))
    mode=MODE_VERSION;
  else
    PARSE_ERROR("Unknown command %s", argv[1]);
  
  while ((opt=vulpes_getopt(argc, argv, cmdline_options, mode)) != -1) {
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
    case OPT_UPLOAD:
      config.old_keyring_name=optparams[0];
      config.dest_name=optparams[1];
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
	  printf("WARNING: unable to open lka service.\n");
      if(config.lka_svc != NULL)
	if(vulpes_lka_add(LKA_HFS, LKA_TAG_SHA1, optparams[1]))
	  printf("WARNING: unable to add lka database %s.\n", optparams[1]);
      break;
    }
  }
  
  /* Check arguments */
  switch (mode) {
  case MODE_HELP:
    usage();
  case MODE_VERSION:
    version();
    return 1;
  default:
    break;
  }
  
  if (config.log_file_name == NULL) {
    /* If --log is not specified, log errors to stdout with an empty infostr */
    config.log_infostr=":";
    config.log_stdout_mask=0x1;
  }
  if (vulpes_log_init())
    goto vulpes_exit;
  
  /* now that parameters are correct - start vulpes log */
  vulpes_log(LOG_BASIC,"Starting. Version: %s, revision: %s %s, PID: %u",
             vulpes_version, svn_branch, svn_revision, (unsigned)getpid());
  
  VULPES_DEBUG("Initializing cache...\n");
  /* Initialize the cache */
  if (cache_init()) {
    vulpes_log(LOG_ERRORS,"unable to initialize cache");
    goto vulpes_exit;
  }
  
  /* XXX we don't do proper cleanup in the error paths */
  
  switch (mode) {
  case MODE_UPLOAD:
    copy_for_upload(config.old_keyring_name, config.dest_name);
    /* Does not return */
  case MODE_CHECK:
    checktags();
    /* Does not return */
  default:
    break;
  }
  
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
  
  if (!foreground) {
    pid=fork();
    if (pid == -1) {
      vulpes_log(LOG_ERRORS,"fork() failed");
      goto vulpes_exit;
    } else if (pid) {
      exit(0);
    }
  }
  ret=0;
  
  /* Enter main loop */
  driver_run();
  
  vulpes_log(LOG_BASIC,"Beginning vulpes shutdown sequence");

  /* Shut down kernel driver */
  driver_shutdown();
  
  /* Shut down transport */
  transport_shutdown();

  /* Close file */
  VULPES_DEBUG("\tClosing cache.\n");
  if (cache_shutdown() == -1) {
      vulpes_log(LOG_ERRORS,"shutdown function failed");
      exit(1);
    }

  /* Close the LKA service */
  if(config.lka_svc != NULL)
    if(vulpes_lka_close())
      vulpes_log(LOG_ERRORS,"failure during lka_close().");    
  
 vulpes_exit:
  vulpes_log(LOG_BASIC,"Exiting");
  vulpes_log_close();
  return ret;
}
