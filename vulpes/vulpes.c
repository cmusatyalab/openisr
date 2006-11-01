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
//#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
/* XXX right now fauxide's data structures are accessed throughout the codebase
   rather than confining them to the fauxide driver */
#include "fauxide.h"
#include "vulpes.h"
#include "vulpes_fids.h"
#include "vulpes_log.h"
#include "vulpes_lka.h"

/* GLOBALS */

volatile int exit_pending = 0;

static unsigned long long sectors_read = 0;
static unsigned long long sectors_written = 0;
static unsigned long long sectors_accessed = 0;

const char *vulpes_version = "0.60";

struct vulpes_config config;
extern char *optarg;
extern int optind, opterr, optopt;


/* FUNCTIONS */
static void vulpes_signal_handler(int sig)
{
  VULPES_DEBUG("Caught signal %d\n", sig);
  exit_pending = 1;
}

int set_signal_handler(int sig, void (*handler)(int sig))
{
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler=handler;
  return sigaction(sig, &sa, NULL);
}

void tally_sector_accesses(unsigned write, unsigned num)
{
  sectors_accessed += num;
  
  if (write) {
    sectors_written += num;
  } else {
    sectors_read += num;
  }
  
#ifdef VERBOSE_DEBUG
  if (sectors_accessed % 1024 == 0) {
    printf(".");
    if (sectors_accessed % (20 * 1024) == 0) {
      printf(" %llu + %llu = %llu\n", sectors_read, sectors_written,
	     sectors_accessed);
    }
    fflush(stdout);
  }
#endif
}

static enum mapping_type char_to_mapping_type(const char *name)
{
  enum mapping_type result = NO_MAPPING;
  
  if (strcmp("lev1", name) == 0) {
    result = LEV1_MAPPING;
  } else if (strcmp("lev1-v", name) == 0) {
    /* XXX */
    result = LEV1V_MAPPING;
  } else if (strcmp("file", name) == 0) {
    result = SIMPLE_FILE_MAPPING;
  } else if (strcmp("disk", name) == 0) {
    result = SIMPLE_DISK_MAPPING;
  } else {
    result = NO_MAPPING;
  }
  
  return result;
}

static void initialize_config(void)
{
  config.trxfer = LOCAL_TRANSPORT;
  config.mapping = NO_MAPPING;
  
  config.proxy_name = NULL;
  config.proxy_port = 80;
  
  config.device_name = NULL;
  config.master_name = NULL;
  config.cache_name = NULL;
  
  config.keyring_name = NULL;
  
  config.vulpes_device = -1;
  
  config.reg.vulpes_id = -1;
  config.reg.pid = -1;
  config.reg.volsize = 0;
  
  config.volsize_func = NULL;
  config.read_func = NULL;
  config.write_func = NULL;
  config.shutdown_func = NULL;
  
  config.verbose = 0;
  
  config.lka_svc = NULL;
  config.special = NULL;
}

static void version(void)
{
  printf("Version: %s (%s, rev %s)\n", vulpes_version, svn_branch, svn_revision);
}

static void usage(const char *progname)
{
  version();
  printf("Usage: %s <options>\n", progname);
  printf("Options:\n");
  printf("\t--map <maptype> <device_name> <local_cache_name>\n");
    printf("\t\tmaptype has to be lev1\n");
  printf("\t--master <transfertype> <master_disk_location/url>\n");
    printf("\t\ttransfertype is one of: local http\n");
  printf("\t--keyring <keyring_file>\n");
  printf("\t[--log <logfile> <info_str> <filemask> <stdoutmask>]\n");
  printf("\t[--debug]\n");
    printf("\t\tIf debug is chosen, then log messages for chosen loglevel(s)\n");
    printf("\t\twill be written out to the logfile without any buffering\n");
  printf("\t[--pid]\n");
  printf("\t[--lka <lkatype> <lkadir>]\n");
    printf("\t\tlkatype must be hfs-sha-1\n");
  printf("\t[--proxy proxy_server port-number]\n");
    printf("\t\tproxy_server is the ip address or the hostname of the proxy\n");
  printf("Usage: %s --help                  Print usage summary and exit.\n", progname);
  printf("Usage: %s --version               Print version information and exit.\n", progname);
  printf("Usage: %s --rescue <device_name>  Rescue a hung Fauxide driver and exit.\n", progname);
  exit(0);
}

#define PARSE_ERROR(str, args...) do { \
    printf("ERROR: " str "\n\n" , ## args); \
    usage(argv[0]); \
  } while (0)

int main(int argc, char *argv[])
{
  const char* logName;
  const char* log_infostr;  
  unsigned logfilemask=0, logstdoutmask=0x1;
  int requiredArgs=1;/* reqd arg count; at least give me a program name! */
  
  /* required parameters */
  int masterDone=0;
  int keyDone=0;
  int logDone=0;
  int mapDone=0;
  int proxyDone=0;
  
  /* Initialize the fidsvc */
  fidsvc_init();
  
  /* Initialize the config structure */
  initialize_config();
  
  /* parse command line */
  if (argc < 2) {
    usage(argv[0]);
  }
  
  /* Partho: command line parsing was getting way out of hand. Using 
   *  getopt_long(). Porting to windows? :) Will need some work
   */
  
  while (1) {
    
    static struct option vulpes_cmdline_options[] =
      {
	{"version", no_argument, 0, 'a'},
	{"allversions", no_argument, 0, 'a'},  /* XXX compatibility with old revs */
	{"rescue", no_argument, 0, 'b'},
	{"pid", no_argument, 0, 'c'},
	{"map", no_argument, 0, 'd'},
	{"master", no_argument, 0, 'e'},
	{"keyring", no_argument, 0, 'f'},
	{"log", no_argument, 0, 'h'},
	{"proxy", no_argument, 0, 'i'},
	{"lka", no_argument, 0, 'l'},
	{"help", no_argument, 0, 'm'},
	{0,0,0,0}
      };
    
    int option_index=0;
    int opt_retVal;
    
    opt_retVal=getopt_long(argc,argv, "", vulpes_cmdline_options,
			   &option_index);
    
    if (opt_retVal == -1)
      break;    
    switch(opt_retVal) {
    case 'a':
      /* version */
      requiredArgs+=1;
      version();
      exit(0);
      break;
    case 'b':
      /* rescue */
      requiredArgs+=2;
      if (optind+0 >= argc) {
	PARSE_ERROR("device_name required for RESCUE.");
      } else {
	const char *device_name = argv[optind++];
	int result;
	printf("START: fauxide_rescue().\n");
	result = fauxide_rescue(device_name);
	printf("END: fauxide_rescue() returned %d.\n", result);
      }
      exit(0);
      break;
    case 'c':
      /* pid */
      requiredArgs+=1;
      printf("VULPES: pid = %u\n", (unsigned) getpid());
      break;
    case 'd':
      /* map */
      if (mapDone) {
	PARSE_ERROR("--map may only be specified once.");
      }
      requiredArgs+=4;
      if (optind+2 >= argc) {
	PARSE_ERROR("failed to parse mapping.");
      }
      
      config.mapping = char_to_mapping_type(argv[optind++]);
      if(config.mapping == NO_MAPPING) {
	PARSE_ERROR("unknown mapping type (%s).", argv[optind-1]);
      }	    
      config.device_name=argv[optind++];
      config.cache_name=argv[optind++];
      mapDone=1;
      break;
    case 'e':
      /* master */
      if (masterDone) {
	PARSE_ERROR("--master may only be specified once.");
      }
      requiredArgs+=3;
      if (optind+1 >= argc) {
	PARSE_ERROR("failed to parse transport.");
      }
      if (strcmp("http",argv[optind])==0)
	config.trxfer=HTTP_TRANSPORT;
      else if (strcmp("local",argv[optind])==0)
	config.trxfer=LOCAL_TRANSPORT;
      else {
	PARSE_ERROR("unknown transport type.");
      }
      optind++;
      config.master_name=argv[optind++];
      masterDone=1;
      break;
    case 'f':
      /* keyring */
      if (keyDone) {
	PARSE_ERROR("--keyring may only be specified once.");
      }
      requiredArgs+=2;
      if (optind+0 >= argc) {
	PARSE_ERROR("failed to parse keyring name.");
      }
      config.keyring_name=argv[optind++];
      keyDone=1;
      break;
    case 'h':
      /* log */
      if (logDone) {
	PARSE_ERROR("--log may only be specified once.");
      }
      requiredArgs+=5;
      if (optind+2 >= argc) {
	PARSE_ERROR("failed to parse logging.");
      }
      logName=argv[optind++];
      log_infostr=argv[optind++];
      logfilemask=strtoul(argv[optind++], NULL, 0);
      logstdoutmask=strtoul(argv[optind++], NULL, 0);
      vulpes_log_init(logName,log_infostr,logfilemask,logstdoutmask);
      logDone=1;
      break;
    case 'i':
      /* proxy */
      {
	char *error_buffer;
	long tmp_num;

	if (proxyDone) {
	  PARSE_ERROR("--proxy may only be specified once.");
	}
	requiredArgs+=3;
	error_buffer=(char*)malloc(64);
	error_buffer[0]=0;
	if (optind+1 >= argc) {
	  PARSE_ERROR("failed to parse proxy description.");
	}
	config.proxy_name=argv[optind++];
	tmp_num=strtol(argv[optind++], &error_buffer,10);
	if (strlen(error_buffer)!=0) {
	  PARSE_ERROR("bad port");
	}
	config.proxy_port=tmp_num;
	free(error_buffer);
	proxyDone=1;
      }
      break;
    case 'l':
      /* lka */
      requiredArgs+=3;
      if (optind+1 >= argc) {
	PARSE_ERROR("failed to parse lka option.");
      }
      /* XXX this is lame */
      if (strcmp("hfs-sha-1", argv[optind++]))
	PARSE_ERROR("invalid LKA type.");
      if(config.lka_svc == NULL)
	if(vulpes_lka_open())
	  printf("WARNING: unable to open lka service.\n");
      if(config.lka_svc != NULL)
	if(vulpes_lka_add(LKA_HFS, LKA_TAG_SHA1, argv[optind++]))
	  printf("WARNING: unable to add lka database %s.\n", argv[optind]);
      break;
    case 'm':
      /* help */
      usage(argv[0]);
    default:
      PARSE_ERROR("unknown command line option.");
    }
  }

  /* Check arguments */
  if (argc!=requiredArgs) {
    PARSE_ERROR("failed to parse cmd line (%d of %d).", requiredArgs, argc);
  }
  if (keyDone==0) {
    PARSE_ERROR("--keyring parameter missing");
  }
  if (masterDone==0) {
    PARSE_ERROR("--master parameter missing");
  }
  if (mapDone==0) {
    PARSE_ERROR("--map parameter missing");
  }
  
  if (logDone==0) {
    logName="/dev/null";
    log_infostr=" ";
    vulpes_log_init(logName,log_infostr,logfilemask,logstdoutmask);
    logDone=1;
  }
  
  /* now that parameters are correct - start vulpes log */
  vulpes_log(LOG_BASIC,"Starting. Version: %s, revision: %s %s, PID: %u",
             vulpes_version, svn_branch, svn_revision, (unsigned)getpid());
  
  /* Register default signal handler */
  {
    int caught_signals[]={SIGUSR1, SIGUSR2, SIGHUP, SIGINT, SIGQUIT, 
			  SIGABRT, SIGTERM, SIGTSTP,
			  SIGKILL}; /* SIGKILL needed... */
    int sig;
    int s=0;
    while((sig=caught_signals[s]) != SIGKILL) {
      if (set_signal_handler(sig, vulpes_signal_handler)) {
	vulpes_log(LOG_ERRORS,"unable to register default signal handler for signal %d", sig);
	goto vulpes_exit;
      }
      s++;
    }
  }
  
  
  VULPES_DEBUG("Establishing mapping...\n");
  /* Initialize the mapping */
  switch (config.mapping) {
  case SIMPLE_FILE_MAPPING:
  case SIMPLE_DISK_MAPPING:
#ifdef VULPES_SIMPLE_DEFINED
    if (initialize_simple_mapping()) {
      vulpes_log(LOG_ERRORS,"ERROR: unable to initialize simple mapping");
      goto vulpes_exit;	
    }
#else
    vulpes_log(LOG_ERRORS,"ERROR: simple mapping not supported in this version.");
    goto vulpes_exit;
#endif
    break;
  case LEV1_MAPPING:
  case LEV1V_MAPPING:
    if (initialize_lev1_mapping()) {
      vulpes_log(LOG_ERRORS,"unable to initialize lev1 mapping");
      goto vulpes_exit;
    }
    break;
  case NO_MAPPING:
  default:
    vulpes_log(LOG_ERRORS,"ERROR: unknown mapping type");
    goto vulpes_exit;
  }
  
  /* XXX we don't do proper cleanup in the error paths */
  
  /* Set up fauxide driver */
  if (fauxide_init()) {
    /* fauxide_init() has already complained to the log */
    goto vulpes_exit;
  }

  /* Enter main loop */
  fauxide_run();
  
  vulpes_log(LOG_BASIC,"Beginning vulpes shutdown sequence");

  /* Shut down fauxide driver */
  fauxide_shutdown();

  /* Close file */
  VULPES_DEBUG("\tClosing map.\n");
  if ((*config.shutdown_func)() == -1) {
      vulpes_log(LOG_ERRORS,"shutdown function failed");
      exit(1);
    }

  /* Close the LKA service */
  if(config.lka_svc != NULL)
    if(vulpes_lka_close())
      vulpes_log(LOG_ERRORS,"failure during lka_close().");    
  
  /* Close the fidsvc */
  fidsvc_close();
  
  /* Print stats */
  vulpes_log(LOG_STATS,"Sectors read:%llu",sectors_read);
  vulpes_log(LOG_STATS,"Sectors written:%llu",sectors_written);
  vulpes_log(LOG_STATS,"Sectors accessed:%llu",sectors_accessed);

  
 vulpes_exit:
  vulpes_log(LOG_BASIC,"Exiting");
  vulpes_log_close();
  return 0;
}
