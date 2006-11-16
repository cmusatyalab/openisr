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
#include <getopt.h>
#include "vulpes.h"
#include "vulpes_log.h"
#include "vulpes_lka.h"
#include "vulpes_util.h"

/* GLOBALS */

const char *vulpes_version = "0.60";

struct vulpes_config config;
extern char *optarg;
extern int optind, opterr, optopt;


/* FUNCTIONS */
static void version(void)
{
  printf("Version: %s (%s, rev %s)\n", vulpes_version, svn_branch, svn_revision);
}

static void usage(const char *progname)
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
    usage(argv[0]); \
  } while (0)

int main(int argc, char *argv[])
{
  const char* logName;
  const char* log_infostr;  
  unsigned logfilemask=0, logstdoutmask=0x1;
  int requiredArgs=1;/* reqd arg count; at least give me a program name! */
  int foreground=0;
  pid_t pid;
  int ret=1;
  
  /* required parameters */
  int masterDone=0;
  int keyDone=0;
  int logDone=0;
  int cacheDone=0;
  int proxyDone=0;
  
  /* parse command line */
  if (argc < 2) {
    usage(argv[0]);
  }
  
  while (1) {
    
    static struct option vulpes_cmdline_options[] =
      {
	{"version", no_argument, 0, 'a'},
	{"allversions", no_argument, 0, 'a'},  /* XXX compatibility with old revs */
	{"foreground", no_argument, 0, 'b'},
	{"pid", no_argument, 0, 'c'},
	{"cache", no_argument, 0, 'd'},
	{"master", no_argument, 0, 'e'},
	{"keyring", no_argument, 0, 'f'},
	{"upload", no_argument, 0, 'g'},
	{"log", no_argument, 0, 'h'},
	{"proxy", no_argument, 0, 'i'},
	{"check", no_argument, 0, 'j'},
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
      exit(1);
      break;
    case 'b':
      /* foreground */
      if (foreground) {
	PARSE_ERROR("--foreground may only be specified once.");
      }
      requiredArgs+=1;
      foreground=1;
      break;
    case 'c':
      /* pid */
      requiredArgs+=1;
      printf("VULPES: pid = %u\n", (unsigned) getpid());
      break;
    case 'd':
      /* cache */
      if (cacheDone) {
	PARSE_ERROR("--cache may only be specified once.");
      }
      requiredArgs+=2;
      if (optind >= argc) {
	PARSE_ERROR("failed to parse cache.");
      }
      config.cache_name=argv[optind++];
      cacheDone=1;
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
      requiredArgs+=3;
      if (optind+1 >= argc) {
	PARSE_ERROR("failed to parse keyring name.");
      }
      config.hex_keyring_name=argv[optind++];
      config.bin_keyring_name=argv[optind++];
      keyDone=1;
      break;
    case 'g':
      /* upload */
      if (config.doUpload) {
	PARSE_ERROR("--upload may only be specified once.");
      }
      requiredArgs+=3;
      if (optind+1 >= argc) {
	PARSE_ERROR("failed to parse upload options.");
      }
      config.doUpload=1;
      config.old_keyring_name=argv[optind++];
      config.dest_name=argv[optind++];
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
    case 'j':
      /* check */
      if (config.doCheck) {
	PARSE_ERROR("--check may only be specified once.");
      }
      requiredArgs+=1;
      config.doCheck=1;
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
  if (masterDone==0 && !config.doUpload && !config.doCheck) {
    PARSE_ERROR("--master parameter missing");
  }
  if (cacheDone==0) {
    PARSE_ERROR("--cache parameter missing");
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
  
  VULPES_DEBUG("Initializing cache...\n");
  /* Initialize the cache */
  if (cache_init()) {
    vulpes_log(LOG_ERRORS,"unable to initialize cache");
    goto vulpes_exit;
  }
  
  /* XXX we don't do proper cleanup in the error paths */
  
  if (config.doUpload) {
    copy_for_upload(config.old_keyring_name, config.dest_name);
    /* Does not return */
  }
  if (config.doCheck) {
    checktags();
    /* Does not return */
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
