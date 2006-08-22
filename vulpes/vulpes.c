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
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <signal.h>
#include <sched.h>
#include <getopt.h>
#include "fauxide.h"
#include "vulpes_map.h"
#include "vulpes_fids.h"
#include "vulpes_log.h"
#include "vulpes_lka.h"

/* EXTERNS */
extern int initialize_lev1_mapping(vulpes_mapping_t * map_ptr);
#ifdef VULPES_SIMPLE_DEFINED
extern int initialize_simple_mapping(vulpes_mapping_t * map_ptr);
#endif
extern const char *svn_revision;
extern const char *svn_branch;

/* DEFINES */
#undef VERBOSE_DEBUG
#ifdef VERBOSE_DEBUG
#define VULPES_DEBUG(fmt, args...)     {printf("[vulpes] " fmt, ## args); fflush(stdout);}
#else
#define VULPES_DEBUG(fmt, args...)     ;
#endif

/* GLOBALS */

static int exit_main_loop = 0;
static int sleeping = 0;
static int got_signal = 0;

static unsigned long long sectors_read = 0;
static unsigned long long sectors_written = 0;
static unsigned long long sectors_accessed = 0;

const char *vulpes_version = "0.60";

static vulpes_mapping_t mapping;
extern char *optarg;
extern int optind, opterr, optopt;

/* check kernel version */
int
running_kernel26 ()
{
  int ret;
  struct utsname un;
  
  ret = uname (&un);
  if (ret < 0) {
    vulpes_log(LOG_ERRORS,"RUNNING_KERNEL26","unable to determine running kernel's version(uname)");
    return 0;
  }
  if (strlen (un.release) < 3) {
    vulpes_log(LOG_ERRORS,"RUNNING_KERNEL26","unable to determine running kernel's version(release)");
    return 0;
  }
  
  //printf ("%c%c%c\n", buf[0], buf[1], buf[2]);
  
  if (un.release[0] == '2' && un.release[1] == '.' && un.release[2] == '6')
    return 1;
  else
    return 0;
}


/* FUNCTIONS */
void vulpes_signal_handler(int sig)
{
  VULPES_DEBUG("Caught signal %d\n", sig);
  
  got_signal = 1;
  
  if (sig != SIGUSR1)
    exit_main_loop = 1;
  return;
}

int vulpes_register(void)
{
  int i;
  int result = 0;
  vulpes_regblk_t regblk;
  vulpes_cmdblk_t cmdblk;
  
  mapping.reg.vulpes_id = 0;
  mapping.reg.pid = getpid();
  mapping.reg.volsize = (*mapping.volsize_func) (&mapping);
  
  regblk.reg = mapping.reg;
  
  if (VULPES_REGBLK_SECT_PER_BUF % VULPES_CMDBLK_SECT_PER_BUF == 0) {
    int num_cmds =
      VULPES_REGBLK_SECT_PER_BUF / VULPES_CMDBLK_SECT_PER_BUF;
    for (i = 0; i < num_cmds; i++) {
      /* Create a dummy cmdblk to use the mapping.read function */
      cmdblk.head.vulpes_id = 0;
      cmdblk.head.cmd = VULPES_CMD_READ;
      cmdblk.head.start_sect = 0;
      cmdblk.head.num_sect = VULPES_CMDBLK_SECT_PER_BUF;
      result = (*mapping.read_func) (&mapping, &cmdblk);
      if (result == -1)
	{
	  vulpes_log(LOG_ERRORS,"VULPES_REGISTER","failed in vulpes register: read_func failed");
	  return -1;
	}
      
      /* Copy from cmdblk to regblk */
      memcpy((regblk.buffer + i * VULPES_CMDBLK_BUFSIZE),
	     cmdblk.buffer, VULPES_CMDBLK_BUFSIZE);
    }
    
    result =
      ioctl(mapping.vulpes_device, FAUXIDE_IOCTL_REGBLK_REGISTER,
	    &regblk);
  } else {
    vulpes_log(LOG_ERRORS,"VULPES_REGISTER","bad buffer sizes");
    result = 0;
  }
  
  
  return result;
}

int vulpes_unregister(void)
{
  int result = 0;
  
  result =
    ioctl(mapping.vulpes_device, FAUXIDE_IOCTL_REGBLK_UNREGISTER,
	  &mapping.reg);
  
  return result;
}

int vulpes_rescue_fauxide(const char *device_name)
{
  int result = 0;
  int rescue_device = -1;

  rescue_device = open(device_name, O_RDWR);
  if (rescue_device < 0) {
    printf("ERROR: vulpes_rescue_fauxide() unable to open device (%s).\n", 
	   device_name);
    result = rescue_device;
  } else {
    result = ioctl(rescue_device, FAUXIDE_IOCTL_RESCUE, NULL);
    close(rescue_device);
  }
  
  return result;
}

int cmdblk_ok(const vulpes_cmd_head_t * head)
{
  int result = 1;
  
  /* vulpes_id is now ignored */
  
  /* Check command parameters */
  switch (head->cmd) {
  case VULPES_CMD_READ:
  case VULPES_CMD_WRITE:
    if (head->start_sect + head->num_sect > mapping.reg.volsize)
      result = 0;
    break;
  default:
    result = 0;
  }
  
  return result;
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

mapping_type_t char_to_mapping_type(const char *name)
{
  mapping_type_t result = NO_MAPPING;
  
  if (strcmp("lev1", name) == 0) {
    result = LEV1_MAPPING;
  } else if (strcmp("lev1-v", name) == 0) {
    result = LEV1V_MAPPING;
  } else if (strcmp("zlev1", name) == 0) {
    result = ZLEV1_MAPPING;
  } else if (strcmp("zlev1-v", name) == 0) {
    result = ZLEV1V_MAPPING;
  } else if (strcmp("file", name) == 0) {
    result = SIMPLE_FILE_MAPPING;
  } else if (strcmp("disk", name) == 0) {
    result = SIMPLE_DISK_MAPPING;
  } else {
    result = NO_MAPPING;
  }
  
  return result;
}

void initialize_null_mapping(void)
{
  mapping.trxfer = LOCAL_TRANSPORT;
  mapping.type = NO_MAPPING;
  
  mapping.proxy_name = NULL;
  mapping.proxy_port = 80;
  
  mapping.device_name = NULL;
  mapping.file_name = NULL;
  mapping.cache_name = NULL;
  
  mapping.keyring_name = NULL;
  
  mapping.vulpes_device = -1;
  
  mapping.reg.vulpes_id = -1;
  mapping.reg.pid = -1;
  mapping.reg.volsize = 0;
  
  mapping.open_func = NULL;
  mapping.volsize_func = NULL;
  mapping.read_func = NULL;
  mapping.write_func = NULL;
  mapping.close_func = NULL;
  
  mapping.verbose = 0;
  
  mapping.lka_svc = NULL;
  mapping.special = NULL;
}

void version(void)
{
  printf("Version: %s (%s, rev %s)\n", vulpes_version, svn_branch, svn_revision);
}

void usage (const char *progname)
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
  printf("\t[--lka <lkatype:lkadir>]\n");
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
  void *old_sig_handler;
  vulpes_cmdblk_t cmdblk;
  pid_t pid;
  const char* logName;
  const char* log_infostr;  
  unsigned logfilemask=0, logstdoutmask=0x1;
  unsigned long long request_counter=0;
  int requiredArgs=1;/* reqd arg count; at least give me a program name! */
  
  /* required parameters */
  int masterDone=0;
  int keyDone=0;
  int logDone=0;
  int mapDone=0;
  int proxyDone=0;
  
  /* Initialize the fidsvc */
  fidsvc_init();
  
  /* Initialize the mapping structure */
  initialize_null_mapping();
  
  /* parse command line */
  if (argc < 2) {
    usage(argv[0]);
  }
  
  /* capture process id */
  pid = getpid();
  
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
	printf("START: vulpes_rescue_fauxide().\n");
	result = vulpes_rescue_fauxide(device_name);
	printf("END: vulpes_rescue_fauxide() returned %d.\n", result);
      }
      exit(0);
      break;
    case 'c':
      /* pid */
      requiredArgs+=1;
      printf("VULPES: pid = %ld\n", (long) pid);
      break;
    case 'd':
      /* map */
      {
	mapping_type_t type;
	
	if (mapDone) {
	  PARSE_ERROR("--map may only be specified once.");
	}
	requiredArgs+=4;
	if (optind+2 >= argc) {
	  PARSE_ERROR("failed to parse mapping.");
	}
	
	type = char_to_mapping_type(argv[optind++]);
	if(type == NO_MAPPING) {
	  PARSE_ERROR("unknown mapping type (%s).", argv[optind-1]);
	}	    
	mapping.type = type;
	mapping.device_name=argv[optind++];
	mapping.cache_name=argv[optind++];
	mapDone=1;
      }
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
	mapping.trxfer=HTTP_TRANSPORT;
      else if (strcmp("local",argv[optind])==0)
	mapping.trxfer=LOCAL_TRANSPORT;
      else {
	PARSE_ERROR("unknown transport type.");
      }
      optind++;
      mapping.file_name=argv[optind++];
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
      mapping.keyring_name=argv[optind++];
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
	mapping.proxy_name=argv[optind++];
	tmp_num=strtol(argv[optind++], &error_buffer,10);
	if (strlen(error_buffer)!=0) {
	  PARSE_ERROR("bad port");
	}
	mapping.proxy_port=tmp_num;
	free(error_buffer);
	proxyDone=1;
      }
      break;
    case 'l':
      /* lka */
      requiredArgs+=2;
      if (optind+0 >= argc) {
	PARSE_ERROR("failed to parse lka option.");
      }
      if(mapping.lka_svc == NULL)
	if((mapping.lka_svc = vulpes_lka_open()) == NULL)
	  printf("WARNING: unable to open lka service.\n");
      if(mapping.lka_svc != NULL)
	if(vulpes_lka_add(mapping.lka_svc, argv[optind]) != VULPES_LKA_RETURN_SUCCESS)
	  printf("WARNING: unable to add lka database %s.\n", argv[optind]);
      optind++;
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
  vulpes_log(LOG_BASIC,"VULPES_START","Version: %s, revision: %s %s, PID: %u",
             vulpes_version, svn_branch, svn_revision, (unsigned)pid);
  
  /* Register our signal handler */
  {
    int caught_signals[]={SIGUSR1, SIGUSR2, SIGHUP, SIGINT, SIGQUIT, 
			  SIGABRT, SIGTERM, SIGTSTP,
			  SIGKILL}; /* SIGKILL needed... */
    int sig;
    int s=0;
    while((sig=caught_signals[s]) != SIGKILL) {
      old_sig_handler = signal(sig, vulpes_signal_handler);
      if (old_sig_handler == SIG_ERR) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to register signal handler for signal");
	goto vulpes_exit;
      }
      
      s++;
    }
  }
  
  
  VULPES_DEBUG("Establishing mapping...\n");
  /* Initialize the mapping */
  switch (mapping.type) {
  case SIMPLE_FILE_MAPPING:
  case SIMPLE_DISK_MAPPING:
#ifdef VULPES_SIMPLE_DEFINED
    if (initialize_simple_mapping(&mapping)) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: unable to initialize simple mapping");
      goto vulpes_exit;	
    }
#else
    vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: simple mapping not supported in this version.");
    goto vulpes_exit;
#endif
    break;
  case LEV1_MAPPING:
  case LEV1V_MAPPING:
  case ZLEV1_MAPPING:
  case ZLEV1V_MAPPING:	{
    if (initialize_lev1_mapping(&mapping)) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to initialize lev1 mapping");
      goto vulpes_exit;
    }
  }
    break;
  case NO_MAPPING:
  default:
    vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: unknown mapping type");
    goto vulpes_exit;
  }
  
  /* Open the device */
  VULPES_DEBUG("\tOpening device\n");
  mapping.vulpes_device = open(mapping.device_name, O_RDWR);
  if (mapping.vulpes_device < 0) {
    vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to open device %s",mapping.device_name);
    goto vulpes_exit;
  }
  
  /* Open the file */
  VULPES_DEBUG("\tOpening file.\n");
  if ((*(mapping.open_func)) (&mapping)) {
    vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to open lev1 %s", mapping.file_name);
    goto vulpes_exit;
  }
  
  /* Register ourselves with the device */
  VULPES_DEBUG("\tRegistering device.\n");
  if (vulpes_register()) {
    vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to register process with device");
    goto vulpes_exit;
  }
  vulpes_log(LOG_BASIC,"VULPES_MAIN","Registered process with device");
  
  /* Need to register twice to get 2.6 kernel module to recognize driver properly */
  if (running_kernel26()) {
    /* Unregister process */
    VULPES_DEBUG("\tUnregistering device.\n");
    if (vulpes_unregister()) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","failed to unregister: %s", mapping.device_name);
    }
    vulpes_log(LOG_BASIC,"VULPES_MAIN","un-Registered process with device");
    /* Close device */
    VULPES_DEBUG("\tClosing device.\n");
    close(mapping.vulpes_device);
    /* Open the device */
    VULPES_DEBUG("\tOpening device.\n");
    mapping.vulpes_device = open(mapping.device_name, O_RDWR);
    if (mapping.vulpes_device < 0) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to open device %s",mapping.device_name);
      goto vulpes_exit;
    }
    /* Register ourselves with the device */
    VULPES_DEBUG("\tRegistering device.\n");
    if (vulpes_register()) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to register process with device");
      goto vulpes_exit;
    }
    vulpes_log(LOG_BASIC,"VULPES_MAIN","Registered process with device");
  }
  
  /* Initialize cmdblk */
  cmdblk.head.cmd = VULPES_CMD_GET;
  cmdblk.head.vulpes_id=0;
  cmdblk.head.fauxide_id=NULL;
  
  /* Enter processing loop */
  do {
    int result = 0;
    
    /* Execute ioctl */
    ioctl(mapping.vulpes_device, FAUXIDE_IOCTL_CMDBLK, &cmdblk);
    
    /* Process cmd */
    switch (cmdblk.head.cmd) {
    case VULPES_CMD_READ:
      vulpes_log(LOG_FAUXIDE_REQ,"READ_IN","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (cmdblk_ok(&(cmdblk.head))) {
	result = (*mapping.read_func) (&mapping, &cmdblk);
      } else {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","%llu:%lu:%lu: bad cmdblk",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
	result = -1;
      }
      vulpes_log(LOG_FAUXIDE_REQ,"READ_OUT","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (result == 0) {
	tally_sector_accesses(0, cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_READ_DONE;
      } else {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","%llu:%lu:%lu: read failed",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_ERROR;
      }
      request_counter++;
      break;
    case VULPES_CMD_WRITE:
      vulpes_log(LOG_FAUXIDE_REQ,"WRITE_IN","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (cmdblk_ok(&(cmdblk.head))) {
	result = (*mapping.write_func) (&mapping, &cmdblk);
      } else {
	result = -1;
      }
      vulpes_log(LOG_FAUXIDE_REQ,"WRITE_DONE","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (result == 0) {
	tally_sector_accesses(1, cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_WRITE_DONE;
      } else {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","%llu:%lu:%lu: write failed",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_ERROR;
      }
      request_counter++;
      break;
    case VULPES_CMD_SLEEP:
      VULPES_DEBUG("Going to sleep...\n");
      sleeping = 1;
      if (!got_signal) {
	int tmp;
	/* Give the system one last chance to post a request */
#ifdef _POSIX_PRIORITY_SCHEDULING
	tmp = sched_yield();
	if (tmp)
	  vulpes_log(LOG_ERRORS,"VULPES_MAIN","sched_yield: %d",errno);
#else
	usleep(20000);	/* 20 msec */
#endif
	if (!got_signal) {
	  VULPES_DEBUG("  ZZzzz...\n");
	  sleep(1);
	}
      }
      sleeping = 0;
      got_signal = 0;
      VULPES_DEBUG("\t...woke up.\n");
      cmdblk.head.cmd = VULPES_CMD_GET;	/* Next call is "get" */
      break;
    default: 
      {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: unknown vulpes command %d",cmdblk.head.cmd);
      }
    }
  } while (exit_main_loop == 0);
  
  /* Unmap */
  vulpes_log(LOG_BASIC,"VULPES_MAIN", "Beginning vulpes shutdown sequence");
  /* Unregister process */
  VULPES_DEBUG("\tUnregistering device.\n");
  if (vulpes_unregister()) {
    vulpes_log(LOG_ERRORS,"VULPES_MAIN","failed to unregister %s", mapping.device_name);
  }
  vulpes_log(LOG_BASIC,"VULPES_MAIN","un-Registered process with device");
  
  /* Close device */
  VULPES_DEBUG("\tClosing device.\n");
  close(mapping.vulpes_device);
  
  /* Close file */
  VULPES_DEBUG("\tClosing map.\n");
  if ((*mapping.close_func) (&mapping) == -1) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","close function failed");
      exit(1);
    }

  /* Close the LKA service */
  if(mapping.lka_svc != NULL)
    if(vulpes_lka_close(mapping.lka_svc) != VULPES_LKA_RETURN_SUCCESS)
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","failure during lka_close().");    
  
  /* Close the fidsvc */
  fidsvc_close();
  
  /* Print stats */
  vulpes_log(LOG_STATS,"VULPES","Sectors read:%llu",sectors_read);
  vulpes_log(LOG_STATS,"VULPES","Sectors written:%llu",sectors_written);
  vulpes_log(LOG_STATS,"VULPES","Sectors accessed:%llu",sectors_accessed);

  
 vulpes_exit:
  vulpes_log(LOG_BASIC,"VULPES_FINISH", "");
  vulpes_log_close();
  return 0;
}
