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

extern int initialize_vulpes_logstats(vulpes_stats_t * stats,
				      const char *filename);
#ifdef VULPES_SIMPLE_DEFINED
extern int initialize_simple_mapping(vulpes_mapping_t * map_ptr);
#endif
extern const char *svn_revision;
extern const char *svn_branch;

/* DEFINES */
/* #define VERBOSE_DEBUG  */
#ifdef VERBOSE_DEBUG
#define VULPES_DEBUG(fmt, args...)     {printf("[vulpes] " fmt, ## args); fflush(stdout);}
#else
#define VULPES_DEBUG(fmt, args...)     ;
#endif

#define MAX_NUM_MAPPINGS               16

/* GLOBALS */

static int exit_main_loop = 0;
static int sleeping = 0;
static int got_signal = 0;

static unsigned long long sectors_read = 0;
static unsigned long long sectors_written = 0;
static unsigned long long sectors_accessed = 0;

const char *vulpes_version = "0.60";

static int num_mappings = 0;
static vulpes_mapping_t mapping[MAX_NUM_MAPPINGS];
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
__inline int valid_stats(vulpes_mapping_t * map_ptr)
{
  return (map_ptr->stats != NULL);
}

void vulpes_signal_handler(int sig)
{
  VULPES_DEBUG("Caught signal %d\n", sig);
  
  got_signal = 1;
  
  if (sig != SIGUSR1)
    exit_main_loop = 1;
  return;
}

int vulpes_register(vulpes_id_t id)
{
  int i;
  int result = 0;
  vulpes_regblk_t regblk;
  vulpes_cmdblk_t cmdblk;
  vulpes_mapping_t *map_ptr;
  
  map_ptr = &mapping[id];
  
  map_ptr->reg.vulpes_id = id;
  map_ptr->reg.pid = getpid();
  map_ptr->reg.volsize = (*map_ptr->volsize_func) (map_ptr);
  
  regblk.reg = mapping[id].reg;
  
  if (VULPES_REGBLK_SECT_PER_BUF % VULPES_CMDBLK_SECT_PER_BUF == 0) {
    int num_cmds =
      VULPES_REGBLK_SECT_PER_BUF / VULPES_CMDBLK_SECT_PER_BUF;
    for (i = 0; i < num_cmds; i++) {
      /* Create a dummy cmdblk to use the mapping.read function */
      cmdblk.head.vulpes_id = id;
      cmdblk.head.cmd = VULPES_CMD_READ;
      cmdblk.head.start_sect = 0;
      cmdblk.head.num_sect = VULPES_CMDBLK_SECT_PER_BUF;
      result = (*map_ptr->read_func) (map_ptr, &cmdblk);
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
      ioctl(map_ptr->vulpes_device, FAUXIDE_IOCTL_REGBLK_REGISTER,
	    &regblk);
  } else {
    vulpes_log(LOG_ERRORS,"VULPES_REGISTER","bad buffer sizes");
    result = 0;
  }
  
  
  return result;
}

int vulpes_unregister(vulpes_id_t id)
{
  int result = 0;
  
  result =
    ioctl(mapping[id].vulpes_device, FAUXIDE_IOCTL_REGBLK_UNREGISTER,
	  &mapping[id].reg);
  
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
  vulpes_id_t id;
  
  id = head->vulpes_id;
  
  /* Check the vulpes_id */
  if (id >= num_mappings) {
    result = 0;
    return result;
  }
  
  /* Check command parameters */
  switch (head->cmd) {
  case VULPES_CMD_READ:
  case VULPES_CMD_WRITE:
    if (head->start_sect + head->num_sect > mapping[id].reg.volsize)
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

stats_type_t char_to_stats_type(const char *name)
{
  stats_type_t result = STATS_NONE;
  
  if (strcmp("log", name) == 0) {
    result = STATS_REQLOG;
  } else {
    result = STATS_NONE;
  }
  
  return result;
}

void initialize_null_mapping(vulpes_id_t id)
{
  vulpes_mapping_t *map_ptr;
  
  map_ptr = &(mapping[id]);
  
  map_ptr->trxfer = LOCAL_TRANSPORT;
  map_ptr->type = NO_MAPPING;
  
  map_ptr->proxy_name = NULL;
  map_ptr->proxy_port = 80;
  map_ptr->outgoing_interface = NULL;
  
  map_ptr->device_name = NULL;
  map_ptr->file_name = NULL;
  map_ptr->cache_name = NULL;
  
  map_ptr->keyring_name = NULL;
  
  map_ptr->vulpes_device = -1;
  
  map_ptr->reg.vulpes_id = -1;
  map_ptr->reg.pid = -1;
  map_ptr->reg.volsize = 0;
  
  map_ptr->open_func = NULL;
  map_ptr->volsize_func = NULL;
  map_ptr->read_func = NULL;
  map_ptr->write_func = NULL;
  map_ptr->close_func = NULL;
  
  map_ptr->verbose = 0;
  
  map_ptr->lka_svc = NULL;
  map_ptr->special = NULL;
  map_ptr->stats = NULL;
}

int initialize_vulpes_stats(vulpes_mapping_t * map_ptr)
{
  vulpes_stats_t *ptr;
  
  ptr = malloc(sizeof(vulpes_stats_t));
  if (!ptr) {
    return -1;
  }
  
  ptr->open = NULL;
  ptr->record_read = NULL;
  ptr->record_write = NULL;
  ptr->close = NULL;
  ptr->special = NULL;
  
  map_ptr->stats = ptr;
  
  return 0;
}

void version(void)
{
  printf("Version: %s (%s, rev %s)\n", vulpes_version, svn_branch, svn_revision);
}

void usage (const char *progname)
{
  version();
  printf("usage: %s [--pid] --map <maptype> <device_name> <local_cache_name> --master <transfertype> <master_disk_location/url> --keyring <keyring_file> [--log <logfile> <info_str> <filemask> <stdoutmask>] [--debug] [--lka <lkatype:lkadir>] [--proxy proxy_server port-number] \n", progname);
  printf("\tIf debug is chosen, then log messages for chosen loglevel(s) will be written out to the logfile without any buffering\n");
  printf ("\tmaptype has to be lev1\n");
  printf ("\ttransfertype is one of: local http\n");
  printf ("\tlkatype must be hfs-sha-1\n");
  printf ("\tproxy_server is the ip address or the hostname of the proxy\n");
  printf("usage: %s --version                 Print version information and exit.\n", progname);
  printf("usage: %s --rescue <device_name>    Attempt to rescue a hung driver and exit.\n", progname);
  /*  printf ("\tinterface is the outgoing network interface/ip-address/hostname to use to connect to proxy on this machine\n");*/
  exit(0);
}

int main(int argc, char *argv[])
{
  void *old_sig_handler;
  vulpes_cmdblk_t cmdblk;
  vulpes_id_t id;
  unsigned i;
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
  
  /* Initialize the fidsvc */
  fidsvc_init();
  
  /* Initialize the mapping array */
  for (i = 0; i <= num_mappings; i++) {
    initialize_null_mapping(i);
  }
  
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
	/*{"stats", no_argument, 0, 'g'},*/
	{"log", no_argument, 0, 'h'},
	{"proxy", no_argument, 0, 'i'},
	/*{"interface", no_argument, 0, 'j'},
	  {"noencryption", no_argument, 0, 'k'},*/
	{"lka", no_argument, 0, 'l'},
	{0,0,0,0}
      };
    
    int option_index=0;
    int opt_retVal;
    vulpes_mapping_t *current_mapping=&(mapping[0]);
    
    opt_retVal=getopt_long(argc,argv, "", vulpes_cmdline_options,
			   &option_index);
    
    if (opt_retVal == -1)
      break;    
    switch(opt_retVal) {
    case 'a':
      requiredArgs+=1;
      version();
      exit(0);
      break;
    case 'b':
      requiredArgs+=2;
      if (optind+0 >= argc) {
	printf("ERROR: device_name required for RESCUE.\n");
	usage(argv[0]);
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
      requiredArgs+=1;
      printf("VULPES: pid = %ld\n", (long) pid);
      break;
    case 'd': 
      {
	mapping_type_t type;
	
	requiredArgs+=4;
	if (optind+2 >= argc) {
	  printf("ERROR: failed to parse mapping.\n");
	  usage(argv[0]);
	}
	
	/* each time we see a new --map (except the first), start a new mapping */
	current_mapping=&(mapping[num_mappings]);
	++num_mappings;
	
	type = char_to_mapping_type(argv[optind++]);
	if(type == NO_MAPPING) {
	  printf("ERROR: unknown mapping type (%s).\n", argv[optind-1]);
	  usage(argv[0]);
	}	    
	current_mapping->type = type;
	current_mapping->device_name=argv[optind++];
	current_mapping->cache_name=argv[optind++];
      }
      break;
    case 'e':
      requiredArgs+=3;
      if (optind+1 >= argc) {
	printf("ERROR: failed to parse transport.\n");
	usage(argv[0]);
      }
      if (strcmp("http",argv[optind])==0)
	current_mapping->trxfer=HTTP_TRANSPORT;
      else if (strcmp("local",argv[optind])==0)
	current_mapping->trxfer=LOCAL_TRANSPORT;
      else {
	printf("ERROR: unknown transport type.\n");
	usage(argv[0]);
      }
      optind++;
      current_mapping->file_name=argv[optind++];
      masterDone=1;
      break;
    case 'f':
      requiredArgs+=2;
      if (optind+0 >= argc) {
	printf("ERROR: failed to parse keyring name.\n");
	usage(argv[0]);
      }
      current_mapping->keyring_name=argv[optind++];
      keyDone=1;
      break;
      /*case 'g': {
	stats_type_t type;
	int tmp;
	
	requiredArgs+=2;
	if (optind+0 >= argc)
	usage(argv[0]);
	type = char_to_stats_type(argv[optind++]);
	
	tmp = initialize_vulpes_stats(&mapping[current_map]);
	if (tmp) {
	printf("ERROR: failed to initialize stats.\n");
	usage(argv[0]);
	}
	
	switch (type) {
	case STATS_REQLOG:
	requiredArgs+=1;
	if (optind+0 >= argc)
	usage(argv[0]);
	tmp =
	initialize_vulpes_logstats(mapping[current_map -1].stats,
	argv[optind++]);
	if (tmp) {
	printf("ERROR: failed to initialize logstats.\n");
	exit(0);
	}
	break;
	case STATS_NONE:
	default:
	printf("ERROR: unknown stats type.\n");
	exit(0);
	}
	};
	break;*/
    case 'h':
      requiredArgs+=5;
      if (optind+2 >= argc) {
	printf("ERROR: failed to parse logging.\n");
	usage(argv[0]);
      }
      logName=argv[optind++];
      log_infostr=argv[optind++];
      logfilemask=strtoul(argv[optind++], NULL, 0);
      logstdoutmask=strtoul(argv[optind++], NULL, 0);
      vulpes_log_init(logName,log_infostr,logfilemask,logstdoutmask);
      logDone=1;
      break;
    case 'i':
      {
	char *error_buffer;
	long tmp_num;
	requiredArgs+=3;
	error_buffer=(char*)malloc(64);
	error_buffer[0]=0;
	if (optind+1 >= argc) {
	  printf("ERROR: failed to parse proxy description.\n");
	  usage(argv[0]);
	}
	current_mapping->proxy_name=argv[optind++];
	tmp_num=strtol(argv[optind++], &error_buffer,10);
	if (strlen(error_buffer)!=0)
	  {
	    printf("bad port\n");
	    usage(argv[0]);
	  }
	current_mapping->proxy_port=tmp_num;
	free(error_buffer);
      }
      break;
      /*			case 'j':
				requiredArgs+=2;
				if (optind+0 >= argc)
				usage(argv[0]);
				current_mapping->outgoing_interface=argv[optind++];
				break;
				case 'k':
				requiredArgs+=1;
      */
    case 'l':
      requiredArgs+=2;
      if (optind+0 >= argc) {
	printf("ERROR: failed to parse lka option.\n");
	usage(argv[0]);
      }
      if(current_mapping->lka_svc == NULL)
	if((current_mapping->lka_svc = vulpes_lka_open()) == NULL)
	  printf("WARNING: unable to open lka service.\n");
      if(current_mapping->lka_svc != NULL)
	if(vulpes_lka_add(current_mapping->lka_svc, argv[optind]) != VULPES_LKA_RETURN_SUCCESS)
	  printf("WARNING: unable to add lka database %s.\n", argv[optind]);
      optind++;
      break;
    default:
      printf("ERROR: unknown command line option.\n");
      usage(argv[0]);
    }
  }

  /* Check arguments */
  if (argc!=requiredArgs) {
    printf("ERROR: failed to parse cmd line (%d of %d).\n", requiredArgs, argc);
    usage(argv[0]);
  }
  if (keyDone==0) {
    printf("--keyring parameter missing\n");
    usage(argv[0]);
  }
  if (masterDone==0) {
    printf("--master parameter missing\n");
    usage(argv[0]);
  }
  if (num_mappings < 1) {
    printf("--map paramater missing\n");
    usage(argv[0]);
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
  
  
  /* Establish the mappings */
  VULPES_DEBUG("Establishing mappings...\n");
  for (i = 0; i < num_mappings; i++) {
    mapping_type_t type=mapping[i].type ;
    /* Initialize the mapping */
    switch (type) {
    case SIMPLE_FILE_MAPPING:
    case SIMPLE_DISK_MAPPING:
#ifdef VULPES_SIMPLE_DEFINED
      if (initialize_simple_mapping(&mapping[i])) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: unable to initialize simple mapping %u",i);
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
      if (initialize_lev1_mapping(&mapping[i])) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to initialize lev1 mapping");
	goto vulpes_exit;
      }
    }
      break;
    case NO_MAPPING:
    default:
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: unknown mapping type %u",i);
      goto vulpes_exit;
    }
    
    /* Open the device */
    VULPES_DEBUG("\tOpening device %d.\n", (int) i);
    mapping[i].vulpes_device = open(mapping[i].device_name, O_RDWR);
    if (mapping[i].vulpes_device < 0) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to open device %s",mapping[i].device_name);
      goto vulpes_exit;
    }
    
    /* Open the file */
    VULPES_DEBUG("\tOpening file %d.\n", (int) i);
    if ((*(mapping[i].open_func)) (&mapping[i])) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to open lev1 %s", mapping[i].file_name);
      goto vulpes_exit;
    }
    
    /* Open the stats */
    if (valid_stats(&mapping[i])) {
      VULPES_DEBUG("\tOpening stats %d.\n", (int) i);
      if ((*(mapping[i].stats->open)) (mapping[i].stats)) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: unable to open stats %u",i);
	goto vulpes_exit;
      }
    }
    
    /* Register ourselves with the device */
    VULPES_DEBUG("\tRegistering device %d.\n", (int) i);
    if (vulpes_register(i)) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to register process with device");
      goto vulpes_exit;
    }
    vulpes_log(LOG_BASIC,"VULPES_MAIN","Registered process with device");
    
    /* Need to register twice to get 2.6 kernel module to recognize driver properly */
    if (running_kernel26()) {
      /* Unregister process */
      VULPES_DEBUG("\tUnregistering device %d.\n", (int) i);
      if (vulpes_unregister(i)) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","failed to unregister: %s", mapping[i].device_name);
      }
      vulpes_log(LOG_BASIC,"VULPES_MAIN","un-Registered process with device");
      /* Close device */
      VULPES_DEBUG("\tClosing device %d.\n", (int) i);
      close(mapping[i].vulpes_device);
      /* Open the device */
      VULPES_DEBUG("\tOpening device %d.\n", (int) i);
      mapping[i].vulpes_device = open(mapping[i].device_name, O_RDWR);
      if (mapping[i].vulpes_device < 0) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to open device %s",mapping[i].device_name);
	goto vulpes_exit;
      }
      /* Register ourselves with the device */
      VULPES_DEBUG("\tRegistering device %d.\n", (int) i);
      if (vulpes_register(i)) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to register process with device");
	goto vulpes_exit;
      }
      vulpes_log(LOG_BASIC,"VULPES_MAIN","Registered process with device");
    }
  }
  
  /* Initialize cmdblk */
  cmdblk.head.cmd = VULPES_CMD_GET;
  cmdblk.head.vulpes_id=0;
  cmdblk.head.fauxide_id=NULL;
  
  /* Enter processing loop */
  id = 0;
  do {
    vulpes_mapping_t *map_ptr;
    int result = 0;
    
    /* Execute ioctl -- use last id */
    ioctl(mapping[id].vulpes_device, FAUXIDE_IOCTL_CMDBLK, &cmdblk);
    
    id = cmdblk.head.vulpes_id;
    map_ptr = &mapping[id];
    
    /* Process cmd */
    switch (cmdblk.head.cmd) {
    case VULPES_CMD_READ:
      vulpes_log(LOG_FAUXIDE_REQ,"READ_IN","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (cmdblk_ok(&(cmdblk.head))) {
	result = (*map_ptr->read_func) (map_ptr, &cmdblk);
      } else {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","%llu:%lu:%lu: bad cmdblk",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
	result = -1;
      }
      vulpes_log(LOG_FAUXIDE_REQ,"READ_OUT","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (result == 0) {
	tally_sector_accesses(0, cmdblk.head.num_sect);
	if (valid_stats(map_ptr)) {
	  if ((*map_ptr->stats->record_read) (map_ptr->stats,&cmdblk.head)) {
	    vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: issuing logstats record_read()");
	  }
	}
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
	result = (*map_ptr->write_func) (map_ptr, &cmdblk);
      } else {
	result = -1;
      }
      vulpes_log(LOG_FAUXIDE_REQ,"WRITE_DONE","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (result == 0) {
	tally_sector_accesses(1, cmdblk.head.num_sect);
	if (valid_stats(map_ptr)) {
	  if ((*map_ptr->stats->record_write) (map_ptr->stats,&cmdblk.head)) {
	    vulpes_log(LOG_ERRORS,"VULPES_MAIN","ERROR: issuing logstats record_write()");
	  }
	}
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
  for (i = 0; i < num_mappings; i++) {
    /* Unregister process */
    VULPES_DEBUG("\tUnregistering device %d.\n", (int) i);
    if (vulpes_unregister(i)) {
      vulpes_log(LOG_ERRORS,"VULPES_MAIN","failed to unregister %s", mapping[i].device_name);
    }
    vulpes_log(LOG_BASIC,"VULPES_MAIN","un-Registered process with device");
    
    /* Close device */
    VULPES_DEBUG("\tClosing device %d.\n", (int) i);
    close(mapping[i].vulpes_device);
    
    /* Close stats */
    VULPES_DEBUG("\tClosing stats %d.\n", (int) i);
    if (valid_stats(&mapping[i])) {
      (*mapping[i].stats->close) (mapping[i].stats);
      free(mapping[i].stats);
      mapping[i].stats = NULL;
    }
    
    /* Close file */
    VULPES_DEBUG("\tClosing map %d.\n", (int) i);
    if ((*mapping[i].close_func) (&mapping[i]) == -1) {
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","close function failed");
	exit(1);
      }

    /* Close the LKA service */
    if(mapping[i].lka_svc != NULL)
      if(vulpes_lka_close(mapping[i].lka_svc) != VULPES_LKA_RETURN_SUCCESS)
	vulpes_log(LOG_ERRORS,"VULPES_MAIN","failure during lka_close().");    
  }
  
  /* Close the fidsvc */
  fidsvc_close();
  
  /* Print stats */
  vulpes_log(LOG_STATS,"VULPES","Sectors read:%llu",sectors_read);
  vulpes_log(LOG_STATS,"VULPES","Sectors written:%llu",sectors_written);
  vulpes_log(LOG_STATS,"VULPES","Sectors accessed:%llu",sectors_accessed);

  
 vulpes_exit:
  vulpes_log(LOG_BASIC,"VULPES_FINISH", "");
  vulpes_log_close();
  exit(0);
  
  return 0;
}
