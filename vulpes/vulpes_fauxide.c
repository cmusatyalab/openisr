#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include "fauxide.h"
#include "vulpes.h"
#include "vulpes_map.h"
#include "vulpes_log.h"

static volatile int need_wakeup = 0;

static void fauxide_usr1_handler(int sig)
{
  /* fauxide sends SIGUSR1 when it wants us to wake up. */
  VULPES_DEBUG("Caught signal %d\n", sig);
  need_wakeup = 1;
}

/* check kernel version */
static int running_kernel26(void)
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
  
  if (un.release[0] == '2' && un.release[1] == '.' && un.release[2] == '6')
    return 1;
  else
    return 0;
}

static int fauxide_register(void)
{
  int i;
  int result = 0;
  vulpes_regblk_t regblk;
  vulpes_cmdblk_t cmdblk;
  
  config.reg.vulpes_id = 0;
  config.reg.pid = getpid();
  config.reg.volsize = (*config.volsize_func)();
  
  regblk.reg = config.reg;
  
  if (VULPES_REGBLK_SECT_PER_BUF % VULPES_CMDBLK_SECT_PER_BUF == 0) {
    int num_cmds =
      VULPES_REGBLK_SECT_PER_BUF / VULPES_CMDBLK_SECT_PER_BUF;
    for (i = 0; i < num_cmds; i++) {
      /* Create a dummy cmdblk to use the config.read function */
      cmdblk.head.vulpes_id = 0;
      cmdblk.head.cmd = VULPES_CMD_READ;
      cmdblk.head.start_sect = 0;
      cmdblk.head.num_sect = VULPES_CMDBLK_SECT_PER_BUF;
      result = (*config.read_func)(&cmdblk);
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
      ioctl(config.vulpes_device, FAUXIDE_IOCTL_REGBLK_REGISTER,
	    &regblk);
  } else {
    vulpes_log(LOG_ERRORS,"VULPES_REGISTER","bad buffer sizes");
    result = 0;
  }
  
  
  return result;
}

static int fauxide_unregister(void)
{
  int result = 0;
  
  result =
    ioctl(config.vulpes_device, FAUXIDE_IOCTL_REGBLK_UNREGISTER,
	  &config.reg);
  
  return result;
}

static int cmdblk_ok(const vulpes_cmd_head_t * head)
{
  int result = 1;
  
  /* vulpes_id is now ignored */
  
  /* Check command parameters */
  switch (head->cmd) {
  case VULPES_CMD_READ:
  case VULPES_CMD_WRITE:
    if (head->start_sect + head->num_sect > config.reg.volsize)
      result = 0;
    break;
  default:
    result = 0;
  }
  
  return result;
}

int fauxide_init(void)
{
  /* Register special signal handler */
  if (set_signal_handler(SIGUSR1, fauxide_usr1_handler)) {
    vulpes_log(LOG_ERRORS, "FAUXIDE_INIT", "Unable to install signal handler");
    return -1;
  }
  
  /* Open the device */
  VULPES_DEBUG("\tOpening device\n");
  config.vulpes_device = open(config.device_name, O_RDWR);
  if (config.vulpes_device < 0) {
    vulpes_log(LOG_ERRORS,"VULPES_MAIN","unable to open device %s",config.device_name);
    return -1;
  }
  
  /* Register ourselves with the device */
  VULPES_DEBUG("\tRegistering device.\n");
  if (fauxide_register()) {
    vulpes_log(LOG_ERRORS,"FAUXIDE_INIT","Unable to register with Fauxide");
    return -1;
  }
  vulpes_log(LOG_BASIC,"FAUXIDE_INIT","Registered with fauxide");
  
  /* Need to register twice to get 2.6 kernel module to recognize driver properly */
  if (running_kernel26()) {
    /* Unregister process */
    VULPES_DEBUG("\tUnregistering device.\n");
    if (fauxide_unregister()) {
      vulpes_log(LOG_ERRORS,"FAUXIDE_INIT","Failed to unregister: %s", config.device_name);
    }
    vulpes_log(LOG_BASIC,"FAUXIDE_INIT","Un-registered process with Fauxide");
    /* Close device */
    VULPES_DEBUG("\tClosing device.\n");
    close(config.vulpes_device);
    /* Open the device */
    VULPES_DEBUG("\tOpening device.\n");
    config.vulpes_device = open(config.device_name, O_RDWR);
    if (config.vulpes_device < 0) {
      vulpes_log(LOG_ERRORS,"FAUXIDE_INIT","Unable to open device %s",config.device_name);
      return -1;
    }
    /* Register ourselves with the device */
    VULPES_DEBUG("\tRegistering device.\n");
    if (fauxide_register()) {
      vulpes_log(LOG_ERRORS,"FAUXIDE_INIT","Unable to register process with Fauxide");
      return -1;
    }
    vulpes_log(LOG_BASIC,"FAUXIDE_INIT","Registered process with Fauxide");
  }
  return 0;
}

void fauxide_shutdown(void)
{
  /* Unregister process */
  VULPES_DEBUG("\tUnregistering device.\n");
  if (fauxide_unregister()) {
    vulpes_log(LOG_ERRORS,"FAUXIDE_SHUTDOWN","failed to unregister %s", config.device_name);
  }
  vulpes_log(LOG_BASIC,"FAUXIDE_SHUTDOWN","un-Registered process with device");
  
  /* Close device */
  VULPES_DEBUG("\tClosing device.\n");
  close(config.vulpes_device);
}

void fauxide_run(void)
{
  vulpes_cmdblk_t cmdblk;
  unsigned long long request_counter=0;
  
  /* Initialize cmdblk */
  cmdblk.head.cmd = VULPES_CMD_GET;
  cmdblk.head.vulpes_id=0;
  cmdblk.head.fauxide_id=NULL;
  
  /* Enter processing loop */
  do {
    int result = 0;
    
    /* Execute ioctl */
    ioctl(config.vulpes_device, FAUXIDE_IOCTL_CMDBLK, &cmdblk);
    
    /* Process cmd */
    switch (cmdblk.head.cmd) {
    case VULPES_CMD_READ:
      vulpes_log(LOG_FAUXIDE_REQ,"READ_IN","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (cmdblk_ok(&(cmdblk.head))) {
	result = (*config.read_func)(&cmdblk);
      } else {
	vulpes_log(LOG_ERRORS,"FAUXIDE_RUN","%llu:%lu:%lu: bad cmdblk",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
	result = -1;
      }
      vulpes_log(LOG_FAUXIDE_REQ,"READ_OUT","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (result == 0) {
	tally_sector_accesses(0, cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_READ_DONE;
      } else {
	vulpes_log(LOG_ERRORS,"FAUXIDE_RUN","%llu:%lu:%lu: read failed",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_ERROR;
      }
      request_counter++;
      break;
    case VULPES_CMD_WRITE:
      vulpes_log(LOG_FAUXIDE_REQ,"WRITE_IN","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (cmdblk_ok(&(cmdblk.head))) {
	result = (*config.write_func)(&cmdblk);
      } else {
	result = -1;
      }
      vulpes_log(LOG_FAUXIDE_REQ,"WRITE_DONE","%llu:%lu:%lu",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
      if (result == 0) {
	tally_sector_accesses(1, cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_WRITE_DONE;
      } else {
	vulpes_log(LOG_ERRORS,"FAUXIDE_RUN","%llu:%lu:%lu: write failed",request_counter,cmdblk.head.start_sect,cmdblk.head.num_sect);
	cmdblk.head.cmd = VULPES_CMD_ERROR;
      }
      request_counter++;
      break;
    case VULPES_CMD_SLEEP:
      VULPES_DEBUG("Going to sleep...\n");
      if (!need_wakeup && !exit_pending) {
	int tmp;
	/* Give the system one last chance to post a request */
#ifdef _POSIX_PRIORITY_SCHEDULING
	tmp = sched_yield();
	if (tmp)
	  vulpes_log(LOG_ERRORS,"FAUXIDE_RUN","sched_yield: %d",errno);
#else
	usleep(20000);	/* 20 msec */
#endif
	if (!need_wakeup && !exit_pending) {
	  VULPES_DEBUG("  ZZzzz...\n");
	  sleep(1);
	}
      }
      need_wakeup = 0;
      VULPES_DEBUG("\t...woke up.\n");
      cmdblk.head.cmd = VULPES_CMD_GET;	/* Next call is "get" */
      break;
    default: 
      vulpes_log(LOG_ERRORS,"FAUXIDE_RUN","ERROR: unknown vulpes command %d",cmdblk.head.cmd);
    }
  } while (exit_pending == 0);
}

int fauxide_rescue(const char *device_name)
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
