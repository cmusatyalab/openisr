#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include "vulpes.h"
#include "vulpes_log.h"
#include "vulpes_util.h"
#include "convergent-user.h"

static const int caught_signals[]={SIGUSR1, SIGUSR2, SIGHUP, SIGINT, SIGQUIT, 
			SIGABRT, SIGTERM, SIGTSTP, 0};
static volatile int exit_pending = 0;

static void signal_handler(int sig)
{
  VULPES_DEBUG("Caught signal %d\n", sig);
  exit_pending = 1;
}

static vulpes_err_t message_ok(const struct isr_message *msg)
{
  int result = 1;
  
  /* Check command parameters */
  switch (msg->type) {
  case ISR_MSGTYPE_GET_META:
  case ISR_MSGTYPE_UPDATE_META:
    if (msg->chunk > state.numchunks)
      result = 0;
    if (msg->length > state.chunksize_bytes)
      result = 0;
    break;
  default:
    result = 0;
  }
  
  return result;
}

static vulpes_err_t loop_bind(void) {
  struct loop_info64 info;
  int i;
  int fd;
  
  for (i=0 ;; i++) {
    snprintf(state.loopdev_name, sizeof(state.loopdev_name), "/dev/loop%d", i);
    fd=open(state.loopdev_name, O_RDWR|O_SYNC);
    if (fd == -1) {
      vulpes_log(LOG_ERRORS,"Couldn't open loop device");
      return VULPES_IOERR;
    }
    if (ioctl(fd, LOOP_GET_STATUS64, &info) && errno == ENXIO) {
      /* XXX race condition */
      if (ioctl(fd, LOOP_SET_FD, state.cachefile_fd)) {
	vulpes_log(LOG_ERRORS,"Couldn't bind to loop device");
	return VULPES_IOERR;
      }
      /* This is required in order to properly configure the (null)
	 transfer function, even though it shouldn't be */
      if (ioctl(fd, LOOP_GET_STATUS64, &info)) {
	vulpes_log(LOG_ERRORS,"Couldn't get status of loop device");
	return VULPES_IOERR;
      }
      /* XXX we don't set the filename */
      if (ioctl(fd, LOOP_SET_STATUS64, &info)) {
	vulpes_log(LOG_ERRORS,"Couldn't configure loop device");
        return VULPES_IOERR;
      }
      break;
    }
  }
  state.loopdev_fd=fd;
  vulpes_log(LOG_BASIC,"Bound to loop device %s",state.loopdev_name);
  return VULPES_SUCCESS;
}

vulpes_err_t driver_init(void)
{
  struct isr_setup setup;
  vulpes_err_t ret;
  int i;
  
  /* Register signal handler */
  for (i=0; caught_signals[i] != 0; i++) {
    if (set_signal_handler(caught_signals[i], signal_handler)) {
      vulpes_log(LOG_ERRORS,"unable to register default signal handler for signal %d",caught_signals[i]);
      return VULPES_CALLFAIL;
    }
  }
  
  ret=loop_bind();
  if (ret)
    return ret;
  
  /* Open the device */
  state.chardev_fd = open("/dev/openisrctl", O_RDWR);
  if (state.chardev_fd < 0) {
    vulpes_log(LOG_ERRORS,"unable to open character device");
    return VULPES_IOERR;
  }
  
  /* Register ourselves with the device */
  memset(&setup, 0, sizeof(setup));
  snprintf(setup.chunk_device, ISR_MAX_DEVICE_LEN, "%s", state.loopdev_name);
  setup.offset=state.offset_bytes / SECTOR_SIZE;
  setup.chunksize=state.chunksize_bytes;
  setup.cachesize=128;
  setup.crypto=ISR_CRYPTO_BLOWFISH_SHA1_COMPAT;
  setup.compress_default=ISR_COMPRESS_ZLIB;
  setup.compress_required=ISR_COMPRESS_NONE|ISR_COMPRESS_ZLIB;
  
  if (ioctl(state.chardev_fd, ISR_IOC_REGISTER, &setup)) {
    vulpes_log(LOG_ERRORS,"unable to register with device driver: %s",strerror(errno));
    return VULPES_IOERR;
  }
  vulpes_log(LOG_BASIC,"Registered with driver");
  return VULPES_SUCCESS;
}

void driver_shutdown(void)
{
  close(state.chardev_fd);
  ioctl(state.loopdev_fd, LOOP_CLR_FD, 0);
  close(state.loopdev_fd);
}

void driver_run(void)
{
  struct isr_message msg;
  unsigned long long request_counter;
  
  /* Enter processing loop */
  for (request_counter=0; !exit_pending; request_counter++) {
    if (read(state.chardev_fd, &msg, sizeof(msg)) != sizeof(msg)) {
      vulpes_log(LOG_ERRORS,"Short read from device driver");
      break;
    }
    
    switch (msg.type) {
    case ISR_MSGTYPE_GET_META:
      vulpes_log(LOG_FAUXIDE_REQ,"GET: %llu:%llu",request_counter,msg.chunk);
      break;
    case ISR_MSGTYPE_UPDATE_META:
      vulpes_log(LOG_FAUXIDE_REQ,"UPDATE: %llu:%llu",request_counter,msg.chunk);
      break;
    default:
      vulpes_log(LOG_FAUXIDE_REQ,"UNKNOWN: %llu:%llu",request_counter,msg.chunk);
      continue;
    }
    
    if (!message_ok(&msg)) {
      vulpes_log(LOG_ERRORS,"%llu:%llu: bad message",request_counter,msg.chunk);
      continue;
    }
    
    /* Process cmd */
    switch (msg.type) {
    case ISR_MSGTYPE_GET_META:
      if (cache_get(&msg)) {
	vulpes_log(LOG_ERRORS,"%llu:%llu: get failed",request_counter,msg.chunk);
	continue;
      }
      msg.type=ISR_MSGTYPE_SET_META;
      if (write(state.chardev_fd, &msg, sizeof(msg)) != sizeof(msg)) {
	vulpes_log(LOG_ERRORS,"Short write to device driver");
      }
      break;
    case ISR_MSGTYPE_UPDATE_META:
      if (cache_update(&msg)) {
	vulpes_log(LOG_ERRORS,"%llu:%llu: update failed",request_counter,msg.chunk);
      }
      break;
    }
  }
}
