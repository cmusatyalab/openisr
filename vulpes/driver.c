/* 
 * Vulpes - support daemon for the OpenISR (R) system virtual disk
 * 
 * Copyright (C) 2002-2005 Intel Corporation
 * Copyright (C) 2005-2007 Carnegie Mellon University
 * 
 * This software is distributed under the terms of the Eclipse Public License, 
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE, 
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <time.h>
#include <linux/loop.h>
#include "vulpes.h"
#include "log.h"
#include "util.h"
#include "nexus.h"

static const int ignored_signals[]={SIGUSR1, SIGUSR2, SIGHUP, SIGTSTP, 0};
static const int caught_signals[]={SIGINT, SIGQUIT, SIGTERM, 0};

#define DEVFILE_NAME "vulpes.dev"
#define REQUESTS_PER_SYSCALL 64
#define WRITEBACK_INTERVAL 60
#define WRITEBACK_IDLE_TIME 5
#define LOOP_UNREGISTER_TRIES 500
#define MY_INTERFACE_VERSION 5
#if MY_INTERFACE_VERSION != NEXUS_INTERFACE_VERSION
#error This code uses a different interface version than the one defined in convergent-user.h
#endif

static void signal_handler(int sig)
{
  char c=sig;
  VULPES_DEBUG("Caught signal %d\n", sig);
  /* Race-free method of catching signals */
  write(state.signal_fds[1], &c, 1);
  /* The fd is set nonblocking, so if the pipe is full, the signal will be
     lost */
}

static vulpes_err_t message_ok(const struct nexus_message *msg)
{
  int result = 1;
  
  /* Check command parameters */
  switch (msg->type) {
  case NEXUS_MSGTYPE_GET_META:
  case NEXUS_MSGTYPE_UPDATE_META:
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
      if (ioctl(fd, LOOP_SET_FD, fileno(state.cachefile_fp))) {
	vulpes_log(LOG_ERRORS,"Couldn't bind to loop device");
	return VULPES_IOERR;
      }
      /* This is required in order to properly configure the (null)
	 transfer function, even though it shouldn't be */
      if (ioctl(fd, LOOP_GET_STATUS64, &info)) {
	vulpes_log(LOG_ERRORS,"Couldn't get status of loop device");
	ioctl(fd, LOOP_CLR_FD, 0);
	return VULPES_IOERR;
      }
      snprintf((char*)info.lo_file_name, LO_NAME_SIZE, "%s", state.image_name);
      if (ioctl(fd, LOOP_SET_STATUS64, &info)) {
	vulpes_log(LOG_ERRORS,"Couldn't configure loop device");
	ioctl(fd, LOOP_CLR_FD, 0);
	return VULPES_IOERR;
      }
      break;
    }
    close(fd);
  }
  state.loopdev_fd=fd;
  vulpes_log(LOG_BASIC,"Bound to loop device %s",state.loopdev_name);
  return VULPES_SUCCESS;
}

vulpes_err_t driver_init(void)
{
  struct nexus_setup setup;
  vulpes_err_t ret;
  int i;
  char revision[64];
  char protocol[8];
  unsigned protocol_i;
  struct utsname utsname;
  FILE *fp;
  
  /* Check driver version */
  if (!is_dir("/sys/class/openisr")) {
    vulpes_log(LOG_ERRORS,"kernel module not loaded");
    return VULPES_NOTFOUND;
  }
  if (read_sysfs_file("/sys/class/openisr/version", protocol, sizeof(protocol))) {
    vulpes_log(LOG_ERRORS,"can't get driver protocol version");
    return VULPES_PROTOFAIL;
  }
  if (sscanf(protocol, "%u", &protocol_i) != 1) {
    vulpes_log(LOG_ERRORS,"can't parse protocol version");
    return VULPES_PROTOFAIL;
  }
  if (protocol_i != MY_INTERFACE_VERSION) {
    vulpes_log(LOG_ERRORS,"protocol mismatch: expected version %u, got version %u",MY_INTERFACE_VERSION,protocol_i);
    return VULPES_PROTOFAIL;
  }
  if (read_sysfs_file("/sys/class/openisr/revision", revision, sizeof(revision))) {
    vulpes_log(LOG_ERRORS,"can't get driver revision");
    return VULPES_PROTOFAIL;
  }
  vulpes_log(LOG_BASIC,"Driver protocol %u, revision %s",protocol_i,revision);
  
  /* Log kernel version */
  if (uname(&utsname))
    vulpes_log(LOG_ERRORS,"Can't get kernel version");
  else
    vulpes_log(LOG_BASIC,"%s %s (%s) on %s",utsname.sysname,utsname.release,utsname.version,utsname.machine);
  
  /* Create signal-passing pipe */
  if (pipe(state.signal_fds)) {
    vulpes_log(LOG_ERRORS,"couldn't create pipe");
    return VULPES_CALLFAIL;
  }
  /* Set it nonblocking */
  if (fcntl(state.signal_fds[0], F_SETFL, O_NONBLOCK) ||
      fcntl(state.signal_fds[1], F_SETFL, O_NONBLOCK)) {
    vulpes_log(LOG_ERRORS,"couldn't set pipe nonblocking");
    return VULPES_CALLFAIL;
  }
  /* Register signal handler */
  for (i=0; caught_signals[i] != 0; i++) {
    if (set_signal_handler(caught_signals[i], signal_handler)) {
      vulpes_log(LOG_ERRORS,"unable to register default signal handler for signal %d",caught_signals[i]);
      return VULPES_CALLFAIL;
    }
  }
  /* Ignore signals that don't make sense for us */
  for (i=0; ignored_signals[i] != 0; i++) {
    if (set_signal_handler(ignored_signals[i], SIG_IGN)) {
      vulpes_log(LOG_ERRORS,"unable to ignore signal %d",ignored_signals[i]);
      return VULPES_CALLFAIL;
    }
  }
  
  /* Open the device.  O_NONBLOCK ensures we never block on a read(), but
     write() may still block */
  state.chardev_fd = open("/dev/openisrctl", O_RDWR|O_NONBLOCK);
  if (state.chardev_fd < 0) {
    if (errno == ENOENT) {
      vulpes_log(LOG_ERRORS,"/dev/openisrctl does not exist");
      return VULPES_NOTFOUND;
    } else {
      vulpes_log(LOG_ERRORS,"unable to open /dev/openisrctl");
      return VULPES_IOERR;
    }
  }
  
  /* Open the regular file that will contain the name of the device node
     we receive */
  if (form_lockdir_file_name(state.devfile_name, sizeof(state.devfile_name), DEVFILE_NAME))
    return VULPES_OVERFLOW;
  fp=fopen(state.devfile_name, "w");
  if (fp == NULL) {
    vulpes_log(LOG_ERRORS,"couldn't open %s for writing",state.devfile_name);
    return VULPES_IOERR;
  }
  
  /* Bind the image file to a loop device */
  ret=loop_bind();
  if (ret) {
    fclose(fp);
    unlink(state.devfile_name);
    return ret;
  }
  
  /* Register ourselves with the device */
  memset(&setup, 0, sizeof(setup));
  snprintf((char*)setup.chunk_device, NEXUS_MAX_DEVICE_LEN, "%s", state.loopdev_name);
  setup.offset=state.offset_bytes / SECTOR_SIZE;
  setup.chunksize=state.chunksize_bytes;
  setup.cachesize=128;
  setup.crypto=NEXUS_CRYPTO_BLOWFISH_SHA1_COMPAT;
  setup.compress_default=NEXUS_COMPRESS_ZLIB;
  setup.compress_required=(1<<NEXUS_COMPRESS_NONE)|(1<<NEXUS_COMPRESS_ZLIB);
  
  if (ioctl(state.chardev_fd, NEXUS_IOC_REGISTER, &setup)) {
    vulpes_log(LOG_ERRORS,"unable to register with device driver: %s",strerror(errno));
    ioctl(state.loopdev_fd, LOOP_CLR_FD, 0);
    fclose(fp);
    unlink(state.devfile_name);
    return VULPES_IOERR;
  }
  fprintf(fp, "/dev/openisr%c\n", 'a' + setup.index);
  fclose(fp);
  state.bdev_index=setup.index;
  vulpes_log(LOG_BASIC,"Registered with driver");
  return VULPES_SUCCESS;
}

static void log_sysfs_value(char *attr)
{
  char fname[MAX_PATH_LENGTH];
  char buf[32];
  
  snprintf(fname, sizeof(fname), "/sys/class/openisr/openisr%c/%s",
				 'a' + state.bdev_index, attr);
  if (read_sysfs_file(fname, buf, sizeof(buf))) {
    vulpes_log(LOG_STATS,"%s:unknown",attr);
  } else {
    vulpes_log(LOG_STATS,"%s:%s",attr,buf);
  }
}

void driver_shutdown(void)
{
  int i;
  
  log_sysfs_value("cache_hits");
  log_sysfs_value("cache_misses");
  log_sysfs_value("cache_alloc_failures");
  log_sysfs_value("chunk_reads");
  log_sysfs_value("chunk_writes");
  log_sysfs_value("chunk_errors");
  log_sysfs_value("chunk_encrypted_discards");
  log_sysfs_value("whole_chunk_updates");
  log_sysfs_value("sectors_read");
  log_sysfs_value("sectors_written");
  log_sysfs_value("compression_ratio_pct");
  
  close(state.chardev_fd);
  unlink(state.devfile_name);
  
  /* XXX Sometimes the loop device doesn't unregister the first time.  For now,
     we retry (a lot) to try to ensure that the user isn't left with a stale
     binding.  However, we still print the warning as a debug aid. */
  for (i=0; i<LOOP_UNREGISTER_TRIES; i++) {
    if (!ioctl(state.loopdev_fd, LOOP_CLR_FD, 0)) {
      if (i > 0)
        vulpes_log(LOG_ERRORS,"Had to try %d times to unbind loop device",i+1);
      break;
    }
    usleep(10000);
  }
  if (i == LOOP_UNREGISTER_TRIES)
    vulpes_log(LOG_ERRORS,"Couldn't unbind loop device");
  
  close(state.loopdev_fd);
  /* We don't trust the loop driver */
  sync();
  sync();
  sync();
}

/* Returns true if there's an outgoing message to send */
static int process_message(struct nexus_message *request,
			   struct nexus_message *reply)
{
  /* Log and verify command */
  switch (request->type) {
  case NEXUS_MSGTYPE_GET_META:
    reply->chunk=request->chunk;
    if (message_ok(request)) {
      vulpes_log(LOG_DRIVER_REQ,"GET: %llu:%llu",state.request_count,request->chunk);
    } else {
      vulpes_log(LOG_ERRORS,"GET: %llu:%llu: bad message",state.request_count,request->chunk);
      reply->type=NEXUS_MSGTYPE_META_HARDERR;
      return 1;
    }
    break;
  case NEXUS_MSGTYPE_UPDATE_META:
    if (message_ok(request)) {
      vulpes_log(LOG_DRIVER_REQ,"UPDATE: %llu:%llu",state.request_count,request->chunk);
    } else {
      vulpes_log(LOG_ERRORS,"UPDATE: %llu:%llu: bad message",state.request_count,request->chunk);
      return 0;
    }
    break;
  default:
    vulpes_log(LOG_ERRORS,"UNKNOWN: %llu:%llu",state.request_count,request->chunk);
    return 0;
  }
  
  /* Process command */
  switch (request->type) {
  case NEXUS_MSGTYPE_GET_META:
    if (cache_get(request, reply)) {
      vulpes_log(LOG_ERRORS,"GET: %llu:%llu: failed",state.request_count,request->chunk);
      reply->type=NEXUS_MSGTYPE_META_HARDERR;
    } else {
      reply->type=NEXUS_MSGTYPE_SET_META;
    }
    return 1;
  case NEXUS_MSGTYPE_UPDATE_META:
    cache_update(request);
    return 0;
  }
  /* Make compiler happy */
  return 0;
}

static void process_batch(void)
{
  struct nexus_message requests[REQUESTS_PER_SYSCALL];
  struct nexus_message replies[REQUESTS_PER_SYSCALL];
  int i;
  int in_count;
  int out_count=0;

  in_count=read(state.chardev_fd, &requests, sizeof(requests));
  if (in_count % sizeof(requests[0]))
    vulpes_log(LOG_ERRORS,"Short read from device driver: %d",in_count);
  in_count /= sizeof(requests[0]);
  
  for (i=0; i<in_count; i++) {
    if (process_message(&requests[i], &replies[out_count]))
      out_count++;
    state.request_count++;
  }
  
  if (out_count == 0)
    return;
  out_count *= sizeof(replies[0]);
  if (write(state.chardev_fd, replies, out_count) != out_count) {
    /* XXX */
    vulpes_log(LOG_ERRORS,"Short write to device driver");
  }
}

void driver_run(void)
{
  fd_set readfds;
  fd_set exceptfds;
  int fdcount=max(state.signal_fds[0], state.chardev_fd) + 1;
  int shutdown_pending=0;
  char signal;
  struct timeval time;
  time_t next_update;
  int ret;
  
  /* Enter processing loop */
  gettimeofday(&time, NULL);
  next_update=time.tv_sec + WRITEBACK_INTERVAL;
  FD_ZERO(&readfds);
  FD_ZERO(&exceptfds);
  for (;;) {
    FD_SET(state.chardev_fd, &readfds);
    FD_SET(state.signal_fds[0], &readfds);
    if (shutdown_pending)
      FD_SET(state.chardev_fd, &exceptfds);
    gettimeofday(&time, NULL);
    time.tv_sec=max(WRITEBACK_IDLE_TIME, next_update - time.tv_sec);
    time.tv_usec=0;
    ret=select(fdcount, &readfds, NULL, &exceptfds, &time);
    if (ret == -1) {
      /* select(2) reports that the fdsets are now undefined, so we start
         over */
      FD_ZERO(&readfds);
      FD_ZERO(&exceptfds);
      if (errno == EINTR) {
	/* Got a signal.  The next time through the loop the pipe will be
	   readable and we can find out what signal it was */
	continue;
      } else {
	vulpes_log(LOG_ERRORS,"select() failed: %s",strerror(errno));
	/* XXX now what? */
      }
    }
    
    /* Run a periodic keyring/cache-header writeback whenever we haven't done
       one in WRITEBACK_INTERVAL seconds and we haven't received any chardev
       traffic in WRITEBACK_IDLE_TIME seconds. */
    /* XXX We do writeout even if no chunks have been modified since the last
       writeout.  In practice it seems that there are usually modified
       chunks. */
    if (ret == 0) {
      gettimeofday(&time, NULL);
      next_update=time.tv_sec + WRITEBACK_INTERVAL;
      cache_writeout();
    }
    
    /* Process pending signals */
    if (FD_ISSET(state.signal_fds[0], &readfds)) {
      while (read(state.signal_fds[0], &signal, sizeof(signal)) > 0) {
	switch (signal) {
	case SIGQUIT:
	  vulpes_log(LOG_BASIC,"Caught SIGQUIT; shutting down immediately");
	  vulpes_log(LOG_BASIC,"Loop unregistration may fail");
	  return;
	default:
	  vulpes_log(LOG_BASIC,"Caught signal; shutdown pending");
	  shutdown_pending=1;
	}
      }
    }
    
    /* If we need to shut down and we think the block device has no users,
       try to unregister */
    if (shutdown_pending && FD_ISSET(state.chardev_fd, &exceptfds)) {
      if (!ioctl(state.chardev_fd, NEXUS_IOC_UNREGISTER))
	return;
    }
    
    /* Process pending requests */
    if (FD_ISSET(state.chardev_fd, &readfds))
      process_batch();
  }
}
