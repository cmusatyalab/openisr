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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/timeb.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include "vulpes_log.h"

static void vulpes_timestamp(char timestamp_coarse[128], char timestamp_fine[32])
{
  struct timeb tp;
  
  ftime(&tp);

  sprintf(timestamp_fine,"%d",(int)(tp.millitm));

  ctime_r(&(tp.time),timestamp_coarse);
  /* delete the newline in timestamp_coarse */
  *index(timestamp_coarse, '\n')='\0';
}

static inline int vulpes_log_fflush_needed(enum logmsgtype msgtype)
{
  return (int)((msgtype==LOG_BASIC) || (msgtype==LOG_ERRORS));
}

vulpes_err_t vulpes_log_init(void)
{
  if (config.log_file_name == NULL)
    return VULPES_SUCCESS;
  
  if ((state.log_fp = fopen(config.log_file_name, "a")) == NULL) {
    vulpes_log(LOG_ERRORS,"Could not create or open %s in write mode",config.log_file_name);
    return VULPES_IOERR;
  }
  return VULPES_SUCCESS;
}

void vulpes_log_close(void)
{
  int ret;
  
  if (state.log_fp == NULL)
    return;
  
  ret=fclose(state.log_fp);
  state.log_fp=NULL;
  if (ret)
    vulpes_log(LOG_ERRORS,"Close of logging file failed");
}

static inline int log_msgtype_active_file(enum logmsgtype msgtype)
{
  return (state.log_fp != NULL && ((1<<msgtype) & config.log_file_mask)) ? 1 : 0;
}

static inline int log_msgtype_active_stdout(enum logmsgtype msgtype)
{
  return ((1<<msgtype) & config.log_stdout_mask) ? 1 : 0;
}

/* This may be called at any time, whether vulpes_log_init() has been called
   or not */
void _vulpes_log(enum logmsgtype msgtype, const char *func,
                const char *format, ...)
{
  unsigned writefile, writestdout;
  char timestamp_coarse[128];
  char timestamp_fine[32];
  const char *s_msgtype;
  char s_func[32];
  char s_buf[6];
  va_list ap;
  int i;

  writefile = log_msgtype_active_file(msgtype);
  writestdout = log_msgtype_active_stdout(msgtype);

  if(!(writefile || writestdout))
    return;

  vulpes_timestamp(timestamp_coarse, timestamp_fine);

  /* Set the msg type string */
  switch(msgtype) {
  case LOG_ERRORS:
    s_msgtype="ERROR";
    break;
  case LOG_STATS:
    s_msgtype="STATS";
    break;
  case LOG_BASIC:
    s_msgtype="EVENT";
    break;
  case LOG_CHUNKS:
    s_msgtype="CHUNK";
    break;
  case LOG_KEYS:
    s_msgtype="CKEYS";
    break;
  case LOG_TRANSPORT:
    s_msgtype="TRANS";
    break;
  case LOG_DRIVER_REQ:
    s_msgtype="REQ";
    break;
  default:
    sprintf(s_buf,"MSG%02u", (unsigned)msgtype);
    s_msgtype=s_buf;
  }
  
  if (func == NULL) {
    sprintf(s_func, "UNKNOWN");
  } else {
    /* Uppercase the function name */
    for (i=0; i<sizeof(s_func)-1; i++) {
      s_func[i]=toupper(func[i]);
      if (s_func[i] == 0)
	break;
    }
    s_func[sizeof(s_func)-1]=0;
  }
  
  /* XXX log messages are no longer printed atomically, so this will give
     us problems if we switch to threads */
  if(writefile) {
    va_start(ap, format);
    fprintf(state.log_fp, "%s%s%s:%s:%s:",
            timestamp_coarse,
            config.log_infostr,
            s_msgtype,
            timestamp_fine,
            s_func);
    vfprintf(state.log_fp, format, ap);
    fprintf(state.log_fp, "\n");
    va_end(ap);
    if(vulpes_log_fflush_needed(msgtype))
      fflush(state.log_fp);
  }

  if(writestdout) {
    va_start(ap, format);
    printf("%s%s%s:%s:%s:",
           timestamp_coarse,
           config.log_infostr,
           s_msgtype,
           timestamp_fine,
           s_func);
    vprintf(format, ap);
    printf("\n");
    va_end(ap);
    if(vulpes_log_fflush_needed(msgtype))
      fflush(stdout);
  }
}
