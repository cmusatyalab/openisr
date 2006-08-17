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
#include "vulpes_log.h"

#define MAX_FNAME_SIZE 128

const char *vulpes_log_c_version = "$Id: vulpes_log.c,v 1.12 2004/12/10 20:46:37 makozuch Exp $";

typedef struct log_s {
  char fname[MAX_FNAME_SIZE+1];
  char *infostr;
  FILE *logf;
  unsigned logf_mask;
  unsigned stdout_mask;
} log_t;

static log_t gl_log = {"/dev/null", NULL, NULL, 0, 1};

/*
 * LOCAL FUNCTIONS
 */

static void vulpes_timestamp(char timestamp_coarse[128], char timestamp_fine[32])
{
  struct timeb tp;
  
  ftime(&tp);

  sprintf(timestamp_fine,"%d",(int)(tp.millitm));

  ctime_r(&(tp.time),timestamp_coarse);
  /* delete the newline in timestamp_coarse */
  *index(timestamp_coarse, '\n')='\0';
}

static __inline
int vulpes_log_fflush_needed(logmsg_t msgtype)
{
  return (int)((msgtype==LOG_BASIC) || (msgtype==LOG_ERRORS));
}

/*
 * INTERFACE FUNCTIONS
 */

int vulpes_log_init(const char* fname, const char *info_str, unsigned logfile_mask, unsigned  stdout_mask)
{
  size_t len;

  /* copy the info string */
  if(info_str!=NULL) {
    len = strlen(info_str);
    if((gl_log.infostr = malloc(len+1)) == NULL) {
      printf("[vulpes_log] ERROR: malloc() failure\n");
      return 1;
    }
    strcpy(gl_log.infostr, info_str);
  } else {
    gl_log.infostr = NULL;
  }

  /* check to ensure that the filename will fit */
  if((len=strlen(fname)) > MAX_FNAME_SIZE) {
    printf("[vulpes_log] ERROR: log filename too long\n");
    return 2;
  }

  /* save the filename */
  strncpy(gl_log.fname, fname, MAX_FNAME_SIZE);
  gl_log.fname[MAX_FNAME_SIZE]='\0';

  /* open the file */
  if((gl_log.logf = fopen(gl_log.fname, "a")) == NULL) {
    printf("[vulpes_log] Could not create or open %s in write mode\n",gl_log.fname);
    return 3;
  }
  
  /* save the mask values */
  gl_log.logf_mask = logfile_mask;
  gl_log.stdout_mask = stdout_mask;
 
  return 0;
}

int vulpes_log_close(void)
{
  if(gl_log.infostr != NULL) {
    free(gl_log.infostr);
    gl_log.infostr = NULL;
  }

  if(fclose(gl_log.logf)) {
    printf("[vulpes_log] ERROR: close of logging file failed.\n");
    return 1;
  }

  gl_log.logf_mask = 0;

  return 0;
}

static __inline
int log_msgtype_active_file(logmsg_t msgtype)
{
  return (((1<<msgtype) & gl_log.logf_mask) ? 1 : 0);
}

static __inline
int log_msgtype_active_stdout(logmsg_t msgtype)
{
  return (((1<<msgtype) & gl_log.stdout_mask) ? 1 : 0);
}

int log_msgtype_active(logmsg_t msgtype)
{
  return (log_msgtype_active_file(msgtype) || log_msgtype_active_stdout(msgtype));
}

int vulpes_log(logmsg_t msgtype, const char *msghdr, const char* field2, const char *field3, 
	       const char *field4, const char *field5)
{
  unsigned writefile, writestdout;

  writefile = log_msgtype_active_file(msgtype);
  writestdout = log_msgtype_active_stdout(msgtype);

  if(writefile || writestdout) {
    char timestamp_coarse[128];
    char timestamp_fine[32];
    const char *s_msgtype;
    char s_buf[6];
  
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
    case LOG_FAUXIDE_REQ:
      s_msgtype="F_REQ";
      break;
    default:
      sprintf(s_buf,"MSG%02u", (unsigned)msgtype);
      s_msgtype=s_buf;
    }
    
    if(writefile) {
      fprintf(gl_log.logf, "%s%s%s:%s:%s:%s:%s:%s:%s\n",
	      timestamp_coarse,
	      ((gl_log.infostr == NULL) ? " " : gl_log.infostr),
	      s_msgtype,
	      timestamp_fine,
	      ((msghdr == NULL) ? "" : msghdr),
	      ((field2 == NULL) ? "" : field2),
	      ((field3 == NULL) ? "" : field3),
	      ((field4 == NULL) ? "" : field4),
	      ((field5 == NULL) ? "" : field5));
      if(vulpes_log_fflush_needed(msgtype))
	fflush(gl_log.logf);
    }

    if(writestdout) {
      printf("%s%s%s:%s:%s:%s:%s:%s:%s\n",
	     timestamp_coarse,
	     ((gl_log.infostr == NULL) ? " " : gl_log.infostr),
	     s_msgtype,
	     timestamp_fine,
	     ((msghdr == NULL) ? "" : msghdr),
	     ((field2 == NULL) ? "" : field2),
	     ((field3 == NULL) ? "" : field3),
	     ((field4 == NULL) ? "" : field4),
	     ((field5 == NULL) ? "" : field5));
      if(vulpes_log_fflush_needed(msgtype))
	fflush(stdout);
    }
  }
  
  return 0;
}
