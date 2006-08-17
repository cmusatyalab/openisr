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

#ifndef VULPES_LOG_H
#define VULPES_LOG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
  LOG_ERRORS=0,
  LOG_STATS=1,
  LOG_BASIC=2,
  LOG_CHUNKS=3,
  LOG_KEYS=4,
  LOG_TRANSPORT=5,
  LOG_FAUXIDE_REQ=7
} logmsg_t ;
  
int vulpes_log_init(const char *fname, const char *info_str, 
		    unsigned logfile_mask, unsigned stdout_mask);

int vulpes_log_close(void);

int log_msgtype_active(logmsg_t msgtype);

int vulpes_log(logmsg_t msgtype, const char *msg_hdr, const char* part_one, 
	       const char *part_two, const char *part_three, 
	       const char *part_four);
  
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
