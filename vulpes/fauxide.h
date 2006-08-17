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

/* $Id: fauxide.h,v 1.5 2004/11/01 16:18:52 makozuch Exp $ */

#ifndef FAUXIDE_H_
#define FAUXIDE_H_

#ifdef __KERNEL__
#  include <linux/ioctl.h>
#else
#  include <sys/ioctl.h>
#endif

#define FAUXIDE_HARDSECT_SIZE        512
#define FAUXIDE_SECTORS_PER_KB       (1024 / FAUXIDE_HARDSECT_SIZE)

typedef int vulpes_cmd_t;
/* Sent by fauxide */
#define VULPES_CMD_SLEEP      0x00	/* vulpes should go to sleep */
#define VULPES_CMD_READ       0x01	/* vulpes will return some data */
#define VULPES_CMD_WRITE      0x02	/* vulpes will store some data */
/* Sent by vulpes */
#define VULPES_CMD_REGISTER   0x20	/* vulpes registers itself */
#define VULPES_CMD_UNREGISTER 0x21	/* vulpes unregisters itself */
#define VULPES_CMD_GET        0x80	/* vulpes needs the next command */
#define VULPES_CMD_READ_DONE  0x81	/* vulpes is returning data in the buffer */
#define VULPES_CMD_WRITE_DONE 0x82	/* vulpes has finished writing */
#define VULPES_CMD_ERROR      0xEE	/* vulpes has detected an error */

#define VULPES_CMDBLK_SECT_PER_BUF   8
#define VULPES_CMDBLK_BUFSIZE        (VULPES_CMDBLK_SECT_PER_BUF*FAUXIDE_HARDSECT_SIZE)	/* bytes */

#define VULPES_REGBLK_SECT_PER_BUF   8
#define VULPES_REGBLK_BUFSIZE        (VULPES_REGBLK_SECT_PER_BUF*FAUXIDE_HARDSECT_SIZE)	/* bytes */

typedef unsigned vulpes_id_t;
typedef struct vulpes_cmd_head_s {
    vulpes_id_t vulpes_id;	/* Id used by vulpes to identify vulpes instance */
    vulpes_cmd_t cmd;
    unsigned long start_sect;
    unsigned long num_sect;
    void *fauxide_id;		/* Id used by fauxide to identify the request */
} vulpes_cmd_head_t;

typedef struct vulpes_cmdblk_s {
    vulpes_cmd_head_t head;
    char buffer[VULPES_CMDBLK_BUFSIZE];
} vulpes_cmdblk_t;

typedef unsigned long vulpes_volsize_t;
#define MAX_VOLSIZE_VALUE      (~(vulpes_volsize_t)0)

typedef struct vulpes_registration_s {
    vulpes_id_t vulpes_id;	/* Id used by vulpes to identify vulpes instance */
    pid_t pid;
    vulpes_volsize_t volsize;	/* Size in sectors */
} vulpes_registration_t;

typedef struct vulpes_regblk_s {
    vulpes_registration_t reg;
    char buffer[VULPES_REGBLK_BUFSIZE];
} vulpes_regblk_t;
#define _FAUXIDE_IOCTL_TYPE                 0xF2

#define FAUXIDE_IOCTL_REGBLK_REGISTER       _IOWR(_FAUXIDE_IOCTL_TYPE, 0x10, vulpes_regblk_t)
#define FAUXIDE_IOCTL_REGBLK_UNREGISTER     _IOWR(_FAUXIDE_IOCTL_TYPE, 0x11, vulpes_registration_t)
#define FAUXIDE_IOCTL_CMDBLK                _IOWR(_FAUXIDE_IOCTL_TYPE, 0x80, vulpes_cmdblk_t)

#define FAUXIDE_IOCTL_RESCUE                _IO(_FAUXIDE_IOCTL_TYPE, 0xD0)
#define FAUXIDE_IOCTL_TEST_SIGNAL           _IO(_FAUXIDE_IOCTL_TYPE, 0xD2)

#endif				/* FAUXIDE_H_ */
