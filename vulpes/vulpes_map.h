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

#ifndef VULPES_MAP_H_
#define VULPES_MAP_H_

#include "fauxide.h"

enum transfer_type {
  NO_TRANSPORT=0,
  LOCAL_TRANSPORT,
  HTTP_TRANSPORT,
};

enum mapping_type {
  NO_MAPPING=0,
  SIMPLE_FILE_MAPPING,
  SIMPLE_DISK_MAPPING,
  LEV1_MAPPING,
  LEV1V_MAPPING,
};

typedef int (*vulpes_open_func_t) (void);
typedef vulpes_volsize_t(*vulpes_volsize_func_t) (void);
typedef int (*vulpes_read_func_t) (vulpes_cmdblk_t *);
typedef int (*vulpes_write_func_t) (const vulpes_cmdblk_t *);
typedef int (*vulpes_close_func_t) (void);

struct vulpes_config {
  enum transfer_type trxfer;	/* Set by main */
  enum mapping_type mapping;    /* Set by main */
  char* proxy_name;             /* Set by main */
  long  proxy_port;             /* set by main */
  
  char *device_name;		/* Set by main */
  char *master_name;		/* Set by main */
  char *cache_name;		/* Set by main */
  char *keyring_name;		/* Set by main */

  int vulpes_device;		/* Set by device driver */
  
  vulpes_registration_t reg;	        /* Set in open_func */
  vulpes_open_func_t open_func;	        /* Set in initialize */
  vulpes_volsize_func_t volsize_func;	/* Set in initialize */
  vulpes_read_func_t read_func;	        /* Set in initialize */
  vulpes_write_func_t write_func;	/* Set in initialize */
  vulpes_close_func_t close_func;	/* Set in initialize */
  
  int verbose;			/* Set by main -- currently not used */
  struct lka_svc *lka_svc;     /* Set by main */
  void *special;		/* Set in open_func */
};

#endif
