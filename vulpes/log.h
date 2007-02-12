/* 
 * Vulpes - support daemon for the OpenISR (TM) system virtual disk
 * 
 * Copyright (C) 2002-2005 Intel Corporation
 * Copyright (C) 2005-2007 Carnegie Mellon University
 * 
 * This software is distributed under the terms of the Eclipse Public License, 
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE, 
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
 * ACCEPTANCE OF THIS AGREEMENT
 */

#ifndef VULPES_LOG_H
#define VULPES_LOG_H

#include "vulpes.h"

enum logmsgtype {
  LOG_ERRORS=0,
  LOG_STATS=1,
  LOG_BASIC=2,
  LOG_CHUNKS=3,
  LOG_KEYS=4,
  LOG_TRANSPORT=5,
  LOG_DRIVER_REQ=7
};

vulpes_err_t vulpes_log_init(void);

void vulpes_log_close(void);

void _vulpes_log(enum logmsgtype msgtype, const char *func,
                const char *format, ...);

#define vulpes_log(type, fmt, args...) _vulpes_log(type, __func__, fmt, ## args)
#ifdef DEBUG
#define vulpes_debug(type, fmt, args...) vulpes_log(type, fmt, ## args)
#else
#define vulpes_debug(type, fmt, args...) do {} while (0)
#endif

#endif
