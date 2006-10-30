#ifndef VULPES_H
#define VULPES_H

/* This header is sort of hacked-together.  Eventually, when we get cleaner
   interfaces, this should be cleaned up a bit. */

#include <stdio.h>
#include "vulpes_map.h"

#undef VERBOSE_DEBUG
#ifdef VERBOSE_DEBUG
#define VULPES_DEBUG(fmt, args...)     {printf("[vulpes] " fmt, ## args); fflush(stdout);}
#else
#define VULPES_DEBUG(fmt, args...)     ;
#endif

extern volatile int exit_pending;
extern struct vulpes_mapping mapping;

int set_signal_handler(int sig, void (*handler)(int sig));
void tally_sector_accesses(unsigned write, unsigned num);

typedef enum vulpes_err {
  VULPES_SUCCESS=0,
  VULPES_OVERFLOW,
  VULPES_IOERR,
  VULPES_NOTFOUND,
  VULPES_INVALID,
  VULPES_NOMEM,
} vulpes_err_t;

#endif
