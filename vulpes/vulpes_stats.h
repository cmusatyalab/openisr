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

#ifndef VULPES_STATS_H_
#define VULPES_STATS_H_

/* 00 - not accessed, 01 - read, clean
 * 10 - blind write, 11 - read, dirty */

/*
typedef struct vulpes_access_record_s {
  vulpes_volsize_t num_sectors;
  unsigned char *sector_state;      // huge bit vector - state of sector s 
                                    // is in sector_state[s/4]:(s%4)
  unsigned long long transitions[4][4];   // transitions from state i to j
} vulpes_access_record_t;
*/

typedef enum {
  STATS_NONE=0,
  STATS_REQLOG=1
} stats_type_t ;


typedef struct vulpes_stats_s vulpes_stats_t;

typedef int (*vulpes_stats_open_func_t) (vulpes_stats_t *);
typedef int (*vulpes_stats_record_read_func_t) (vulpes_stats_t *,
						vulpes_cmd_head_t *);
typedef int (*vulpes_stats_record_write_func_t) (vulpes_stats_t *,
						 vulpes_cmd_head_t *);
typedef int (*vulpes_stats_close_func_t) (vulpes_stats_t *);

struct vulpes_stats_s {
    vulpes_stats_open_func_t open;
    vulpes_stats_record_read_func_t record_read;
    vulpes_stats_record_write_func_t record_write;
    vulpes_stats_close_func_t close;
    void *special;
};

#endif
