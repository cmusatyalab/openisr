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

/* LRU LIST FOR MAINTAINING OPEN FIDs */

#include <stdlib.h>
#include <stdio.h>
#include "vulpes.h"
#include "vulpes_log.h"
#include "vulpes_fids.h"

#define MAX_OPEN_FIDS          128

struct fid_node {
  fid_id_t parent;
  fidsvc_reclamation_func_t reclaim;
  fid_id_t child;
  int index;
};

static struct fid_node fid_array[MAX_OPEN_FIDS];

static int r_num_open_fids = 0;

static fid_id_t mru = NULL_FID_ID;
static fid_id_t lru = NULL_FID_ID;

static int reclaim_fid(fid_id_t ptr)
{
  VULPES_DEBUG("fidsvc: reclaiming fnp %d.\n", (int) ptr);
  
  return (*fid_array[ptr].reclaim) (fid_array[ptr].index);
}

static void init_fid(fid_id_t ptr)
{
  fid_array[ptr].parent = NULL_FID_ID;
  fid_array[ptr].reclaim = NULL;
  fid_array[ptr].index = -1;
  fid_array[ptr].child = NULL_FID_ID;
}

inline int fidsvc_num_open(void)
{
  return r_num_open_fids;
}

static inline fid_id_t set_mru(fid_id_t fnp)
{
  VULPES_DEBUG("fidsvc: setting mru to %d.\n", (int) fnp);
  
  return (mru = fnp);
}

static inline fid_id_t set_lru(fid_id_t fnp)
{
  VULPES_DEBUG("fidsvc: setting lru to %d.\n", (int) fnp);
  
  return (lru = fnp);
}

void fidsvc_get(fid_id_t fnp)
{
  fid_id_t parent, child;
  
  VULPES_DEBUG("fidsvc: getting fnp %d\n", (int) fnp);
  
  /* make fnp the mru, if not already */
  if (fnp != mru) {
    parent = fid_array[fnp].parent;
    child = fid_array[fnp].child;
    
    /* connect the parent and child */
    fid_array[parent].child = child;
    if (fnp != lru) {
      fid_array[child].parent = parent;
    } else {
      /* because fnp!=mru and fnp==lru, we know that mru!=lru */
      set_lru(parent);
    }
    
    /* make fnp the new mru */
    fid_array[mru].parent = fnp;
    fid_array[fnp].parent = NULL_FID_ID;
    fid_array[fnp].child = mru;
    set_mru(fnp);
  }
}

fid_id_t fidsvc_register(fidsvc_reclamation_func_t reclaim, int index)
{
  fid_id_t ptr, new_child;
  
  VULPES_DEBUG("fidsvc: registering fid %d ... \n", (int) fid);
  
  if (r_num_open_fids == MAX_OPEN_FIDS) {
    fid_id_t lru_parent;
    int result;
    
    ptr = lru;
    
    VULPES_DEBUG("fidsvc_register(%d) returning %d [CASE MAX]. \n",
		 (int) fid, (int) ptr);
    
    /*printf("fidsvc_register(%d) returning %d [CASE MAX]. \n",
      (int) fid, (int) ptr);*/
    result = reclaim_fid(lru);
    if (result == -1)
      return -1;
    lru_parent = fid_array[lru].parent;
    fid_array[lru_parent].child = NULL_FID_ID;
    fid_array[mru].parent = ptr;
    new_child = mru;
    set_lru(lru_parent);
  } else if (r_num_open_fids == 0) {
    ptr = 0;
    
    VULPES_DEBUG("fidsvc_register(%d) returning %d [CASE 0]. \n",
		 (int) fid, (int) ptr);
    
    new_child = NULL_FID_ID;
    r_num_open_fids++;
    set_lru(0);
  } else {
    for (ptr = 0; ptr < MAX_OPEN_FIDS; ptr++)
      if ((fid_array[ptr].parent == NULL_FID_ID) && (ptr != mru))
	break;
    
    VULPES_DEBUG("fidsvc_register(%d) returning %d [CASE RAMP]. \n",
		 (int) fid, (int) ptr);
    
    new_child = mru;
    fid_array[mru].parent = ptr;
    r_num_open_fids++;
  }
  
  fid_array[ptr].parent = NULL_FID_ID;
  fid_array[ptr].reclaim = reclaim;
  fid_array[ptr].child = new_child;
  fid_array[ptr].index= index;
  
  set_mru(ptr);
  
  return ptr;
}

int fidsvc_remove(fid_id_t fnp)
{
  fid_id_t parent, child;
  int result;
  
  if (fnp == NULL_FID_ID)
    {
      vulpes_log(LOG_ERRORS,"removing a null fid");
      return -1;
    }
  
  VULPES_DEBUG("fidsvc: removing fnp %d\n", (int) fnp);
  
  parent = fid_array[fnp].parent;
  child = fid_array[fnp].child;
  
  if (parent != NULL_FID_ID) {
    fid_array[parent].child = child;
  } else {
    set_mru(child);
  }
  
  if (child != NULL_FID_ID) {
    fid_array[child].parent = parent;
  } else {
    set_lru(parent);
  }
  
  result = reclaim_fid(fnp);
  if (result) {
      vulpes_log(LOG_ERRORS,"reclaim_fid() returned non-zero");
  }
  
  --r_num_open_fids;
  
  return result;
}

void fidsvc_init(void)
{
  fid_id_t ptr;
  
  for (ptr = 0; ptr < MAX_OPEN_FIDS; ptr++) {
    init_fid(ptr);
  }
}

void fidsvc_close(void)
{
  while (fidsvc_num_open() > 0) {
    if (fidsvc_remove(lru) == -1)
      {
	printf("Failed in fidsvc_close...\n");
	exit(1);
      }
  }
}
