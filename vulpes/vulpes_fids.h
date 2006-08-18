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

#ifndef VULPES_FIDS_H_
#define VULPES_FIDS_H_


#define NULL_FID               -1
#define NULL_FID_ID            -1



typedef int fid_t;
typedef int fid_id_t;

typedef int (*fidsvc_reclamation_func_t) (fid_t, void *, int);

void fidsvc_init(void);
void fidsvc_close(void);

int fidsvc_num_open(void);
fid_t fidsvc_get(fid_id_t fnp);
int fidsvc_remove(fid_id_t fnp);
fid_id_t fidsvc_register(int fid, fidsvc_reclamation_func_t reclaim,
			 void *reclaim_data, int index);



#endif
