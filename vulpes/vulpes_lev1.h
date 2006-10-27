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

#ifndef VULPES_LEV1_H_
#define VULPES_LEV1_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "fauxide.h"
#include "vulpes_map.h"
#include "vulpes_fids.h"

/* DEFINES */
#define MAX_INDEX_NAME_LENGTH 256
#define MAX_CHUNK_NAME_LENGTH 512
#define MAX_DIRLENGTH 256
#define NULL_FID -1

#endif
