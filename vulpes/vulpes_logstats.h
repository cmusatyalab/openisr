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

#ifndef VULPES_LOGSTATS_H_
#define VULPES_LOGSTATS_H_

/* A logstats file consists of a header 
 * followed by hdr.num_records records */

/* The header structure should never change */
/* New versions can insert additional data after
 * this structure */
typedef struct vulpes_logstats_file_hdr_s {
    unsigned long version;
    unsigned long reserved;
    unsigned long long num_records;
} vulpes_logstats_file_hdr_t;

typedef struct vulpes_logstats_ver1_record_s {
    unsigned long long timestamp;	/* top byte is read(=0) or write(=1) */
    unsigned long start_sector;
    unsigned long num_sector;
} vulpes_logstats_ver1_record_t;

#endif
