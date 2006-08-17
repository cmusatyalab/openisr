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

#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include "fauxide.h"
#include "vulpes_stats.h"
#include "vulpes_logstats.h"

#define MAX_LOGFILE_NAME_LENGTH       255

#define _rdtscll(val)     __asm__ __volatile__("rdtsc" : "=A" (val))

typedef struct vulpes_logstats_special_s {
    char logfilename[MAX_LOGFILE_NAME_LENGTH + 1];
    int logfile;
    unsigned long long num_records;
} vulpes_logstats_special_t;

const char *vulpes_logstats_c_version = "$Id: vulpes_logstats.c,v 1.7 2004/11/01 16:18:53 makozuch Exp $";

const unsigned long current_logstats_version = 0x1;



int vulpes_logstats_open(vulpes_stats_t * stats)
{
    vulpes_logstats_file_hdr_t hdr;
    ssize_t bytes;
    vulpes_logstats_special_t *spec;

    spec = stats->special;

    /* open the file */
    spec->logfile =
	open(spec->logfilename, O_RDWR | O_CREAT | O_TRUNC, 0660);
    if (spec->logfile < 0) {
	return errno;
    }

    /* write the header */
    hdr.version = current_logstats_version;
    hdr.reserved = 0;
    hdr.num_records = 0;

    bytes = write(spec->logfile, &hdr, sizeof(hdr));
    if (bytes != sizeof(hdr)) {
	close(spec->logfile);
	return -1;
    }

    return 0;
}

__inline
    int logstats_write_record(int fid, vulpes_cmd_head_t * head, int rw)
{
    vulpes_logstats_ver1_record_t rec;
    ssize_t bytes;

    _rdtscll(rec.timestamp);
    rec.timestamp &= 0x00ffffffffffffffull;
    if (rw)
	rec.timestamp |= 0x0100000000000000ull;;

    rec.start_sector = head->start_sect;
    rec.num_sector = head->num_sect;

    bytes = write(fid, &rec, sizeof(rec));

    return ((bytes == sizeof(rec)) ? 0 : -1);
}

int vulpes_logstats_record_read(vulpes_stats_t * stats,
				vulpes_cmd_head_t * head)
{
    int result;
    vulpes_logstats_special_t *spec;

    spec = (vulpes_logstats_special_t *) stats->special;

    result = logstats_write_record(spec->logfile, head, 0);

    if (!result)
	spec->num_records++;

    return result;
}

int vulpes_logstats_record_write(vulpes_stats_t * stats,
				 vulpes_cmd_head_t * head)
{
    int result;
    vulpes_logstats_special_t *spec;

    spec = (vulpes_logstats_special_t *) stats->special;

    result = logstats_write_record(spec->logfile, head, 1);

    if (!result)
	spec->num_records++;

    return result;
}

int vulpes_logstats_close(vulpes_stats_t * stats)
{
    vulpes_logstats_file_hdr_t hdr;
    int result = 0;
    off_t off;
    vulpes_logstats_special_t *spec;

    spec = stats->special;

    /* rewrite the header with updated num_records */
    off = lseek(spec->logfile, 0, SEEK_SET);
    if (off == 0) {
	ssize_t bytes;
	hdr.version = current_logstats_version;
	hdr.reserved = 0;
	hdr.num_records = spec->num_records;

	bytes = write(spec->logfile, &hdr, sizeof(hdr));
	if (bytes != sizeof(hdr)) {
	    result = -1;
	}
    } else {
	result = -1;
    }


    /* close the file */
    if (spec->logfile >= 0)
	close(spec->logfile);

    /* deallocate memory */
    free(spec);
    stats->special = NULL;

    return result;
}

int initialize_vulpes_logstats(vulpes_stats_t * stats,
			       const char *filename)
{
    vulpes_logstats_special_t *spec;

    spec = malloc(sizeof(vulpes_logstats_special_t));
    if (spec == NULL) {
	return -1;
    }

    stats->special = spec;

    spec->num_records = 0;
    spec->logfile = -1;

    /* form the filename */
    if (strlen(filename) > MAX_LOGFILE_NAME_LENGTH) {
	spec->logfile = -1;
	return -2;
    }
    strcpy(spec->logfilename, filename);

    stats->open = vulpes_logstats_open;
    stats->record_read = vulpes_logstats_record_read;
    stats->record_write = vulpes_logstats_record_write;
    stats->close = vulpes_logstats_close;

    return 0;
}
