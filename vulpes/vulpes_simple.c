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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <linux/hdreg.h>

#include "fauxide.h"
#include "vulpes_map.h"

typedef int simple_mapping_special_t;

const char *vulpes_simple_c_version = "$Id: vulpes_simple.c,v 1.7 2004/11/01 16:18:53 makozuch Exp $";

static inline int long_seek(int fid, unsigned long long lloffset)
{
    const off_t max_offset = 0x7fffffff;

    off_t off, tmp_off;

    if (lloffset > max_offset) {
	printf("ERROR: long_seek() lloffset = %llu\n", lloffset);
	return (-1);
    }

    off = (off_t) lloffset;
    tmp_off = lseek(fid, off, SEEK_SET);
    if (tmp_off != off) {
	printf("ERROR: long_seek() off=%ld tmp_off=%ld\n",
	       (long) off, (long) tmp_off);
	return (-1);
    }

    return 0;
}

vulpes_volsize_t simple_file_volsize_func(const vulpes_mapping_t * map_ptr)
{
    int fileno;
    struct stat filestat;
    off_t size_bytes;
    vulpes_volsize_t volsize;	/* sectors */

    fileno = *((int *) map_ptr->special);

    /* Get file statistics */
    if (fstat(fileno, &filestat)) {
	printf("ERROR: unable to fstat().\n");
	return (off_t) 0;
    }

    size_bytes = filestat.st_size;

    volsize = ((size_bytes / FAUXIDE_HARDSECT_SIZE)
	       + (size_bytes % FAUXIDE_HARDSECT_SIZE ? 1 : 0));

    return volsize;
}

vulpes_volsize_t simple_disk_volsize_func(const vulpes_mapping_t * map_ptr)
{
    struct hd_big_geometry geo;
    int result;
    int dev;
    vulpes_volsize_t volsize;	/* sectors */

    dev = *((int *) map_ptr->special);

    bzero(&geo, sizeof(geo));

    result = ioctl(dev, HDIO_GETGEO_BIG, &geo);
    if (result) {
	printf("ERROR: getgeo_big returned %d.\n\n", result);
	return -1;
    }

    volsize =
	(vulpes_volsize_t) geo.cylinders * (vulpes_volsize_t) geo.heads *
	(vulpes_volsize_t) geo.sectors;

    return volsize;
}

int simple_open_func(vulpes_mapping_t * map_ptr)
{
    int result = 0;
    int fid;

    fid = open(map_ptr->file_name, O_RDWR);
    if (fid < 0) {
	printf("ERROR: unable to open %s.\n", map_ptr->file_name);
	return -1;
    }

    *((int *) (map_ptr->special)) = fid;

    return result;
}

int simple_close_func(vulpes_mapping_t * map_ptr)
{
    int result = 0;

    if (map_ptr->special != NULL) {
	close(*((int *) map_ptr->special));
	free(map_ptr->special);
	map_ptr->special = NULL;
    }

    return result;
}

int simple_read_func(const vulpes_mapping_t * map_ptr,
		     vulpes_cmdblk_t * cmdblk)
{
    unsigned long long start;
    ssize_t bytes, tmp_size;
    int result = 0;
    int fid;

    fid = *((int *) map_ptr->special);

    start =
	(unsigned long long) cmdblk->head.start_sect *
	FAUXIDE_HARDSECT_SIZE;

    result = long_seek(fid, start);
    if (result) {
	printf("ERROR: seeking %s to sector %lu (byte %llu)\n",
	       map_ptr->file_name, (unsigned long) cmdblk->head.start_sect,
	       (unsigned long long) start);
    }

    bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
    tmp_size = read(fid, cmdblk->buffer, bytes);
    if (tmp_size != bytes) {
	printf("ERROR: reading %s. %llu bytes\n", map_ptr->file_name,
	       (unsigned long long) bytes);
	result = -1;
    }

    return result;
}

int simple_write_func(const vulpes_mapping_t * map_ptr,
		      const vulpes_cmdblk_t * cmdblk)
{
    unsigned long long start;
    ssize_t bytes, tmp_size;
    int result = 0;
    int fid;

    fid = *((int *) map_ptr->special);

    start =
	(unsigned long long) cmdblk->head.start_sect *
	FAUXIDE_HARDSECT_SIZE;

    result = long_seek(fid, start);
    if (result) {
	printf("ERROR: seeking %s to sector %lu (byte %llu)\n",
	       map_ptr->file_name, (unsigned long) cmdblk->head.start_sect,
	       (unsigned long long) start);
    }

    bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
    tmp_size = write(fid, cmdblk->buffer, bytes);
    if (tmp_size != bytes) {
	printf("ERROR: writing %s. %llu bytes\n",
	       map_ptr->file_name, (unsigned long long) bytes);
	result = -1;
    }

    return result;
}


int initialize_simple_mapping(vulpes_mapping_t * map_ptr)
{
    if (map_ptr->type == SIMPLE_FILE_MAPPING) {
	map_ptr->volsize_func = simple_file_volsize_func;
    } else if (map_ptr->type == SIMPLE_DISK_MAPPING) {
	map_ptr->volsize_func = simple_disk_volsize_func;
    } else {
	return -1;
    }

    map_ptr->special = malloc(sizeof(simple_mapping_special_t));
    if (map_ptr->special == NULL) {
	return -1;
    }

    map_ptr->open_func = simple_open_func;
    map_ptr->read_func = simple_read_func;
    map_ptr->write_func = simple_write_func;
    map_ptr->close_func = simple_close_func;

    return 0;
}
