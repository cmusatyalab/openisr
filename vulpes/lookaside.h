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


#ifndef VULPES_LKA_H_
#define VULPES_LKA_H_

#include "vulpes.h"

/* Type to relay the type of LKA tags */
enum lka_tag {
  LKA_TAG_UNKNOWN=0,
  LKA_TAG_SHA1,
};

enum lka_type {
  LKA_HFS,
};

/* Initialize the lka service */
vulpes_err_t vulpes_lka_open(void);

/* Close the lka service */
vulpes_err_t vulpes_lka_close(void);

/* Add an LKA database to the service */
vulpes_err_t vulpes_lka_add(enum lka_type type, enum lka_tag tag_type,
                            const char *root);

/* Read in a file matching the tag to the given buffer */
/* If src_filename is not NULL, *src_filename will point to 
   a malloc'ed array which contains the name of the source file.
   NOTE: The calling function should call free() on *src_filename. */
vulpes_err_t vulpes_lka_lookup(enum lka_tag tag_type, const void *tag,
                               void *buf, int *bufsize, char **src_filename);

#endif /* VULPES_LKA_H_ */
