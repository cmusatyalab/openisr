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


#ifndef VULPES_LKA_H_
#define VULPES_LKA_H_

/* LKA service type */
typedef struct lka_svc *vulpes_lka_svc_t;
  
/* Type to relay the type of LKA tags */
typedef int vulpes_lka_tag_t;
  
#define VULPES_LKA_TAG_UNKNOWN 0
#define VULPES_LKA_TAG_SHA1    1
  
/* Return type for LKA functions */
typedef int vulpes_lka_return_t;
  
#define VULPES_LKA_RETURN_SUCCESS      0
#define VULPES_LKA_RETURN_TAG_NOTFOUND 1
#define VULPES_LKA_RETURN_FILE_EXISTS  2
#define VULPES_LKA_RETURN_FILE_OPEN_FAILED 3
#define VULPES_LKA_RETURN_FILE_CLOSE_FAILED 4
#define VULPES_LKA_RETURN_FILE_WRITE_FAILED 5
#define VULPES_LKA_RETURN_ERROR        127

typedef int lka_type_t;

#define LKA_HFS 0

/* Initialize the lka service */
vulpes_lka_svc_t
vulpes_lka_open(void);
  
/* Close the lka service */
vulpes_lka_return_t
vulpes_lka_close(vulpes_lka_svc_t svc);

/* Add an LKA database to the service */
vulpes_lka_return_t
vulpes_lka_add(vulpes_lka_svc_t svc, lka_type_t type, vulpes_lka_tag_t tag_type,
               const char *root);

/* Copy a file matching the tag to the dst_filename */
/* If src_filename is not NULL, *src_filename will point to 
   a malloc'ed array which contains the name of the source file.
   NOTE: The calling function should call free() on *src_filename. */
vulpes_lka_return_t
vulpes_lka_copy(vulpes_lka_svc_t svc, vulpes_lka_tag_t tag_type, 
		const void *tag, const char *dst_filename,
		char **src_filename);

#endif /* VULPES_LKA_H_ */
