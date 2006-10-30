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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "vulpes.h"
#include "vulpes_lka.h"
#include "vulpes_log.h"
#include "vulpes_util.h"

/*
 * DEFINES
 */

#undef DEBUG
#define MAX_LKA_STRING_LEN 256

/*
 * TYPES
 */

/* XXX overly simple-minded linked list */
struct lka_svc {
  struct lka_provider *next;
};

struct lka_provider {
  struct lka_provider *next;
  char *root;
  lka_type_t type;
  vulpes_lka_tag_t tag_type;
  unsigned r_accesses;
  unsigned r_hits;
};

/*
 * LOCAL FUNCTIONS
 */
static vulpes_err_t file_lookup(struct lka_provider *prov, const void *tag,
             void *buf, int *bufsize, char **src_filename)
{
  vulpes_err_t err;
  char name[2*MAX_LKA_STRING_LEN+1];
  char *cptr;
  int i;
  int fd;

  /* Form the source file name.  Check the source file name bound. */
  switch(prov->tag_type) {
  case VULPES_LKA_TAG_SHA1:
    {
      unsigned char *sha1value = (unsigned char*)tag;

      /* A 20-byte SHA-1 tag will become a 40-byte ASCII name + up to 3 slashes */
      if(strlen(prov->root) + 40 + 3 + 1 > sizeof(name)) return VULPES_INVALID;
      /* Copy the root */
      strncpy(name, prov->root, MAX_LKA_STRING_LEN);
      cptr=name+strlen(name);
      /* Append a slash */
      *cptr++='/';
      /* Convert the tag to a filename */
      for(i=0; i<20; i++) {
	cptr += sprintf(cptr, "%02X", sha1value[i]);
      }
      /* Add a null for safety */
      *cptr++='\0';
    }
    break;
  default:
    return VULPES_INVALID;
  }

  /* Read in the source file */
  fd=open(name, O_RDONLY);
  if(fd == -1) {
    vulpes_debug(LOG_TRANSPORT,"LKA_COPY_FILE","lka file not found: %s",src);
    return VULPES_NOTFOUND;
  } else {
    vulpes_debug(LOG_TRANSPORT,"LKA_COPY_FILE","lka file found: %s",src);
  }
  err=read_file(fd, buf, bufsize);
  close(fd);
  if (err) return err;
  
  /* Copy the source file name */
  if(src_filename != NULL) {
    char *srcbuf;
    int srcbuf_size;

    srcbuf_size=strlen(name)+1;
    srcbuf=malloc(srcbuf_size);
    if(srcbuf != NULL) {
      strncpy(srcbuf, name, srcbuf_size);
      srcbuf[srcbuf_size-1]='\0';
    }
    *src_filename = srcbuf;
  }
  return VULPES_SUCCESS;
}

/*
 * EXPORTED FUNCTIONS
 */

/* Initialize the lka service */
vulpes_lka_svc_t vulpes_lka_open(void)
{
  struct lka_svc *svc=malloc(sizeof(*svc));
  if (svc == NULL)
    return NULL;
  memset(svc, 0, sizeof(*svc));
  return svc;
}

/* Close the lka service */
vulpes_err_t vulpes_lka_close(vulpes_lka_svc_t svc)
{
  struct lka_provider *prov;
  struct lka_provider *tmp;

  if(svc == NULL) return VULPES_INVALID;
  prov=svc->next;
  while (prov != NULL) {
    vulpes_log(LOG_STATS,"LOOKASIDE","lookup requests: %u",prov->r_accesses);
    vulpes_log(LOG_STATS,"LOOKASIDE","lookup hits: %u",prov->r_hits);
    tmp=prov;
    prov=prov->next;
    free(tmp->root);
    free(tmp);
  }
  free(svc);
  return VULPES_SUCCESS;
}

/* Add an LKA database to the service */
vulpes_err_t vulpes_lka_add(vulpes_lka_svc_t svc, lka_type_t type,
                            vulpes_lka_tag_t tag_type, const char *root)
{
  int len;
  struct lka_provider *cur;
  struct lka_provider *tmp;

  if(svc == NULL) return VULPES_INVALID;

  /* check the length of root */
  len=strlen(root);
  if((len > MAX_LKA_STRING_LEN) || (len == 0)) {
    return VULPES_INVALID;
  }
  
  switch (type) {
  case LKA_HFS:
    /* ensure that root is an absolute path */
    if(root[0] != '/') return VULPES_INVALID;
    break;
  default:
    return VULPES_INVALID;
  }

  tmp=malloc(sizeof(*tmp));
  if (tmp == NULL) return VULPES_NOMEM;
  memset(tmp, 0, sizeof(*tmp));
  tmp->root=strdup(root);
  if (tmp->root == NULL) {
    free(tmp);
    return VULPES_NOMEM;
  }
  tmp->type=type;
  tmp->tag_type=tag_type;
  
  if (svc->next == NULL) {
    svc->next=tmp;
  } else {
    cur=svc->next;
    while (cur->next != NULL)
      cur=cur->next;
    cur->next=tmp;
  }

  return VULPES_SUCCESS;
}

/* Copy a file matching the tag to the dst_filename */
vulpes_err_t vulpes_lka_lookup(vulpes_lka_svc_t svc, vulpes_lka_tag_t tag_type, 
		const void *tag, void *buf, int *bufsize,
		char **src_filename)
{
  struct lka_provider *prov;

  if(svc == NULL) return VULPES_INVALID;
  prov=svc->next;
  
  while (prov != NULL) {
    if (prov->tag_type == tag_type) {
      prov->r_accesses++;
      if (file_lookup(prov, tag, buf, bufsize, src_filename)
	  == VULPES_SUCCESS) {
        prov->r_hits++;
	return VULPES_SUCCESS;
      }
    }
    prov=prov->next;
  }

  return VULPES_NOTFOUND;
}

