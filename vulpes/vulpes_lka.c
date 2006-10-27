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

#include "vulpes_lka.h"
#include "vulpes_log.h"
#include "vulpes_util.h"

/*
 * DEFINES
 */

/* #define DEBUG 1 */

const int MAX_LKA_STRING_LEN=256;

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
static vulpes_lka_return_t copy_file(const char *dest, const char *src)
{
  const int rdbuf_size=4096;
  char rdbuf[rdbuf_size];
  int bytes_remaining;
  int bytes_read=0;
  
  /* Check the existence of the source file */
  int inf=open(src, O_RDONLY);
  if(inf == -1) {
#ifdef DEBUG
    vulpes_log(LOG_TRANSPORT,"LKA_COPY_FILE","lka file not found: %s",src);
#endif
    return VULPES_LKA_RETURN_TAG_NOTFOUND;
  } else {
#ifdef DEBUG
    vulpes_log(LOG_TRANSPORT,"LKA_COPY_FILE","lka file found: %s",src);
#endif
  }

  /* Determine the bytes_remaining */
  if(( bytes_remaining = get_filesize(inf)) == 0) {
    close(inf);
    return VULPES_LKA_RETURN_ERROR;
  }
  
  /* Open the destination for writing */
  int outf = open(dest, O_RDWR|O_CREAT|O_EXCL|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
  if(outf == -1) {
    int tmp=errno;
    close(inf);
    return ((tmp==EEXIST) ? VULPES_LKA_RETURN_FILE_EXISTS : VULPES_LKA_RETURN_FILE_OPEN_FAILED);
  }
  
  /* Copy the source to the destination */
  while((bytes_remaining > 0) 
	&& ((bytes_read=read(inf, rdbuf, rdbuf_size)) > 0)) {
    int to_write = bytes_read;
    int written;
    
    /* write bytes_read bytes */
    while(to_write > 0) {
      /* do the write */
      written = write(outf, rdbuf, to_write);
      
      /* check the bytes written */
      if(written > 0) {
	to_write -= written;
      } else {
	close(inf);
	close(outf);
	return VULPES_LKA_RETURN_FILE_WRITE_FAILED;
      }
    }
    
    bytes_remaining -= bytes_read;
  }

  close(outf);
  close(inf);

  return ((bytes_remaining==0) ? VULPES_LKA_RETURN_SUCCESS : VULPES_LKA_RETURN_ERROR);
}

static vulpes_lka_return_t
copy_to_file(struct lka_provider *prov, const void *tag,
             const char *dst_filename, char **src_filename)
{
  vulpes_lka_return_t result = VULPES_LKA_RETURN_ERROR;
  char buffer[2*MAX_LKA_STRING_LEN+1];
  char *cptr;
  int i;

  /* Form the source file name.  Check the source file name bound. */
  switch(prov->tag_type) {
  case VULPES_LKA_TAG_SHA1:
    {
      unsigned char *sha1value = (unsigned char*)tag;

      /* A 20-byte SHA-1 tag will become a 40-byte ASCII name + up to 3 slashes */
      if(strlen(prov->root) + 40 + 3 + 1 > sizeof(buffer)) return VULPES_LKA_RETURN_ERROR;
      /* Copy the root */
      strncpy(buffer, prov->root, MAX_LKA_STRING_LEN);
      cptr=buffer+strlen(buffer);
      /* Append a slash */
      *cptr++='/';
      /* Convert the tag to a filename */
      for(i=0; i<20; i++) {
	int bytes;
	bytes = sprintf(cptr, "%02X", sha1value[i]);
	if(bytes >= 0) cptr+=bytes;
	else return VULPES_LKA_RETURN_ERROR;
      }
      /* Add a null for safety */
      *cptr++='\0';
    }
    break;
  default:
    return VULPES_LKA_RETURN_ERROR;
  }

  /* Copy the source to the destination */
  result = copy_file(dst_filename, buffer);

  /* Copy the source file name */
  if((result==VULPES_LKA_RETURN_SUCCESS) && (src_filename!=NULL)) {
    char *srcbuf;
    int srcbuf_size;

    srcbuf_size=strlen(buffer)+1;
    srcbuf=(char*)malloc(srcbuf_size);
    if(srcbuf != NULL) {
      strncpy(srcbuf, buffer, srcbuf_size);
      srcbuf[srcbuf_size-1]='\0';
    }
    *src_filename = srcbuf;
  }

  return result;
}

/*
 * EXPORTED FUNCTIONS
 */

/* Initialize the lka service */
vulpes_lka_svc_t
vulpes_lka_open(void)
{
  struct lka_svc *svc=malloc(sizeof(*svc));
  if (svc == NULL)
    return NULL;
  memset(svc, 0, sizeof(*svc));
  return svc;
}

/* Close the lka service */
vulpes_lka_return_t
vulpes_lka_close(vulpes_lka_svc_t svc)
{
  struct lka_provider *prov;
  struct lka_provider *tmp;

  if(svc == NULL) return VULPES_LKA_RETURN_ERROR;
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
  return VULPES_LKA_RETURN_SUCCESS;
}

/* Add an LKA database to the service */
vulpes_lka_return_t
vulpes_lka_add(vulpes_lka_svc_t svc, lka_type_t type, vulpes_lka_tag_t tag_type,
               const char *root)
{
  int len;
  struct lka_provider *cur;
  struct lka_provider *tmp;

  if(svc == NULL) return VULPES_LKA_RETURN_ERROR;

  /* check the length of root */
  len=strlen(root);
  if((len > MAX_LKA_STRING_LEN) || (len == 0)) {
    return VULPES_LKA_RETURN_ERROR;
  }
  
  switch (type) {
  case LKA_HFS:
    /* ensure that root is an absolute path */
    if(root[0] != '/') return VULPES_LKA_RETURN_ERROR;
    break;
  default:
    return VULPES_LKA_RETURN_ERROR;
  }

  tmp=malloc(sizeof(*tmp));
  if (tmp == NULL) return VULPES_LKA_RETURN_ERROR;
  memset(tmp, 0, sizeof(*tmp));
  tmp->root=strdup(root);
  if (tmp->root == NULL) {
    free(tmp);
    return VULPES_LKA_RETURN_ERROR;
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

  return VULPES_LKA_RETURN_SUCCESS;
}

/* Copy a file matching the tag to the dst_filename */
vulpes_lka_return_t
vulpes_lka_copy(vulpes_lka_svc_t svc, vulpes_lka_tag_t tag_type, 
		const void *tag, const char *dst_filename,
		char **src_filename)
{
  struct lka_provider *prov;

  if(svc == NULL) return VULPES_LKA_RETURN_ERROR;
  prov=svc->next;
  
  while (prov != NULL) {
    if (prov->tag_type == tag_type) {
      prov->r_accesses++;
      if (copy_to_file(prov, tag, dst_filename, src_filename)
	  == VULPES_LKA_RETURN_SUCCESS) {
        prov->r_hits++;
	return VULPES_LKA_RETURN_SUCCESS;
      }
    }
    prov=prov->next;
  }

  return VULPES_LKA_RETURN_ERROR;
}

