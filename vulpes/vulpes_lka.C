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

#include <exception>
#include <list>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "vulpes_lka.h"
#include "vulpes_log.h"

/*
 * DEFINES
 */

/* #define DEBUG 1 */

const int MAX_LKA_STRING_LEN=256;
const char *lka_prov_str_hfs_sha1="hfs-sha-1";

/*
 * TYPES
 */

// CLASS: lka_provider
class lka_provider {
protected:
  vulpes_lka_tag_t r_tag_t;
  unsigned r_accesses;
  unsigned r_hits;

public:
  lka_provider(vulpes_lka_tag_t tagt) : r_tag_t(tagt), r_accesses(0), r_hits(0) {}
  virtual ~lka_provider(void) {
    vulpes_log(LOG_STATS,"LOOKASIDE","lookup requests: %u",r_accesses);
    vulpes_log(LOG_STATS,"LOOKASIDE","lookup hits: %u",r_hits);
  }

  inline virtual vulpes_lka_tag_t 
  tag_type(void) const {return r_tag_t;}

  virtual vulpes_lka_return_t
  copy_to_file(vulpes_lka_tag_t tagt, 
	       const void *tag, const char *dst_filename, 
	       char **src_filename) {
    ++r_accesses;
    return VULPES_LKA_RETURN_TAG_NOTFOUND;}
};

// CLASS: hfs_lka_provider
class hfs_lka_provider : public lka_provider {
protected:
  char *pathroot;

  vulpes_lka_return_t
  p_copy_to_file(vulpes_lka_tag_t tagt, 
		 const void *tag, const char *dst_filename, 
		 char **src_filename);
public:
  hfs_lka_provider(vulpes_lka_tag_t tagt, const char *root) throw(std::exception);
  ~hfs_lka_provider(void);

  vulpes_lka_return_t
  copy_to_file(vulpes_lka_tag_t tagt, 
	       const void *tag, const char *dst_filename,
	       char **src_filename);
};


/*
 * LOCAL FUNCTIONS
 */
static off_t get_filesize(int fileno)
{
    struct stat filestat;
    
    /* Get file statistics */
    if (fstat(fileno, &filestat)) {
      return (off_t) 0;
    }

    return filestat.st_size;
}

static vulpes_lka_return_t copy_file(const char *dest, const char *src)
{
  const int rdbuf_size=4096;
  char rdbuf[rdbuf_size];
  int bytes_remaining;
  int bytes_read=0;
  
  // Check the existence of the source file
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

  // Determine the bytes_remaining
  if(( bytes_remaining = get_filesize(inf)) == 0) {
    close(inf);
    return VULPES_LKA_RETURN_ERROR;
  }
  
  // Open the destination for writing
  int outf = open(dest, O_RDWR|O_CREAT|O_EXCL|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
  if(outf == -1) {
    int tmp=errno;
    close(inf);
    return ((tmp==EEXIST) ? VULPES_LKA_RETURN_FILE_EXISTS : VULPES_LKA_RETURN_FILE_OPEN_FAILED);
  }
  
  // Copy the source to the destination
  while((bytes_remaining > 0) 
	&& ((bytes_read=read(inf, rdbuf, rdbuf_size)) > 0)) {
    int to_write = bytes_read;
    int written;
    
    // write bytes_read bytes
    while(to_write > 0) {
      // do the write
      written = write(outf, rdbuf, to_write);
      
      // check the bytes written
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

/*
 * MEMBER FUNCTIONS
 */

hfs_lka_provider::hfs_lka_provider(vulpes_lka_tag_t tagt, const char *root) throw(std::exception)
  : lka_provider(tagt)
{
  int rootlen;

  // check the length of root
  rootlen=strlen(root);
  if((rootlen > MAX_LKA_STRING_LEN) || (rootlen == 0)) {
    throw std::exception();
  }

  // ensure that root is an absolute path
  if(root[0] != '/') {
    throw std::exception();
  }

  // allocate the pathroot string
  pathroot=new char[rootlen+1];

  // copy the string
  strncpy(pathroot, root, rootlen);
  pathroot[rootlen]='\0';
}

hfs_lka_provider::~hfs_lka_provider(void)
{
  delete[] pathroot;
}

inline vulpes_lka_return_t
hfs_lka_provider::p_copy_to_file(vulpes_lka_tag_t tagt, 
				 const void *tag, const char *dst_filename,
				 char **src_filename)
{
  vulpes_lka_return_t result = VULPES_LKA_RETURN_ERROR;
  char buffer[2*MAX_LKA_STRING_LEN+1];
  char *cptr;

  // Check the type
  if(tagt != tag_type())
    return VULPES_LKA_RETURN_TAG_NOTFOUND;

  // Form the source file name
  // Check the source file name bound
  switch(tagt) {
  case VULPES_LKA_TAG_SHA1:
    {
      unsigned char *sha1value = (unsigned char*)tag;

      // A 20-byte SHA-1 tag will become a 40-byte ASCII name + up to 3 slashes
      if(sizeof(pathroot) + 40 + 3 + 1 > sizeof(buffer)) return VULPES_LKA_RETURN_ERROR;
      // Copy the root
      strncpy(buffer, pathroot, MAX_LKA_STRING_LEN);
      cptr=buffer+strlen(buffer);
      // Append a slash
      *cptr++='/';
      // Convert the tag to a filename
      for(int i=0; i<20; i++) {
	int bytes;
	bytes = sprintf(cptr, "%02X", sha1value[i]);
	if(bytes >= 0) cptr+=bytes;
	else return VULPES_LKA_RETURN_ERROR;
      }
      // Add a null for safety
      *cptr++='\0';
    }
    break;
  default:
    return VULPES_LKA_RETURN_ERROR;
  }

  // Copy the source to the destination
  result = copy_file(dst_filename, buffer);

  // Copy the source file name
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

vulpes_lka_return_t
hfs_lka_provider::copy_to_file(vulpes_lka_tag_t tagt, 
			       const void *tag, const char *dst_filename,
			       char **src_filename)
{
  vulpes_lka_return_t result = p_copy_to_file(tagt, tag, dst_filename, 
					      src_filename);

  ++r_accesses;
  if(result == VULPES_LKA_RETURN_SUCCESS) 
    ++r_hits;

  return result;
}


/*
 * GLOBALS
 */
typedef std::list<lka_provider*> lka_provider_list_t;

/*
 * EXPORTED FUNCTIONS
 */

/* Initialize the lka service */
vulpes_lka_svc_t
vulpes_lka_open(void)
{
  lka_provider_list_t *provlist;

  provlist=new lka_provider_list_t();

  return provlist;
}

/* Close the lka service */
vulpes_lka_return_t
vulpes_lka_close(vulpes_lka_svc_t svc)
{
  lka_provider_list_t *provlist;
  lka_provider *tmp;
  lka_provider_list_t::reverse_iterator riter;

  if(svc == NULL) return VULPES_LKA_RETURN_ERROR;

  provlist=(lka_provider_list_t *)svc;

  for(riter=provlist->rbegin(); riter!=provlist->rend(); riter++) {
    tmp = *riter;
    provlist->pop_back();
    delete tmp;
  }

  delete provlist;

  return VULPES_LKA_RETURN_SUCCESS;
}

/* Add an LKA database to the service */
vulpes_lka_return_t
vulpes_lka_add(vulpes_lka_svc_t svc, const char *lka_identifier)
{
  lka_provider_list_t *provlist;
  char buffer[MAX_LKA_STRING_LEN+1];
  int len;
  lka_provider *tmp;
  char *cptr;

  if(svc == NULL) return VULPES_LKA_RETURN_ERROR;

  provlist=(lka_provider_list_t *)svc;

  // check the length of lka_identifier
  len=strlen(lka_identifier);
  if((len > MAX_LKA_STRING_LEN) || (len == 0)) {
    return VULPES_LKA_RETURN_ERROR;
  }

  // copy the lka_identifier
  strncpy(buffer, lka_identifier, MAX_LKA_STRING_LEN+1);

  // Find the ':' separator
  cptr=index(buffer, ':');
  if(cptr==NULL) return VULPES_LKA_RETURN_ERROR;
  // Replace the ':' with a NULL
  *cptr='\0';
  // buffer is now a type-string and ++cptr is the rootname
  ++cptr;

  // Create a new provider, tmp, that can be added to the provider_list
  try {
    // "switch" on the type-string in buffer
    if(strncmp(buffer, lka_prov_str_hfs_sha1, MAX_LKA_STRING_LEN)==0) {
      tmp=new hfs_lka_provider(VULPES_LKA_TAG_SHA1, cptr);
/*
    } else if(strncmp(buffer, lka_prov_str_hdbfs_sha1, MAX_LKA_STRING_LEN)==0) {
      tmp=new hdbfs_lka_provider(VULPES_LKA_TAG_SHA1, cptr);
*/
    } else {
      return VULPES_LKA_RETURN_ERROR;
    }
  } catch(std::exception &e) {
      return VULPES_LKA_RETURN_ERROR;
  }

  // If we got here, we have a tmp provider to be inserted
  provlist->push_back(tmp);

  return VULPES_LKA_RETURN_SUCCESS;
}

/* Copy a file matching the tag to the dst_filename */
vulpes_lka_return_t
vulpes_lka_copy(vulpes_lka_svc_t svc, vulpes_lka_tag_t tag_type, 
		const void *tag, const char *dst_filename,
		char **src_filename)
{
  lka_provider_list_t *provlist;
  lka_provider_list_t::iterator iter;

  if(svc == NULL) return VULPES_LKA_RETURN_ERROR;

  provlist=(lka_provider_list_t *)svc;

  for(iter=provlist->begin(); iter!=provlist->end(); iter++)
    if((*iter)->copy_to_file(tag_type, tag, dst_filename, src_filename)
       == VULPES_LKA_RETURN_SUCCESS)
      return VULPES_LKA_RETURN_SUCCESS;

  return VULPES_LKA_RETURN_ERROR;
}

