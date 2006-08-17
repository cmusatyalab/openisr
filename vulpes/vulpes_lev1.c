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
#include <errno.h>
#include <zlib.h>

#include "fauxide.h"
#include "vulpes_map.h"
#include "vulpes_fids.h"
#include "vulpes_lev1_encryption.h"
#include "vulpes_lev1.h"
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include "vulpes_log.h"
#include <sys/time.h>

/* #define DEBUG */
/* #define VERBOSE_DEBUG */
#ifdef VERBOSE_DEBUG
#define VULPES_DEBUG(fmt, args...)     printf("[vulpes] " fmt, ## args)
#else
#define VULPES_DEBUG(fmt, args...)     ;
#endif

const unsigned CHUNK_STATUS_ACCESSED = 0x0001;	/* This chunk has been accessed this session */
const unsigned CHUNK_STATUS_DIRTY = 0x0002;	/* This chunk has been written this session */
const unsigned CHUNK_STATUS_RW = 0x0200;	/* This chunk was last opened read/write */
const unsigned CHUNK_STATUS_LKA_COPY = 0x4000;	/* This chunk data was fetched from the LKA cache */
const unsigned CHUNK_STATUS_SHADOW_PRESENT = 0x8000;	/* This chunk is present in the local cache */

const char *vulpes_lev1_c_version = "$Id: vulpes_lev1.c,v 1.29 2005/08/24 18:48:07 jaharkes Exp $";

/* LOCALS */
static int enableEncryption;

typedef struct chunk_data_s {
  fid_id_t fnp;		/* NULL_FID_ID if not currently open */
  unsigned status;
  unsigned char *buffer;	/* File is now always read into memory */
} chunk_data_t;

struct lev1_mapping_special_s {
  char index_name[MAX_INDEX_NAME_LENGTH];
  unsigned version;
  unsigned chunksize_bytes;
  unsigned chunksperdir;
  unsigned numchunks;
  unsigned numdirs;
  vulpes_volsize_t volsize;	/* sectors */
  unsigned chunksize;		/* sectors */
  int verbose;
  int compressed_chunks;
  
  keyring_t *keyring;
  
  int shadow;
  chunk_data_t **cd;		/* cd[][] */
};
typedef  struct lev1_mapping_special_s lev1_mapping_special_t;

const char *lev1_index_name = "index.lev1";
static unsigned writes_before_read = 0;

static void get_dir_chunk(const lev1_mapping_special_t * spec,
			  unsigned sect_num, unsigned *dir, unsigned *chunk);
static void get_dir_chunk_from_chunk_num(const lev1_mapping_special_t * spec,
					 unsigned chunk_num, unsigned *dir, unsigned *chunk);
static unsigned get_chunk_number(const lev1_mapping_special_t * spec,
				 unsigned sect_num);
static int form_chunk_file_name(char *buffer, int bufsize,
				const char *rootname,
				unsigned dir, unsigned chunk,
				const char *suffix, const vulpes_mapping_t* map_ptr);


/* various functions to enable HTTP transport via the CURL library */
typedef struct curl_buffer_s {
  char *buf;
  size_t size;
  size_t maxsize;
} curl_buffer_t;
static CURL *curl_handle;
static curl_buffer_t* curl_buffer;
static char curl_error_buffer[CURL_ERROR_SIZE];

static void destroy_curl(void)
{
  curl_easy_cleanup(curl_handle);
  free(curl_buffer->buf);
  free(curl_buffer);
}

/* the curl writeback function */
/* TODO: should check for buffer overflows and report it back somehow */
size_t curl_write_callback_function(char* curlbuf, size_t size, size_t nitems,
				    void *myPtr)
{
  size_t totSize = size*nitems;
  curl_buffer_t* ptr = (curl_buffer_t *)myPtr;
  
  char* nxtWrite= &(ptr->buf[ptr->size]);
  if (totSize > ptr->maxsize - ptr->size)
      totSize = ptr->maxsize - ptr->size;
  memcpy(nxtWrite,curlbuf,totSize);
  ptr->size += totSize;
  
  return totSize;
}

/* warning: not thread-safe(same as rest of vulpes!) */
static __inline
void init_curl(const vulpes_mapping_t *map_ptr)
{
  /*if (doneOnce)
    return;
    else
    doneOnce++;
    
    curl_global_init(CURL_GLOBAL_ALL);*/
  
  /* init the curl session */
  curl_handle = curl_easy_init();
  
  /* announce vulpes as "the agent"*/
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "vulpes-agent/1.0");
  
  /* disable use of signals - dont want bad interactions with vulpes */
  curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
  
  /* disable internal progress meter if any */
  curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1);
  
  /* curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1);*/
  
  /* dont die when you have low speed networks */
  curl_easy_setopt(curl_handle,CURLOPT_CONNECTTIMEOUT, 60);
  curl_easy_setopt(curl_handle,CURLOPT_TIMEOUT, 60);
  
  /* set up the error buffer to trap errors */
  memset(curl_error_buffer, 0, CURL_ERROR_SIZE);
  curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, curl_error_buffer);
  
  if (map_ptr->outgoing_interface)
    curl_easy_setopt(curl_handle, CURLOPT_INTERFACE, map_ptr->outgoing_interface);
  
  /* set up proxies if any */
  if ( (map_ptr->proxy_name) && (map_ptr->proxy_port))
    {
      curl_easy_setopt(curl_handle, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
      curl_easy_setopt(curl_handle, CURLOPT_PROXY, (map_ptr->proxy_name));
      curl_easy_setopt(curl_handle, CURLOPT_PROXYPORT, map_ptr->proxy_port);
    }
  
  /* disable Nagle's algorithm 
     curl_easy_setopt(curl_handle, CURLOPT_TCP_NODELAY, 1);*/
  
  lev1_mapping_special_t *spec= (lev1_mapping_special_t *) map_ptr->special;
  curl_buffer = (curl_buffer_t*) malloc(sizeof(curl_buffer_t));
  curl_buffer->size=0;
  curl_buffer->maxsize=1.002*spec->chunksize_bytes+20;
  curl_buffer->buf = malloc (curl_buffer->maxsize);
  
  /* register my write function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_write_callback_function);
  
  /* pass the curl_buffer as the place to write to in callback function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)curl_buffer);
  
  /* atexit(destroy_curl);*/
}

/* AUXILLIARY FUNCTIONS */
static __inline int cdp_is_rw(chunk_data_t * cdp)
{
  return ((cdp->status & CHUNK_STATUS_RW) == CHUNK_STATUS_RW);
}

static __inline int cdp_is_accessed(chunk_data_t * cdp)
{
  return ((cdp->status & CHUNK_STATUS_ACCESSED) ==
	  CHUNK_STATUS_ACCESSED);
}

static __inline int cdp_is_dirty(chunk_data_t * cdp)
{
  int result;

  result = ((cdp->status & CHUNK_STATUS_DIRTY) == CHUNK_STATUS_DIRTY);

#ifdef DEBUG
  if(result && !cdp_is_rw(cdp)) {
    char s_value[12];
    sprintf(s_value,"%#x", cdp->status);
    vulpes_log(LOG_ERRORS,"CDP_IS_DIRTY()",NULL,NULL, "cdp is dirty but not rw", s_value);
  }
  if(result && !cdp_is_accessed(cdp)) {
    char s_value[12];
    sprintf(s_value,"%#x", cdp->status);
    vulpes_log(LOG_ERRORS,"CDP_IS_DIRTY()",NULL,NULL, "cdp is dirty but not accessed", s_value);
  }
#endif

  return result;
}

static __inline void mark_cdp_accessed(chunk_data_t * cdp)
{
  cdp->status |= CHUNK_STATUS_ACCESSED;
}

static __inline void mark_cdp_dirty(chunk_data_t * cdp)
{
  cdp->status |= CHUNK_STATUS_DIRTY;
}

static __inline void mark_cdp_readwrite(chunk_data_t * cdp)
{
  cdp->status |= CHUNK_STATUS_RW;
}

static __inline void mark_cdp_readonly(chunk_data_t * cdp)
{
  cdp->status &= ~CHUNK_STATUS_RW;
}

static __inline int cdp_shadow_present(chunk_data_t * cdp)
{
  return ((cdp->status & CHUNK_STATUS_SHADOW_PRESENT) ==
	  CHUNK_STATUS_SHADOW_PRESENT);
}

static __inline int cdp_lka_copy(chunk_data_t * cdp)
{
  return ((cdp->status & CHUNK_STATUS_LKA_COPY) ==
	  CHUNK_STATUS_LKA_COPY);
}

static __inline void mark_cdp_lka_copy(chunk_data_t * cdp)
{
  cdp->status |= CHUNK_STATUS_LKA_COPY;
}

static __inline void mark_cdp_not_lka_copy(chunk_data_t * cdp)
{
  cdp->status &= ~CHUNK_STATUS_LKA_COPY;
}

static __inline
unsigned get_chunk_number(const lev1_mapping_special_t * spec,
			  unsigned sect_num)
{
  return sect_num / spec->chunksize;
}

static __inline
void get_dir_chunk_from_chunk_num(const lev1_mapping_special_t * spec,
				  unsigned chunk_num, unsigned *dir, unsigned *chunk)
{
  *chunk = chunk_num % spec->chunksperdir;
  *dir = chunk_num / spec->chunksperdir;
}


static __inline
chunk_data_t *get_cdp_from_chunk_num(const lev1_mapping_special_t * spec,
					  unsigned chunk_num)
{
  unsigned dir, chunk;
  chunk_data_t *cdp;

  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);
  
  cdp = &(spec->cd[dir][chunk]);

  return cdp;
}
  

static __inline
void get_dir_chunk(const lev1_mapping_special_t * spec,
		   unsigned sect_num, unsigned *dir, unsigned *chunk)
{
  unsigned chunk_num;		/* absolute chunk numbers */
  
  chunk_num = get_chunk_number(spec, sect_num);
  
  get_dir_chunk_from_chunk_num(spec, chunk_num, dir, chunk);
}

static __inline void mark_cdp_shadow_present(chunk_data_t * cdp)
{
  cdp->status |= CHUNK_STATUS_SHADOW_PRESENT;
}

static int form_index_name(const char *dirname,
			   lev1_mapping_special_t * spec)
{
  size_t len_dir, len_name;
  int add_slash = 0;
  
  /* check lengths */
  len_dir = strlen(dirname);
  if (dirname[len_dir - 1] != '/') {
    add_slash = 1;
  }
  len_name = strlen(lev1_index_name);
  if (len_dir + len_name + add_slash + 1 > MAX_INDEX_NAME_LENGTH) {
    return -1;
  }
  
  /* form dirname */
  strcpy(spec->index_name, dirname);
  if (add_slash) {
    spec->index_name[len_dir] = '/';
    spec->index_name[len_dir + 1] = '\0';
  }
  strcat(spec->index_name, lev1_index_name);
  
  return 0;
}

static __inline
int one_chunk(const lev1_mapping_special_t * spec,
	      const vulpes_cmdblk_t * cmdblk)
{
  unsigned start, end;	/* absolute chunk numbers */
  
  start = get_chunk_number(spec, cmdblk->head.start_sect);
  end =
    get_chunk_number(spec,
		     (cmdblk->head.start_sect + cmdblk->head.num_sect -
		      1));
  
  return (start == end);
}

static __inline int is_dir(const char *name)
{
  struct stat s;
  int result = 0;
  
  if (stat(name, &s) == 0) {
    result = S_ISDIR(s.st_mode);
  }
  
  return result;
}

static __inline int is_file(const char *name)
{
  struct stat s;
  int result = 0;
  
  if (stat(name, &s) == 0) {
    result = S_ISREG(s.st_mode);
  }
  
  return result;
}

static __inline
off_t get_filesize(int fileno)
{
    struct stat filestat;
    
    /* Get file statistics */
    if (fstat(fileno, &filestat)) {
      return (off_t) 0;
    }

    return filestat.st_size;
}

static __inline
int form_dir_name(char *buffer, int bufsize,
		  const char *rootname, unsigned dir)
{
  int result = 0;
  size_t len;
  
  /* Assume buffer != NULL */
  
  len = strlen(rootname);
  
  if (bufsize > len + 6) {
    strcpy(buffer, rootname);
    sprintf(buffer + len, "/%04u/", dir);
    buffer[len + 6] = '\0';	/* just to be sure we have trailing nul */
  } else {
    buffer[0] = '\0';	/* Assumed buf_size > 0 */
    result = -1;
  }
  
  return result;
}

static __inline
int form_chunk_file_name(char *buffer, int bufsize,
			 const char *rootname,
			 unsigned dir, unsigned chunk,
			 const char *suffix, const vulpes_mapping_t* map_ptr)
{
  if (map_ptr->trxfer == LOCAL_TRANSPORT){
    int result = 0;
    size_t len;
    size_t sufflen;
    
    /* Assume buffer != NULL */
    
    len = strlen(rootname);
    sufflen = strlen(suffix);
    
    if (bufsize > len + 10) {	/* 10=5(dir)+5(chunk) */
      strcpy(buffer, rootname);
      sprintf(buffer + len, "/%04u", dir);
      sprintf(buffer + len + 5, "/%04u", chunk);
      sprintf(buffer + len + 10, "%s", suffix);
      buffer[len + 10 + sufflen + 1] = '\0';	/* just to be sure we have trailing nul */
    } else {	
      buffer[0] = '\0';	/* Assumed buf_size > 0 */			
      result = -1;
    }
    
    return result;
  }
  
  if (map_ptr->trxfer == HTTP_TRANSPORT){
    int result = 0;
    size_t len;
    size_t sufflen;
    
    /* Assume buffer != NULL */
    
    len = strlen(rootname);
    sufflen = strlen(suffix);
    
    buffer[0]=0;
    strcpy(buffer, rootname);
    
    if (bufsize > len + 10) {	/* 10=5(dir)+5(chunk) */
      sprintf(buffer + len, "/%04u", dir);
      sprintf(buffer + len + 5, "/%04u", chunk);
      sprintf(buffer + len + 10, "%s", suffix);
      buffer[len + 10 + sufflen + 1] = '\0';	/* just to be sure we have trailing nul */
    } else {	
      buffer[0] = '\0';	/* Assumed buf_size > 0 */			
      result = -1;
    }
    
    return result;
  }
  return -1;/*if we havent caught the tranxport type - return error*/
}

#ifdef DEBUG
static void 
printf_buffer_stats(const char *msg, unsigned index, const unsigned char *buf, unsigned bufsize)
{
  unsigned char *bufhash;
  unsigned char s_bufhash[41];
  unsigned char s_value[32];
  int i;

  bufhash=digest(buf, bufsize);
  for(i=0; i<20; i++) {
    sprintf(&(s_bufhash[2*i]), "%02x", bufhash[i]);
  }
  free(bufhash);

  sprintf(s_value,"%u", index);
  vulpes_log(LOG_CHUNKS,msg,NULL,"BUF_STATS", "buffer indx", s_value);	  

  sprintf(s_value,"%#08x", (unsigned)buf);
  vulpes_log(LOG_CHUNKS,msg,NULL,"BUF_STATS", "buffer addr", s_value);	  

  sprintf(s_value,"%u", bufsize);
  vulpes_log(LOG_CHUNKS,msg,NULL,"BUF_STATS", "buffer size", s_value);	  

  vulpes_log(LOG_CHUNKS,msg,NULL,"BUF_STATS", "buffer hash", s_bufhash);	  
}
#endif

static void
print_check_tag_error(const vulpes_mapping_t *map_ptr, unsigned chunk_num,
		      const unsigned char *tag)
{
  lev1_mapping_special_t *spec;
  unsigned char s_tag[41];
  unsigned char s_kr_tag[41];
  unsigned char *kr_tag;
  int i;

  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  if(lev1_get_tag(spec->keyring, chunk_num, &kr_tag) == LEV1_ENCRYPT_SUCCESS) {
    for(i=0; i<20; i++) {
      sprintf(&(s_tag[2*i]), "%02x", tag[i]);
      sprintf(&(s_kr_tag[2*i]), "%02x", kr_tag[i]);
    }
    vulpes_log(LOG_ERRORS,"CHECK_TAG_ERROR","expected",s_kr_tag,"found",s_tag);
  } else {
    vulpes_log(LOG_ERRORS,"CHECK_TAG_ERROR",NULL,NULL,NULL,"failed to get kr_tag");
  }
}

static int
valid_chunk_buffer(const unsigned char *buffer, unsigned bufsize, 
		  const vulpes_mapping_t *map_ptr, unsigned chunk_num)
{
  int bufvalid = 0;
  keyring_t *keyring;
  lev1_mapping_special_t *spec;
  unsigned char *dgst; /* hash of the buffer contents - malloc'ed by digest */

  spec = (lev1_mapping_special_t *) map_ptr->special;
  keyring = spec->keyring;

  if(keyring == NULL) {
    bufvalid = (bufsize == spec->chunksize_bytes);
  } else {
    dgst = digest(buffer, bufsize);
    bufvalid = (lev1_check_tag(keyring, chunk_num, dgst) == LEV1_ENCRYPT_SUCCESS);
    if(! bufvalid) {
      print_check_tag_error(map_ptr, chunk_num, dgst);
    }
    
    free(dgst);
  }

  return bufvalid;
}

static int
valid_chunk_file(const unsigned char *filename, 
		 const vulpes_mapping_t *map_ptr, unsigned chunk_num)
{
  int f;
  int fsize;
  unsigned char *buf;
  int result;

  if(!is_file(filename)) return 0;

  if((f=open(filename, O_RDONLY)) < 0) return 0;

  fsize = get_filesize(f);

  buf=malloc(fsize);
  if(buf == NULL) return 0;

  result = read(f, buf, fsize);
  if(result != fsize) return 0;

  result = valid_chunk_buffer(buf, fsize, map_ptr, chunk_num);

  free(buf);

  close(f);

  return result;
}

static int 
lev1_copy_file(const char *src, const char *dst, const vulpes_mapping_t *map_ptr, unsigned chunk_num)
{
  int transport_medium=map_ptr->trxfer;
  lev1_mapping_special_t *spec;
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  /* first check the lka database(s) */
  if(spec->keyring != NULL) { /* currently, must have keyring for lka lookup */
    if(map_ptr->lka_svc != NULL) {
      unsigned char *tag;
      
      if(lev1_get_tag(spec->keyring, chunk_num, &tag)==LEV1_ENCRYPT_SUCCESS) {
	vulpes_lka_return_t lka_ret;
	char *lka_src_file;

#ifdef DEBUG
	{
	  unsigned char s_bufhash[41];
	  int i;

	  for(i=0; i<20; i++) {
	    sprintf(&(s_bufhash[2*i]), "%02x", tag[i]);
	  }
	  vulpes_log(LOG_CHUNKS,"LEV1_COPY_FILE",NULL,NULL, "lka lookup tag", s_bufhash);	  
	}
#endif

	lka_ret = vulpes_lka_copy(map_ptr->lka_svc, VULPES_LKA_TAG_SHA1, 
				  tag, dst, &lka_src_file);
	if(lka_ret == VULPES_LKA_RETURN_SUCCESS) {
	  if(valid_chunk_file(dst, map_ptr, chunk_num)) {
	    /* LKA hit */
	    chunk_data_t *cdp;
	    
	    vulpes_log(LOG_CHUNKS,"LEV1_COPY_FILE",NULL,NULL, 
		       "lka lookup hit for ", dst);	  
	    cdp = get_cdp_from_chunk_num(spec, chunk_num);
	    mark_cdp_lka_copy(cdp);
	  } else {
	    /* Tag check failure */
	    vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",
		       "SERIOUS, NON-FATAL ERROR - lka lookup hit from ",
		       ((lka_src_file == NULL) ? "<src>" : lka_src_file), 
		       "failed tag match for ", dst);
	    lka_ret = VULPES_LKA_RETURN_ERROR;

	    /* unlink dst here */
	    if(unlink(dst)) {
	      vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",
			 "SERIOUS ERROR - unable to unlink file ", dst,
			 NULL, NULL);
	      /* Fall through and see if recovery is possible
		 (through an overwrite to the file) */
	    }
	  }

	  /* free the source name buffer */
	  if(lka_src_file != NULL) free(lka_src_file);

	  if(lka_ret == VULPES_LKA_RETURN_SUCCESS) return 0;
	  /* else, fall through */
	} else {
	  /* LKA miss */
	  vulpes_log(LOG_CHUNKS,"LEV1_COPY_FILE",NULL,NULL, "lka lookup miss for ", dst);
	}
      } else {
	/* Serious error?  Chunk not found in keyring */
	vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,NULL, NULL,"failure in lev1_get_tag()");
      }
    }
  }
  
  if (transport_medium == LOCAL_TRANSPORT)
    {
#define LEV1COPYFILEBUFLEN 4096
      char buf[LEV1COPYFILEBUFLEN];
      int buflen = LEV1COPYFILEBUFLEN;
      
      gzFile in_f;
      int out_f;
      int num;
      
      vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE",NULL,"local_begin",(char*)src,(char*)dst);
      in_f = gzopen(src, "r");
      if (in_f == NULL) {
	vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,NULL,"unable to open input",(char*)src);
	return -1;
      }
      
      out_f = open(dst, ( O_CREAT | O_RDWR | O_TRUNC), 0660);
      if (out_f == -1) {
	vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"local","unable to open output",(char*)dst);
	return -1;
      }
      
      
      while ((num = gzread(in_f, buf, buflen)) != 0) {
	if (num == -1) {
	  vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"local","unable to read input",(char*)src);
	  return -1;
	}
	
	if (write(out_f, buf, num) != num) {
	  vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"local","unable to write output",(char*)dst);
	  return -1;
	}
      }
      
      close(out_f);
      gzclose(in_f);
      vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE",NULL,"local_end",(char*)src,(char*)dst);
      
      return 0;
    }
  
  if (transport_medium == HTTP_TRANSPORT)
    {
      CURLcode retVal;
      int retstatus=-1;

      /* init curl session */
      init_curl(map_ptr);
      
      /* specify REMOTE FILE to get */
      curl_easy_setopt(curl_handle, CURLOPT_URL, src);
      
      /* perform the get */
      vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE",NULL,"http_begin",(char*)src,(char*)dst);
      retVal=curl_easy_perform(curl_handle);
      vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE",NULL,"http_end",(char*)src,(char*)dst);
      
      /* check for get errors */
      if ((strlen(curl_error_buffer)!=0) || (retVal!=0)) {
	/* problems */
	vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"http","curl",
		   curl_error_buffer);
	/*
	printf("Curl Error: %s\n",curl_error_buffer);
	if (retVal!=0)
	  printf("%s on error code %s\n",curl_error_buffer,
		 curl_easy_strerror(retVal)); 
	*/
	retstatus=-1;
      } else if(! valid_chunk_buffer(curl_buffer->buf, curl_buffer->size,
				    map_ptr, chunk_num)) {
	vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"http get failure",
		   (char*)src, "buffer not valid");
	retstatus=-1;
      } else {
	/* open cache file */
	int fd; 
	if ((fd=open(dst, O_CREAT|O_TRUNC|O_WRONLY,0660)) < 2) {
	  vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"http copy failure",
		     "unable to open output",(char*)dst);
	  close(fd);
	  destroy_curl();
	  return -1;
	}

	/* write to cache */
	if(write(fd,curl_buffer->buf,curl_buffer->size) == curl_buffer->size) {
	  vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE",NULL,"http copy success",
		     (char*)src,(char*)dst);
	  /* close the cache file */
	  close(fd);
	  retstatus=0;
	} else {
	  vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"http copy failure",
		     "unable to write output",(char*)dst);
	  /* delete the cache file */
	  close(fd);
	  if(unlink(dst)) {
	    /* this is really serious. we've put a bad file in the cache 
	       and can't remove it.
	       TODO: ensure that we shut down from here */
	    vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,
		       "!!! http unlink failure!!!",
		       "unable to unlink output",(char*)dst);
	  }
	  retstatus=-1;
	}

      }

      /* return from http transport */
      destroy_curl();
      return retstatus;
    }
      
  return -1;/* if we havent caught the transport type yet - return error */
}

int lev1_reclaim(fid_t fid, void *data, int chunk_num)
{
  unsigned dir=0, chunk=0;
  chunk_data_t *cdp;
  int err;
  char s_chunk_num[32];
  lev1_mapping_special_t *spec;
  unsigned chunksize;
  
#ifdef DEBUG
      {
	char s_spec_addr[32];
	sprintf(s_spec_addr,"%#08x",(unsigned) data);
	vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM",NULL,NULL,"received spec addr",s_spec_addr);
      }
#endif

  spec = (lev1_mapping_special_t *) data;
  
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);
  
  cdp = &(spec->cd[dir][chunk]);
  
  chunksize = spec->chunksize_bytes;
  
  sprintf(s_chunk_num,"%d", chunk_num);
  
  /* We have some work to do: compress the memory buffer
   * and then, if reqd encrypt it, then write to file
   * and close it. use the buffer to recalculate the new
   * keys, update the keyring, free buffer and get out
   */
  
  if (enableEncryption) {
    
    if (!cdp) {
      vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,"cdp is NULL, cant reclaim", s_chunk_num);
      /* fd = fidsvc_get(cdp->fnp); */
      return -1;
    }
    
    if (!cdp->buffer) {
      vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,"tried to reclaim null buffer", s_chunk_num);
    } else { 
      if (!cdp_is_dirty(cdp)) {
	/* just close the file (below) -- no changes */
	vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM",NULL,NULL,"clean chunk close().",s_chunk_num);
      } else {
	unsigned long compressedSize;
	int encryptedSize, errCode;
	unsigned char *compressed, *encrypted, *newkey, *newtag;
	
	compressedSize = 1.002 * chunksize+20;
	compressed = (unsigned char *) malloc(compressedSize);
	if(!compressed) {
	  vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,"malloc() failed while trying to compress buffer.",s_chunk_num);
	  return -1;
	}
	
	errCode = compress2(compressed, &compressedSize, cdp->buffer,
			    chunksize, Z_DEFAULT_COMPRESSION);
	if (errCode != Z_OK) {
	  vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,"error compressing chunk",s_chunk_num);
	  return -1;
	} 
	
	newkey = digest(compressed, compressedSize);
	vulpes_encrypt(compressed, compressedSize, &encrypted,
		       &encryptedSize, newkey, 20);
	newtag = digest(encrypted, encryptedSize);
	
#ifdef DEBUG
	printf_buffer_stats("LEV1_RECLAIM plaintext", chunk_num, cdp->buffer, chunksize);
	{
	  char s_compressed_size[32];
	  sprintf(s_compressed_size,"%lu",compressedSize);
	  vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM",NULL,"compressed chunk size",s_compressed_size,s_chunk_num);
	}
	printf_buffer_stats("LEV1_RECLAIM encrypted", chunk_num, encrypted, encryptedSize);
#endif

	lev1_updateKey(spec->keyring, newkey, newtag, chunk_num);
	
	errCode = ftruncate(fid, 0);
	if (errCode != 0) {
	  vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,"ftruncate failed",s_chunk_num);
	  return -1;
	}
	
	lseek(fid, 0, SEEK_SET);
	if(write(fid, encrypted, encryptedSize) != encryptedSize) {
	  vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,"chunk write failed.",s_chunk_num);
	  return -1;
	}

	free(compressed);
      	free(newkey);
	free(newtag);
	free(encrypted);

	vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM",NULL,NULL,"dirty chunk close().",s_chunk_num);
      }
    } 
  } else {
    vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,"reclaim() without encryption not implemented",s_chunk_num);
    return -1;
  }
  
  if (close(fid)!=0) {
    err=errno;
    if (err==EBADF)
      vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,NULL,"close failed ebadf");
    else
      vulpes_log(LOG_ERRORS,"LEV1_RECLAIM",NULL,NULL,NULL,"close failed");
  }

  /* clean up the cdp */
  cdp->fnp = NULL_FID_ID;
  if (cdp->buffer != NULL) {
    free(cdp->buffer);
    cdp->buffer = NULL;
  }
  
  return 0;
}

static __inline void binToHex(unsigned char* bin, unsigned char hex[2])
{
  int i;
  unsigned char tmp;
  
  tmp = *bin;
  i = ((int)tmp)/16;
  if (i<10)
    hex[0] = '0' + i;
  else
    hex[0] = 'A' + (i-10);
  i = ((int)tmp)%16;
  if (i<10)
    hex[1] = '0' + i;
  else
    hex[1] = 'A' + (i-10);
}


/* In earlier version we returned the FID (an int)
 * but with new versions, we are always going to
 * read from a memory buffer, which is part of the
 * chunk_data_t structure. so we return an error code
 * if required. in essence, the open function just
 * sets up the buffers - which essentially means that
 * we decrypt the file, decompress it and read it into
 * memory
 */
/* returns 0 if okay else -1 on bad exit */
static __inline
int open_chunk_file(const vulpes_mapping_t * map_ptr,
		    const vulpes_cmdblk_t * cmdblk, int open_for_writing)
{
  char chunk_name[MAX_CHUNK_NAME_LENGTH];
  lev1_mapping_special_t *spec;
  unsigned dir = 0, chunk = 0;
  unsigned chunk_num=0;
  int chunksPerDir;
  fid_t fid;
  chunk_data_t *cdp;
  char s_chunk_num[32];
  int open_readwrite;

  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  chunksPerDir = spec->chunksperdir;

  /* find the dir,chunk numbers */
  chunk_num=get_chunk_number(spec,cmdblk->head.start_sect);
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);
  cdp = &(spec->cd[dir][chunk]);  

  sprintf(s_chunk_num,"%d", chunk_num);
  
  open_readwrite = open_for_writing;
  if(cdp_is_dirty(cdp) && !open_readwrite) {
    open_readwrite = 1;
#ifdef DEBUG
    {
      char s_spec_addr[32];
      sprintf(s_spec_addr,"%#08x",(unsigned) spec);
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"changing mode from ro to rw",s_chunk_num);
    }
#endif
  }

  /* if the file is already open, return */
  if (cdp->fnp != NULL_FID_ID) {
    fid = fidsvc_get(cdp->fnp); /* Partho: redundant call, but has side-effects. DO NOT REMOVE */
    /* check if we need the file to be readwrite */
    if (open_readwrite && !cdp_is_rw(cdp)) {
      /* Close the readonly file */
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,NULL,"failure while attempting to close file and reopen in rw mode");
	return -1;
      }
      
      /* Continue as if we missed the fid cache */
      /* -- Note: this algorithm fouls up the replacement policy of the fid cache */
    } else {
      if (!cdp->buffer) {
	vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"null buffer in cdp",s_chunk_num);
      }
      return 0;
    }
  }
  
  /* otherwise(file not open), form the filename */
  if (form_chunk_file_name(chunk_name, MAX_CHUNK_NAME_LENGTH,
			   spec->shadow ? map_ptr->cache_name : map_ptr->
			   file_name, dir, chunk, "",map_ptr)) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"unable to form lev1 file name",s_chunk_num);
    return -1;
  }
  
  /* Check for writes_before_reads */
  if(!cdp_is_accessed(cdp) && open_readwrite)
    ++ writes_before_read;
  
  /* copy shadow if needed */
  if (spec->shadow) {
    /* check if we know that the file is present */
    if (!cdp_shadow_present(cdp)) {
      /* check if the file is present anyway */
      if (is_file(chunk_name)) {
	/* the file is present -- set the shadow_present flag */
	mark_cdp_shadow_present(cdp);
      } else {
	/* the file has not been copied yet */
	char remote_name[MAX_CHUNK_NAME_LENGTH];
	if (form_chunk_file_name
	    (remote_name, MAX_CHUNK_NAME_LENGTH,
	     map_ptr->file_name, dir, chunk,
	     (spec->compressed_chunks ? ".gz" : ""),map_ptr)) {
	  vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"unable to form lev1 remote name",s_chunk_num);
	  return -1;
	}
	/*if (spec->verbose)
	  printf("Copying %s to %s ...", remote_name, chunk_name);*/
	
	if (lev1_copy_file(remote_name, chunk_name, map_ptr, chunk_num) == 0) {
	  mark_cdp_shadow_present(cdp);
	} else {
	  vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",NULL,"unable to copy",remote_name,chunk_name);
	  return -1;
	}
      }
    }
  }
  
  /* REM: we still have to open the encrypted(and compressed) file
   * and store the fid somewhere. so the next bunch of lines stay!
   */
  
  /* open the file */
  if (open_readwrite)
    fid = open(chunk_name,  O_RDWR);
  else
    fid = open(chunk_name,  O_RDONLY);
  if (fid < 0) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,"unable to open",chunk_name,s_chunk_num);
    return -1;
  }
  vulpes_log(LOG_CHUNKS,"OPEN_CHUNK_FILE","open",(open_readwrite ? "rw" : "ro"),chunk_name,s_chunk_num);
  
  /* store the fid */
  cdp->fnp = fidsvc_register(fid, lev1_reclaim, spec, chunk_num);
#ifdef DEBUG
      {
	char s_spec_addr[32];
	sprintf(s_spec_addr,"%#08x",(unsigned) spec);
	vulpes_log(LOG_CHUNKS,"OPEN_CHUNK_FILE",NULL,NULL,"register spec addr",s_spec_addr);
      }
#endif

  /* Assume that the file will be read and written according to open_readwrite */
  mark_cdp_accessed(cdp);
  if (open_readwrite) {
    mark_cdp_readwrite(cdp);
  } else {
    mark_cdp_readonly(cdp);
  }
  
  /* Now, instead of returning the fid, we need to set up the buffer, decrypt
   * using the key and then decompress it; and then return an error code
   */
  if (enableEncryption) {
    unsigned char *decryptedFile=NULL, *encryptedFile=NULL, 
      *decompressedFile=NULL, *tag=NULL, *key=NULL;
    unsigned fSize;
    unsigned long decompressedSize, compressedSize;
    int size, errCode;
    static unsigned char tag_log[41];
    unsigned char *readPtr ,*writePtr;
    int i;
    
    if((fSize = get_filesize(fid)) == 0) {
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"Encrypted file size is zero",s_chunk_num);
      return -1;
    }
    lseek(fid, 0, SEEK_SET);

#ifdef DEBUG
      {
	char s_compressed_size[32];
	sprintf(s_compressed_size,"%d",fSize);
	vulpes_log(LOG_CHUNKS,"OPEN_CHUNK_FILE",NULL,"compressed chunk size",s_compressed_size,s_chunk_num);
      }
#endif

    encryptedFile = (unsigned char *) malloc(fSize);
    if (encryptedFile == NULL) {
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"Couldnt malloc encrypted file",s_chunk_num);
      return -1;
    }

    errCode = read(fid, encryptedFile, fSize);
    if (errCode!=fSize) {
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"Could not read the required number of bytes",s_chunk_num);
      return -1;
    }

    tag = digest(encryptedFile, fSize);
    
    if (lev1_check_tag(spec->keyring, chunk_num, tag) != LEV1_ENCRYPT_SUCCESS){
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"lev1_check_tag() failed.",s_chunk_num);
      /* #ifdef DEBUG */
      {
	unsigned char s_tag[41];
	unsigned char s_kr_tag[41];
	unsigned char *kr_tag;
	int i;
	
	if(lev1_get_tag(spec->keyring, chunk_num, &kr_tag) == LEV1_ENCRYPT_SUCCESS) {
	  for(i=0; i<20; i++) {
	    sprintf(&(s_tag[2*i]), "%02x", tag[i]);
	    sprintf(&(s_kr_tag[2*i]), "%02x", kr_tag[i]);
	  }
	  vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","expected",s_kr_tag,"found",s_tag);
	} else {
	  vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,NULL,"failed to get kr_tag");
	}
      }
      /* #endif */
      return -1;
    }
    
    if (lev1_get_key(spec->keyring, chunk_num, &key) != LEV1_ENCRYPT_SUCCESS){
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"lev1_get_key() failed.",s_chunk_num);
      return -1;
    }
    
    if (!vulpes_decrypt
	(encryptedFile, fSize, &decryptedFile, &size, key, 20)) {
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"couldnt decrypt file into memory",s_chunk_num);
      return -1;
    };
    writePtr=tag_log; readPtr=tag;
    for(i=0;i<20;i++,readPtr++,writePtr+=2)
      binToHex(readPtr,writePtr);
    *writePtr='\0';

    if (open_readwrite)
      vulpes_log(LOG_KEYS,"OPEN_CHUNK_FILE",NULL,"w",s_chunk_num,tag_log);
    else
      vulpes_log(LOG_KEYS,"OPEN_CHUNK_FILE",NULL,"r",s_chunk_num,tag_log);
    
    free(encryptedFile);
    encryptedFile = NULL;
    
    decompressedFile = NULL;
    decompressedFile = (unsigned char *) malloc(spec->chunksize_bytes);
    if (decompressedFile == NULL) {
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"couldnt malloc space for decompressed file",s_chunk_num);
      return -1;
    }

    compressedSize = size;
    errCode = 0;
    decompressedSize = spec->chunksize_bytes;
    errCode =
      uncompress(decompressedFile, &decompressedSize, decryptedFile,
		 compressedSize);
    if (errCode != Z_OK) {
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"couldnt decompress file",s_chunk_num);
      return -1;
    };
    
    if (decompressedSize!=spec->chunksize_bytes) {
      /* Partho: This "error condition" may not be an error in future versions */
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"On decompressing, final size is NOT CHUNKSIZE",s_chunk_num);
      return -1;
    }
    free(decryptedFile);

    /* eliminating extraneous copy -- MAK */
    /*
    unsigned char *tmpDecompress=NULL;
    tmpDecompress = NULL;
    tmpDecompress = (unsigned char *) malloc(decompressedSize);
    if (tmpDecompress == NULL) {
      vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"couldnt malloc space for tmpDecompress",NULL);
      return -1;
    }

    memcpy(tmpDecompress, decompressedFile, decompressedSize);
    free(decompressedFile);
    cdp->buffer = tmpDecompress;
    */
    cdp->buffer = decompressedFile;

#ifdef DEBUG
    printf_buffer_stats("OPEN_CHUNK_FILE", chunk_num, cdp->buffer, spec->chunksize_bytes);
#endif
  } else {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE",NULL,NULL,"open() without encryption not implemented",s_chunk_num);
    return -1;
  }

  return 0;
}

/* INTERFACE FUNCTIONS */

vulpes_volsize_t lev1_volsize_func(const vulpes_mapping_t * map_ptr)
{
  return ((const lev1_mapping_special_t *) map_ptr->special)->volsize;
}

/* returns -1 if an error occurs
 *  returns  0 on a normal exit */
int lev1_open_func(vulpes_mapping_t * map_ptr)
{
  lev1_mapping_special_t *spec;
  unsigned long long volsize_bytes;
  int parse_error = 0;
  int result = 0;
  FILE *f;
  unsigned u, v;
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  /* Form index_name */
  if (map_ptr->trxfer == LOCAL_TRANSPORT)
    {
      result = form_index_name(map_ptr->cache_name, spec);
      /*result = form_index_name(map_ptr->file_name, spec);*/
    }
  else
    if (map_ptr->trxfer == HTTP_TRANSPORT)
      result = form_index_name(map_ptr->cache_name,spec);
  
  /* result =  0 means good
   *  result = -1 means error */
  if (result !=0 ) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,NULL,"unable to form lev1 index name");
    return -1;
  }
  
  /* Open index file */
  f = fopen(spec->index_name, "r");
  if (f == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"unable to open index file",spec->index_name);
    return -1;
  }
  
  /* Scan index file */
  if (fscanf(f, "VERSION= %u\n", &spec->version) != 1) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"unable to parse version from index file",spec->index_name);
    fclose(f);
    return -1;
  }
  if (spec->version != 1) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"unknown lev1 version number",spec->index_name);
    fclose(f);
    return -1;
  }
  
  if (fscanf(f, "CHUNKSIZE= %u\n", &spec->chunksize_bytes) != 1)
    parse_error = 1;
  if (fscanf(f, "CHUNKSPERDIR= %u\n", &spec->chunksperdir) != 1)
    parse_error = 1;
  if (fscanf(f, "VOLSIZE= %llu\n", &volsize_bytes) != 1)
    parse_error = 1;
  if (fscanf(f, "NUMCHUNKS= %u\n", &spec->numchunks) != 1)
    parse_error = 1;
  if (fscanf(f, "NUMDIRS= %u\n", &spec->numdirs) != 1)
    parse_error = 1;
  
  if (parse_error) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"bad parse",spec->index_name);
    result = -1;
  } else {
    unsigned long long tmp_volsize;
    
    /* compute derivative values */
    if (spec->chunksize_bytes % FAUXIDE_HARDSECT_SIZE != 0) {
      char c_size[32];
      sprintf(c_size,"%u",spec->chunksize_bytes);
      vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"bad chunksize",c_size);
      result = -1;
    } else {
      spec->chunksize =
	spec->chunksize_bytes / FAUXIDE_HARDSECT_SIZE;
    }
    
    tmp_volsize = spec->chunksize * spec->numchunks;
    if (tmp_volsize > MAX_VOLSIZE_VALUE) {
      char v_size[32];
      sprintf(v_size,"%llu",tmp_volsize);
      vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"lev1 volsize too big", v_size);
      result = -1;
    } else {
      spec->volsize = (vulpes_volsize_t) tmp_volsize;
    }
  }
  fclose(f);
  
  /* Create caching directories if needed */
  if (spec->shadow) {
    /* Check if the root directory exists */
    if (!is_dir(map_ptr->cache_name)) {
      vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"unable to open dir", map_ptr->cache_name);
      result = -1;
    } else {
      char dirname[MAX_DIRLENGTH];
      unsigned d;
      
      /* check the subdirectories  -- create if needed */
      for (d = 0; d < spec->numdirs; d++) {
	form_dir_name(dirname, MAX_DIRLENGTH, map_ptr->cache_name, d);
	if (!is_dir(dirname)) {
	  if (mkdir(dirname, 0770)) {
	    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,"unable to mkdir", dirname);
	    result = -1;
	    break;
	  }
	}
      }
    }
  }
  
  /* Allocate the fid array */
  spec->cd = malloc(spec->numdirs * sizeof(chunk_data_t *));
  if (spec->cd == NULL)
    {
      vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,NULL,"unable to allocate fid array");
      return -1;
    }
  for (u = 0; u < spec->numdirs; u++) {
    spec->cd[u] = NULL;
  }
  for (u = 0; u < spec->numdirs; u++) {
    spec->cd[u] = malloc(spec->chunksperdir * sizeof(chunk_data_t));
    if (spec->cd[u] == NULL)
      {
	vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC",NULL,NULL,NULL,"unable to allocate fid array 2");
	return -1;
      }
    /* fill the file descriptors with -1 */
    for (v = 0; v < spec->chunksperdir; v++) {
      spec->cd[u][v].fnp = NULL_FID_ID;
      spec->cd[u][v].status = 0;
      spec->cd[u][v].buffer = NULL;
    }
  }
  
  return result;
}

int lev1_close_func(vulpes_mapping_t * map_ptr)
{
  char chunk_name[MAX_CHUNK_NAME_LENGTH];
  lev1_mapping_special_t *spec;
  int result = 0;
  unsigned u, v;
  
  unsigned dirty_chunks = 0;
  unsigned accessed_chunks = 0;
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  
  if (spec != NULL) {
    /* deallocate the fnp array */
    if (spec->cd != NULL) {
      for (u = 0; u < spec->numdirs; u++) {
	if (spec->cd[u] != NULL) {
	  for (v = 0; v < spec->chunksperdir; v++) {
	    if (cdp_is_accessed(&(spec->cd[u][v]))) {
	      ++accessed_chunks;
	      if (cdp_is_dirty(&(spec->cd[u][v]))) {
		++dirty_chunks;
		if (spec->verbose) {
		  if (form_chunk_file_name(chunk_name, MAX_CHUNK_NAME_LENGTH,
		       spec->shadow ? map_ptr->cache_name : map_ptr->file_name,
		       u, v, "",map_ptr)) {
		    vulpes_log(LOG_ERRORS,"LEV1_CLOSE_FUNCTION",NULL,NULL,NULL,"unable to form lev1 file name");
		    return -1;
		  }
		  vulpes_log(LOG_CHUNKS,"LEV1_CLOSE_FUNCTION",NULL,NULL,"MODIFIEDCLOSE",chunk_name);
		}
	      }
	    }
	    if (spec->cd[u][v].fnp != NULL_FID_ID) {
	      if (fidsvc_remove(spec->cd[u][v].fnp)) {
		char dir_c[32],fil_c[32];
		sprintf(dir_c,"%d",u);
		sprintf(fil_c,"%d",v);
		vulpes_log(LOG_ERRORS,"LEV1_CLOSE",NULL,dir_c,fil_c,"failed in fidsvc_remove");
		return -1;
	      }
	    }
	  }
	  free(spec->cd[u]);
	  spec->cd[u] = NULL;
	}
      }
      free(spec->cd);
      spec->cd = NULL;
    }
    
    map_ptr->special = NULL;
    free(spec);
  }
  
  result = lev1_cleanupKeys(spec->keyring, map_ptr->keyring_name);
  if (result == -1) {
    vulpes_log(LOG_ERRORS,"LEV1_CLOSE",NULL,NULL,NULL,"lev1_cleanupKeys failed");
    return result;
  }

  /* Print close stats */
  {
    char s_buffer[12];

    sprintf(s_buffer, "%u", accessed_chunks);
    vulpes_log(LOG_STATS,"LEV1_CLOSE_FUNCTION",NULL,NULL,"CHUNKS_ACCESSED",s_buffer);
    sprintf(s_buffer, "%u", dirty_chunks);
    vulpes_log(LOG_STATS,"LEV1_CLOSE_FUNCTION",NULL,NULL,"CHUNKS_MODIFIED",s_buffer);
    sprintf(s_buffer, "%u", writes_before_read);
    vulpes_log(LOG_STATS,"LEV1_CLOSE_FUNCTION",NULL,NULL,"CHUNKS_RAW",s_buffer);
  }  

  return result;
}

int lev1_read_func(const vulpes_mapping_t * map_ptr,
		   vulpes_cmdblk_t * cmdblk)
{
  lev1_mapping_special_t *spec;
  off_t start;
  ssize_t bytes;
  chunk_data_t *cdp=NULL;
  unsigned chunk_num = 0, dir = 0, chunk = 0;
  char s_chunk_num[32];
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  /* find the dir,chunk numbers */
  chunk_num=get_chunk_number(spec,cmdblk->head.start_sect);
  sprintf(s_chunk_num,"%d", chunk_num);
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);

  if (!one_chunk(spec, cmdblk)) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC",NULL,NULL,"request crosses chunk boundary",s_chunk_num);
    return -1;
  }
  
  cdp = &(spec->cd[dir][chunk]);

  if (open_chunk_file(map_ptr, cmdblk, 0) != 0) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC",NULL,NULL,"open_chunk_file failed",s_chunk_num);
    /* if the open returned a failure... cleanup */
    if (cdp->fnp != NULL_FID_ID) {
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC",NULL,NULL,NULL,"fidsvc_remove() failed during cleanup");
      }
    }
    return -1;
  };
  
  start = (cmdblk->head.start_sect % spec->chunksize) * FAUXIDE_HARDSECT_SIZE;
  bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
  
  if (start+bytes>spec->chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC",NULL,NULL,"trying to read beyond end of chunk",s_chunk_num);
    return -1;
  }
  
  if (cdp->buffer == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC",NULL,NULL,"cdp buffer is null",s_chunk_num);
    return -1;
  }

  if(memcpy(cmdblk->buffer, ((unsigned char *) (cdp->buffer)) + start, bytes) == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC",NULL,NULL,"Could not do a lev1_read. memcpy failed",s_chunk_num);
    return -1;
  }

  vulpes_log(LOG_FAUXIDE_REQ,"LEV1_READ_FUNC",NULL,NULL,"read",s_chunk_num);
  return 0;
}

int lev1_write_func(const vulpes_mapping_t * map_ptr,
		    const vulpes_cmdblk_t * cmdblk)
{
  lev1_mapping_special_t *spec;
  off_t start;
  ssize_t bytes;
  chunk_data_t *cdp=NULL;
  unsigned chunk_num = 0, dir = 0, chunk = 0;
  char s_chunk_num[32];
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  /* find the dir,chunk numbers */
  chunk_num=get_chunk_number(spec,cmdblk->head.start_sect);
  sprintf(s_chunk_num,"%d", chunk_num);
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);

  if (!one_chunk(spec, cmdblk)) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC",NULL,NULL,"request crosses chunk boundary",s_chunk_num);
    return -1;
  }
  
  cdp = &(spec->cd[dir][chunk]);

  if (open_chunk_file(map_ptr, cmdblk, 1) != 0) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC",NULL,NULL,"open_chunk_file failed",s_chunk_num);
    /* if the open returned a failure... cleanup */
    if (cdp->fnp != NULL_FID_ID) {
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC",NULL,NULL,NULL,"fidsvc_remove() failed during cleanup");
      }
    }
    return -1;
  };
  
  start = (cmdblk->head.start_sect % spec->chunksize) * FAUXIDE_HARDSECT_SIZE;
  bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
  
  if (start+bytes>spec->chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC",NULL,NULL,"trying to write beyond end of chunk",s_chunk_num);
    return -1;
  }
  
  if (cdp->buffer == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC",NULL,NULL,"cdp buffer is null",s_chunk_num);
    return -1;
  }

  /* Check for writes_before_reads */
  if (!cdp_is_accessed(cdp))
    ++writes_before_read;
  
  mark_cdp_dirty(cdp);
  if (memcpy(((unsigned char *) (cdp->buffer)) + start, cmdblk->buffer, bytes) == 0) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC",NULL,NULL,"memcpy failed",s_chunk_num);
    return -1;
  }

  vulpes_log(LOG_FAUXIDE_REQ,"LEV1_WRITE_FUNC",NULL,NULL,"write",s_chunk_num);
  return 0;
}


int initialize_lev1_mapping(vulpes_mapping_t * map_ptr)
{
  lev1_mapping_special_t *spec;
  
  /* Allocate special */
  spec = map_ptr->special = malloc(sizeof(lev1_mapping_special_t));
  if (!map_ptr->special)
    {
      vulpes_log(LOG_ERRORS,"LEV1_INIT",NULL,NULL,NULL,"malloc for map_ptr->special failed");
      return -1;
    }
  bzero(map_ptr->special, sizeof(lev1_mapping_special_t));
  
  switch (map_ptr->type) {
  case LEV1_MAPPING:
    break;
  case LEV1V_MAPPING:
    spec->verbose = 1;
    break;
  case ZLEV1_MAPPING:
    spec->compressed_chunks = 1;
    break;
  case ZLEV1V_MAPPING:
    spec->compressed_chunks = 1;
    spec->verbose = 1;
    break;
  default:
    free(map_ptr->special);
    map_ptr->special = NULL;
    return -1;
  }
  
  spec->shadow = (map_ptr->cache_name != NULL);
  if (spec->compressed_chunks && !spec->shadow) {
    vulpes_log(LOG_ERRORS,"LEV1_INIT",NULL,NULL,NULL,"attempted compression without caching");
    free(map_ptr->special);
    map_ptr->special = NULL;
    return -1;
  }
  
  if (map_ptr->cache_name)
    vulpes_log(LOG_BASIC,"LEV1_INIT",NULL,NULL,"vulpes_cache",map_ptr->cache_name);
  else
    vulpes_log(LOG_BASIC,"LEV1_INIT",NULL,NULL,"vulpes_cache","none");
  if ( (map_ptr->proxy_name) && (map_ptr->proxy_port))
    {
      char p_port[32];
      sprintf(p_port,"%ld",map_ptr->proxy_port);
      vulpes_log(LOG_BASIC,"LEV1_INIT",NULL,NULL,"proxy",map_ptr->proxy_name);
      vulpes_log(LOG_BASIC,"LEV1_INIT",NULL,NULL,"proxy-port",p_port);
    }
  /* DELETEME 
     printf("Cache name = <%s>  Shadow = %d\n",
     ((map_ptr->cache_name != NULL) ? map_ptr->cache_name : "NULL"),
     spec->shadow);
     if (map_ptr->outgoing_interface)
     printf("Using interface %s for network connections\n", map_ptr->outgoing_interface);
     if ( (map_ptr->proxy_name) && (map_ptr->proxy_port))
     printf("Will connect to port %ld on the proxy server - %s\n",map_ptr->proxy_port, map_ptr->proxy_name);
     DELETEME */
  
  map_ptr->open_func = lev1_open_func;
  map_ptr->volsize_func = lev1_volsize_func;
  map_ptr->read_func = lev1_read_func;
  map_ptr->write_func = lev1_write_func;
  map_ptr->close_func = lev1_close_func;
  
  enableEncryption = ((map_ptr->keyring_name==NULL) ? 0 : 1);
  if (enableEncryption) {
    if((spec->keyring = lev1_initEncryption(map_ptr->keyring_name)) == NULL) {
      vulpes_log(LOG_ERRORS,"LEV1_INIT",NULL,NULL,NULL,"lev1_initEncryption() failed.");
      return -1;	
    }
  } else {
    vulpes_log(LOG_ERRORS,"LEV1_INIT",NULL,NULL,NULL,"null keyring name");
    return -1;
  }
  
  return 0;
}
