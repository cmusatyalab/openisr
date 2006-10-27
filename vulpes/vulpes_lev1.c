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
#include <errno.h>
#include <zlib.h>
#include "fauxide.h"
#include "vulpes_map.h"
#include "vulpes_fids.h"
#include "vulpes_lev1_encryption.h"
#include "vulpes_lev1.h"
#include "vulpes_log.h"
#include "vulpes_util.h"
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
const unsigned CHUNK_STATUS_PRESENT = 0x8000;	/* This chunk is present in the local cache */
const char *lev1_index_name = "index.lev1";

/* LOCALS */
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
  
  keyring_t *keyring;
  
  chunk_data_t **cd;		/* cd[][] */
};
typedef  struct lev1_mapping_special_s lev1_mapping_special_t;

static unsigned writes_before_read = 0;

static void get_dir_chunk(const lev1_mapping_special_t * spec,
			  unsigned sect_num, unsigned *dir, unsigned *chunk);
static void get_dir_chunk_from_chunk_num(const lev1_mapping_special_t * spec,
					 unsigned chunk_num, unsigned *dir, unsigned *chunk);
static unsigned get_chunk_number(const lev1_mapping_special_t * spec,
				 unsigned sect_num);
static int form_chunk_file_name(char *buffer, int bufsize,
				const char *rootname,
				unsigned dir, unsigned chunk);

/* XXX for now */
extern int local_get(char *buf, int *bufsize, const char *file);
extern int http_get(const vulpes_mapping_t *map_ptr, char *buf, int *bufsize,
	  	const char *url);

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
  if(result && !cdp_is_rw(cdp))
    vulpes_log(LOG_ERRORS,"CDP_IS_DIRTY()","cdp is dirty but not rw: %#x", cdp->status);
  if(result && !cdp_is_accessed(cdp))
    vulpes_log(LOG_ERRORS,"CDP_IS_DIRTY()","cdp is dirty but not accessed: %#x", cdp->status);
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

static __inline int cdp_present(chunk_data_t * cdp)
{
  return ((cdp->status & CHUNK_STATUS_PRESENT) ==
	  CHUNK_STATUS_PRESENT);
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

static __inline void mark_cdp_present(chunk_data_t * cdp)
{
  cdp->status |= CHUNK_STATUS_PRESENT;
}

static int form_index_name(const char *dirname,
			   lev1_mapping_special_t * spec)
{
  int add_slash = 0;
  int result;
  
  if (dirname[strlen(dirname) - 1] != '/') {
    add_slash = 1;
  }
  
  result=snprintf(spec->index_name, MAX_INDEX_NAME_LENGTH, "%s%s%s",
                        dirname, (add_slash ? "/" : ""), lev1_index_name);

  if (result >= MAX_INDEX_NAME_LENGTH || result == -1) {
    /* Older versions of libc return -1 on truncation */
    return -1;
  }
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

static __inline
int form_dir_name(char *buffer, int bufsize,
		  const char *rootname, unsigned dir)
{
  int result;
  
  /* Assume buffer != NULL */
  
  result=snprintf(buffer, bufsize, "%s/%04u/", rootname, dir);
  if (result >= bufsize || result == -1) {
    /* Older versions of libc return -1 on truncation */
    return -1;
  }
  return 0;
}

static __inline
int form_chunk_file_name(char *buffer, int bufsize,
			 const char *rootname,
			 unsigned dir, unsigned chunk)
{
  int result;
  
  /* Assume buffer != NULL */
  
  result=snprintf(buffer, bufsize, "%s/%04u/%04u", rootname, dir, chunk);
  if (result >= bufsize || result == -1) {
    /* Older versions of libc return -1 on truncation */
    return -1;
  }
  return 0;
}

#ifdef DEBUG
static void 
printf_buffer_stats(const char *msg, unsigned index, const unsigned char *buf, unsigned bufsize)
{
  unsigned char *bufhash;
  unsigned char s_bufhash[41];
  int i;

  bufhash=digest(buf, bufsize);
  for(i=0; i<20; i++) {
    sprintf(&(s_bufhash[2*i]), "%02x", bufhash[i]);
  }
  free(bufhash);

  vulpes_log(LOG_CHUNKS,msg,"BUF_STATS: buffer indx: %u", index);
  vulpes_log(LOG_CHUNKS,msg,"BUF_STATS: buffer addr: %#08x", (unsigned)buf);
  vulpes_log(LOG_CHUNKS,msg,"BUF_STATS: buffer size: %u", bufsize);
  vulpes_log(LOG_CHUNKS,msg,"BUF_STATS: buffer hash: %s", s_bufhash);
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
    vulpes_log(LOG_ERRORS,"CHECK_TAG_ERROR","expected %s, found %s",s_kr_tag,s_tag);
  } else {
    vulpes_log(LOG_ERRORS,"CHECK_TAG_ERROR","failed to get kr_tag");
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

  dgst = digest(buffer, bufsize);
  bufvalid = (lev1_check_tag(keyring, chunk_num, dgst) == LEV1_ENCRYPT_SUCCESS);
  if(! bufvalid) {
    print_check_tag_error(map_ptr, chunk_num, dgst);
  }
  
  free(dgst);

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
  lev1_mapping_special_t *spec;
  char *buf;
  int buflen;
  int ret;
  int fd;
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  /* first check the lka database(s) */
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
	vulpes_log(LOG_CHUNKS,"LEV1_COPY_FILE","lka lookup tag: %s", s_bufhash);	  
      }
#endif

      lka_ret = vulpes_lka_copy(map_ptr->lka_svc, VULPES_LKA_TAG_SHA1, 
				tag, dst, &lka_src_file);
      if(lka_ret == VULPES_LKA_RETURN_SUCCESS) {
	if(valid_chunk_file(dst, map_ptr, chunk_num)) {
	  /* LKA hit */
	  chunk_data_t *cdp;
	  
	  vulpes_log(LOG_CHUNKS,"LEV1_COPY_FILE","lka lookup hit for %s",dst);	  
	  cdp = get_cdp_from_chunk_num(spec, chunk_num);
	  mark_cdp_lka_copy(cdp);
	} else {
	  /* Tag check failure */
	  vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",
		     "SERIOUS, NON-FATAL ERROR - lka lookup hit from %s failed tag match for %s",
		     ((lka_src_file == NULL) ? "<src>" : lka_src_file), 
		     dst);
	  lka_ret = VULPES_LKA_RETURN_ERROR;

	  /* unlink dst here */
	  if(unlink(dst)) {
	    vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",
		       "SERIOUS ERROR - unable to unlink file %s", dst);
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
	vulpes_log(LOG_CHUNKS,"LEV1_COPY_FILE","lka lookup miss for %s", dst);
      }
    } else {
      /* Serious error?  Chunk not found in keyring */
      vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE","failure in lev1_get_tag()");
    }
  }
  
  buflen=1.002*spec->chunksize_bytes+20;
  buf=malloc(buflen);
  if (buf == NULL) {
    vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE","malloc failed");
    return -1;
  }
  
  vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE","begin_transport: %s %s",src,dst);
  switch (map_ptr->trxfer) {
  case LOCAL_TRANSPORT:
    ret=local_get(buf, &buflen, src);
    break;
  case HTTP_TRANSPORT:
    ret=http_get(map_ptr, buf, &buflen, src);
    break;
  default:
    vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE","unknown transport");
    ret=-1;
  }
  vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE","end_transport: %s %s",src,dst);
  if (ret) {
    goto out;
  }
  /* buflen has been updated with the length of the data */
  
  /* check retrieved data for validity */
  if(!valid_chunk_buffer(buf, buflen, map_ptr, chunk_num)) {
    vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE","failure: %s buffer not valid",src);
    ret=-1;
    goto out;
  }

  /* open destination cache file */
  if ((fd=open(dst, O_CREAT|O_TRUNC|O_WRONLY,0660)) == -1) {
    vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE","unable to open output %s",dst);
    ret=-1;
    goto out;
  }
  
  /* write to cache */
  if(write(fd, buf, buflen) != buflen) {
      vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE","unable to write output %s",dst);
      /* delete the cache file */
      close(fd);
      if(unlink(dst)) {
	/* this is really serious. we've put a bad file in the cache 
	   and can't remove it.
	   XXX: ensure that we shut down from here */
	vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE",
		   "!!! unlink failure!!!: unable to unlink output %s",dst);
      }
      ret=-1;
  }
  close(fd);
  vulpes_log(LOG_TRANSPORT,"LEV1_COPY_FILE","end: %s %s",src,dst);
  
out:
  free(buf);
  return ret;
}

int lev1_reclaim(fid_t fid, void *data, int chunk_num)
{
  unsigned dir=0, chunk=0;
  chunk_data_t *cdp;
  int err;
  lev1_mapping_special_t *spec;
  unsigned chunksize;
  
#ifdef DEBUG
  vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM","received spec addr: %#08x",(unsigned)data);
#endif

  spec = (lev1_mapping_special_t *) data;
  
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);
  
  cdp = &(spec->cd[dir][chunk]);
  
  chunksize = spec->chunksize_bytes;
  
  /* We have some work to do: compress the memory buffer,
   * encrypt it, then write to file and close it. use the
   * buffer to recalculate the new keys, update the keyring,
   * free buffer and get out
   */
  
  if (!cdp) {
    vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","cdp is NULL, cannot reclaim %d", chunk_num);
    /* fd = fidsvc_get(cdp->fnp); */
    return -1;
  }
  
  if (!cdp->buffer) {
    vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","tried to reclaim null buffer: %d", chunk_num);
  } else {
    if (!cdp_is_dirty(cdp)) {
      /* just close the file (below) -- no changes */
      vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM","clean chunk close: %d", chunk_num);
    } else {
      unsigned long compressedSize;
      int encryptedSize, errCode;
      unsigned char *compressed, *encrypted, *newkey, *newtag;
      
      compressedSize = 1.002 * chunksize+20;
      compressed = (unsigned char *) malloc(compressedSize);
      if(!compressed) {
	vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","malloc() failed while trying to compress buffer: %d",chunk_num);
	return -1;
      }
      
      errCode = compress2(compressed, &compressedSize, cdp->buffer,
			  chunksize, Z_DEFAULT_COMPRESSION);
      if (errCode != Z_OK) {
	vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","error compressing chunk: %d",chunk_num);
	return -1;
      } 
      
      newkey = digest(compressed, compressedSize);
      vulpes_encrypt(compressed, compressedSize, &encrypted,
		     &encryptedSize, newkey, 20);
      newtag = digest(encrypted, encryptedSize);
      
#ifdef DEBUG
      printf_buffer_stats("LEV1_RECLAIM plaintext", chunk_num, cdp->buffer, chunksize);
      vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM","compressed chunk size %lu for %d",compressed_size,chunk_num);
      printf_buffer_stats("LEV1_RECLAIM encrypted", chunk_num, encrypted, encryptedSize);
#endif

      lev1_updateKey(spec->keyring, newkey, newtag, chunk_num);
      
      errCode = ftruncate(fid, 0);
      if (errCode != 0) {
	vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","ftruncate failed: %d",chunk_num);
	return -1;
      }
      
      lseek(fid, 0, SEEK_SET);
      if(write(fid, encrypted, encryptedSize) != encryptedSize) {
	vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","chunk write failed: %d",chunk_num);
	return -1;
      }

      free(compressed);
      free(newkey);
      free(newtag);
      free(encrypted);

      vulpes_log(LOG_CHUNKS,"LEV1_RECLAIM","dirty chunk close: %d",chunk_num);
    }
  } 
  
  if (close(fid)!=0) {
    err=errno;
    if (err==EBADF)
      vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","close failed ebadf");
    else
      vulpes_log(LOG_ERRORS,"LEV1_RECLAIM","close failed");
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
  int open_readwrite;

  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  chunksPerDir = spec->chunksperdir;

  /* find the dir,chunk numbers */
  chunk_num=get_chunk_number(spec,cmdblk->head.start_sect);
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);
  cdp = &(spec->cd[dir][chunk]);  

  open_readwrite = open_for_writing;
  if(cdp_is_dirty(cdp) && !open_readwrite) {
    open_readwrite = 1;
#ifdef DEBUG
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","changing mode from ro to rw: ",chunk_num);
#endif
  }

  /* if the file is already open, return */
  if (cdp->fnp != NULL_FID_ID) {
    fid = fidsvc_get(cdp->fnp); /* Partho: redundant call, but has side-effects. DO NOT REMOVE */
    /* check if we need the file to be readwrite */
    if (open_readwrite && !cdp_is_rw(cdp)) {
      /* Close the readonly file */
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","failure while attempting to close file and reopen in rw mode");
	return -1;
      }
      
      /* Continue as if we missed the fid cache */
      /* -- Note: this algorithm fouls up the replacement policy of the fid cache */
    } else {
      if (!cdp->buffer) {
	vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","null buffer in cdp: %d",chunk_num);
      }
      return 0;
    }
  }
  
  /* otherwise(file not open), form the cache filename */
  if (form_chunk_file_name(chunk_name, MAX_CHUNK_NAME_LENGTH,
			   map_ptr->cache_name, dir, chunk)) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","unable to form lev1 file name: %d",chunk_num);
    return -1;
  }
  
  /* Check for writes_before_reads */
  if(!cdp_is_accessed(cdp) && open_readwrite)
    ++ writes_before_read;
  
  /* check if we know that the file is present in the cache */
  if (!cdp_present(cdp)) {
    /* check if the file is present anyway */
    if (is_file(chunk_name)) {
      /* the file is present -- set the present flag */
      mark_cdp_present(cdp);
    } else {
      /* the file has not been copied yet */
      char remote_name[MAX_CHUNK_NAME_LENGTH];
      if (form_chunk_file_name(remote_name, MAX_CHUNK_NAME_LENGTH,
	   map_ptr->master_name, dir, chunk)) {
	vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","unable to form lev1 remote name: %d",chunk_num);
	return -1;
      }
      
      if (lev1_copy_file(remote_name, chunk_name, map_ptr, chunk_num) == 0) {
	mark_cdp_present(cdp);
      } else {
	vulpes_log(LOG_ERRORS,"LEV1_COPY_FILE","unable to copy %s %s",remote_name,chunk_name);
	return -1;
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
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","unable to open %s %d",chunk_name,chunk_num);
    return -1;
  }
  vulpes_log(LOG_CHUNKS,"OPEN_CHUNK_FILE","open %s %s %d",(open_readwrite ? "rw" : "ro"),chunk_name,chunk_num);
  
  /* store the fid */
  cdp->fnp = fidsvc_register(fid, lev1_reclaim, spec, chunk_num);
#ifdef DEBUG
  vulpes_log(LOG_CHUNKS,"OPEN_CHUNK_FILE","register spec addr %#08x",(unsigned)spec);
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
  unsigned char *decryptedFile=NULL, *encryptedFile=NULL, 
    *decompressedFile=NULL, *tag=NULL, *key=NULL;
  unsigned fSize;
  unsigned long decompressedSize, compressedSize;
  int size, errCode;
  static unsigned char tag_log[41];
  unsigned char *readPtr ,*writePtr;
  int i;
  
  if((fSize = get_filesize(fid)) == 0) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","Encrypted file size is zero: %d",chunk_num);
    return -1;
  }
  lseek(fid, 0, SEEK_SET);

#ifdef DEBUG
  vulpes_log(LOG_CHUNKS,"OPEN_CHUNK_FILE","compressed chunk size %d %d",fSize,chunk_num);
#endif

  encryptedFile = (unsigned char *) malloc(fSize);
  if (encryptedFile == NULL) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","Could not malloc encrypted file: %d",chunk_num);
    return -1;
  }

  errCode = read(fid, encryptedFile, fSize);
  if (errCode!=fSize) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","Could not read the required number of bytes: %d",chunk_num);
    return -1;
  }

  tag = digest(encryptedFile, fSize);
  
  if (lev1_check_tag(spec->keyring, chunk_num, tag) != LEV1_ENCRYPT_SUCCESS){
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","lev1_check_tag() failed: %d",chunk_num);
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
	vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","expected %s, found %s",s_kr_tag,s_tag);
      } else {
	vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","failed to get kr_tag");
      }
    }
    /* #endif */
    return -1;
  }
  
  if (lev1_get_key(spec->keyring, chunk_num, &key) != LEV1_ENCRYPT_SUCCESS){
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","lev1_get_key() failed: %d",chunk_num);
    return -1;
  }
  
  if (!vulpes_decrypt
      (encryptedFile, fSize, &decryptedFile, &size, key, 20)) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","could not decrypt file into memory: %d",chunk_num);
    return -1;
  };
  writePtr=tag_log; readPtr=tag;
  for(i=0;i<20;i++,readPtr++,writePtr+=2)
    binToHex(readPtr,writePtr);
  *writePtr='\0';

  if (open_readwrite)
    vulpes_log(LOG_KEYS,"OPEN_CHUNK_FILE","w %d %s",chunk_num,tag_log);
  else
    vulpes_log(LOG_KEYS,"OPEN_CHUNK_FILE","r %d %s",chunk_num,tag_log);
  
  free(encryptedFile);
  encryptedFile = NULL;
  
  decompressedFile = NULL;
  decompressedFile = (unsigned char *) malloc(spec->chunksize_bytes);
  if (decompressedFile == NULL) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","could not malloc space for decompressed file: %d",chunk_num);
    return -1;
  }

  compressedSize = size;
  errCode = 0;
  decompressedSize = spec->chunksize_bytes;
  errCode =
    uncompress(decompressedFile, &decompressedSize, decryptedFile,
	       compressedSize);
  if (errCode != Z_OK) {
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","could not decompress file: %d",chunk_num);
    return -1;
  };
  
  if (decompressedSize!=spec->chunksize_bytes) {
    /* Partho: This "error condition" may not be an error in future versions */
    vulpes_log(LOG_ERRORS,"OPEN_CHUNK_FILE","On decompressing, final size is NOT CHUNKSIZE: %d",chunk_num);
    return -1;
  }
  free(decryptedFile);

  cdp->buffer = decompressedFile;

#ifdef DEBUG
    printf_buffer_stats("OPEN_CHUNK_FILE", chunk_num, cdp->buffer, spec->chunksize_bytes);
#endif

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
  result = form_index_name(map_ptr->cache_name, spec);
  
  /* result =  0 means good
   *  result = -1 means error */
  if (result !=0 ) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unable to form lev1 index name");
    return -1;
  }
  
  /* Open index file */
  f = fopen(spec->index_name, "r");
  if (f == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unable to open index file %s",spec->index_name);
    return -1;
  }
  
  /* Scan index file */
  if (fscanf(f, "VERSION= %u\n", &spec->version) != 1) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unable to parse version from index file %s",spec->index_name);
    fclose(f);
    return -1;
  }
  if (spec->version != 1) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unknown lev1 version number: %s",spec->index_name);
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
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","bad parse: %s",spec->index_name);
    result = -1;
  } else {
    unsigned long long tmp_volsize;
    
    /* compute derivative values */
    if (spec->chunksize_bytes % FAUXIDE_HARDSECT_SIZE != 0) {
      vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","bad chunksize: %u",spec->chunksize_bytes);
      result = -1;
    } else {
      spec->chunksize =
	spec->chunksize_bytes / FAUXIDE_HARDSECT_SIZE;
    }
    
    tmp_volsize = spec->chunksize * spec->numchunks;
    if (tmp_volsize > MAX_VOLSIZE_VALUE) {
      vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","lev1 volsize too big: %llu", tmp_volsize);
      result = -1;
    } else {
      spec->volsize = (vulpes_volsize_t) tmp_volsize;
    }
  }
  fclose(f);
  
  /* Check if the cache root directory exists */
  if (!is_dir(map_ptr->cache_name)) {
    vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unable to open dir: %s", map_ptr->cache_name);
    result = -1;
  } else {
    char dirname[MAX_DIRLENGTH];
    unsigned d;
    
    /* check the subdirectories  -- create if needed */
    for (d = 0; d < spec->numdirs; d++) {
      form_dir_name(dirname, MAX_DIRLENGTH, map_ptr->cache_name, d);
      if (!is_dir(dirname)) {
	if (mkdir(dirname, 0770)) {
	  vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unable to mkdir: %s", dirname);
	  result = -1;
	  break;
	}
      }
    }
  }
  
  /* Allocate the fid array */
  spec->cd = malloc(spec->numdirs * sizeof(chunk_data_t *));
  if (spec->cd == NULL)
    {
      vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unable to allocate fid array");
      return -1;
    }
  for (u = 0; u < spec->numdirs; u++) {
    spec->cd[u] = NULL;
  }
  for (u = 0; u < spec->numdirs; u++) {
    spec->cd[u] = malloc(spec->chunksperdir * sizeof(chunk_data_t));
    if (spec->cd[u] == NULL)
      {
	vulpes_log(LOG_ERRORS,"LEV1_OPEN_FUNC","unable to allocate fid array 2");
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
		       map_ptr->cache_name, u, v)) {
		    vulpes_log(LOG_ERRORS,"LEV1_CLOSE_FUNCTION","unable to form lev1 file name");
		    return -1;
		  }
		  vulpes_log(LOG_CHUNKS,"LEV1_CLOSE_FUNCTION","MODIFIEDCLOSE %s",chunk_name);
		}
	      }
	    }
	    if (spec->cd[u][v].fnp != NULL_FID_ID) {
	      if (fidsvc_remove(spec->cd[u][v].fnp)) {
		vulpes_log(LOG_ERRORS,"LEV1_CLOSE","%d %d failed in fidsvc_remove",u,v);
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
    vulpes_log(LOG_ERRORS,"LEV1_CLOSE","lev1_cleanupKeys failed");
    return result;
  }

  /* Print close stats */
  vulpes_log(LOG_STATS,"LEV1_CLOSE_FUNCTION","CHUNKS_ACCESSED:%u",accessed_chunks);
  vulpes_log(LOG_STATS,"LEV1_CLOSE_FUNCTION","CHUNKS_MODIFIED:%u",dirty_chunks);
  vulpes_log(LOG_STATS,"LEV1_CLOSE_FUNCTION","CHUNKS_RAW:%u",writes_before_read);

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
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  /* find the dir,chunk numbers */
  chunk_num=get_chunk_number(spec,cmdblk->head.start_sect);
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);

  if (!one_chunk(spec, cmdblk)) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC","request crosses chunk boundary: %d",chunk_num);
    return -1;
  }
  
  cdp = &(spec->cd[dir][chunk]);

  if (open_chunk_file(map_ptr, cmdblk, 0) != 0) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC","open_chunk_file failed: %d",chunk_num);
    /* if the open returned a failure... cleanup */
    if (cdp->fnp != NULL_FID_ID) {
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC","fidsvc_remove() failed during cleanup");
      }
    }
    return -1;
  };
  
  start = (cmdblk->head.start_sect % spec->chunksize) * FAUXIDE_HARDSECT_SIZE;
  bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
  
  if (start+bytes>spec->chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC","trying to read beyond end of chunk %d",chunk_num);
    return -1;
  }
  
  if (cdp->buffer == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC","cdp buffer is null: %d",chunk_num);
    return -1;
  }

  if(memcpy(cmdblk->buffer, ((unsigned char *) (cdp->buffer)) + start, bytes) == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_READ_FUNC","Could not do a lev1_read. memcpy failed: %d",chunk_num);
    return -1;
  }

  vulpes_log(LOG_FAUXIDE_REQ,"LEV1_READ_FUNC","read: %d",chunk_num);
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
  
  spec = (lev1_mapping_special_t *) map_ptr->special;
  
  /* find the dir,chunk numbers */
  chunk_num=get_chunk_number(spec,cmdblk->head.start_sect);
  get_dir_chunk_from_chunk_num(spec, chunk_num, &dir, &chunk);

  if (!one_chunk(spec, cmdblk)) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC","request crosses chunk boundary: %d",chunk_num);
    return -1;
  }
  
  cdp = &(spec->cd[dir][chunk]);

  if (open_chunk_file(map_ptr, cmdblk, 1) != 0) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC","open_chunk_file failed: %d",chunk_num);
    /* if the open returned a failure... cleanup */
    if (cdp->fnp != NULL_FID_ID) {
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC","fidsvc_remove() failed during cleanup");
      }
    }
    return -1;
  };
  
  start = (cmdblk->head.start_sect % spec->chunksize) * FAUXIDE_HARDSECT_SIZE;
  bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
  
  if (start+bytes>spec->chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC","trying to write beyond end of chunk: %d",chunk_num);
    return -1;
  }
  
  if (cdp->buffer == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC","cdp buffer is null: %d",chunk_num);
    return -1;
  }

  /* Check for writes_before_reads */
  if (!cdp_is_accessed(cdp))
    ++writes_before_read;
  
  mark_cdp_dirty(cdp);
  if (memcpy(((unsigned char *) (cdp->buffer)) + start, cmdblk->buffer, bytes) == 0) {
    vulpes_log(LOG_ERRORS,"LEV1_WRITE_FUNC","memcpy failed: %d",chunk_num);
    return -1;
  }

  vulpes_log(LOG_FAUXIDE_REQ,"LEV1_WRITE_FUNC","write: %d",chunk_num);
  return 0;
}


int initialize_lev1_mapping(vulpes_mapping_t * map_ptr)
{
  lev1_mapping_special_t *spec;
  
  /* Allocate special */
  spec = map_ptr->special = malloc(sizeof(lev1_mapping_special_t));
  if (!map_ptr->special)
    {
      vulpes_log(LOG_ERRORS,"LEV1_INIT","malloc for map_ptr->special failed");
      return -1;
    }
  bzero(map_ptr->special, sizeof(lev1_mapping_special_t));
  
  switch (map_ptr->type) {
  case LEV1_MAPPING:
    break;
  case LEV1V_MAPPING:
    spec->verbose = 1;
    break;
  default:
    free(map_ptr->special);
    map_ptr->special = NULL;
    return -1;
  }
  
  vulpes_log(LOG_BASIC,"LEV1_INIT","vulpes_cache: %s", map_ptr->cache_name);
  if ((map_ptr->proxy_name) && (map_ptr->proxy_port)) {
    vulpes_log(LOG_BASIC,"LEV1_INIT","proxy: %s",map_ptr->proxy_name);
    vulpes_log(LOG_BASIC,"LEV1_INIT","proxy-port: %ld",map_ptr->proxy_port);
  }
  
  map_ptr->open_func = lev1_open_func;
  map_ptr->volsize_func = lev1_volsize_func;
  map_ptr->read_func = lev1_read_func;
  map_ptr->write_func = lev1_write_func;
  map_ptr->close_func = lev1_close_func;
  
  if((spec->keyring = lev1_initEncryption(map_ptr->keyring_name)) == NULL) {
    vulpes_log(LOG_ERRORS,"LEV1_INIT","lev1_initEncryption() failed");
    return -1;	
  }
  
  return 0;
}
