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
#include <netinet/in.h>
#include "fauxide.h"
#include "vulpes_fids.h"
#include "vulpes_lev1_encryption.h"
#include "vulpes_lka.h"
#include "vulpes_log.h"
#include "vulpes_util.h"
#include "vulpes_state.h"
#include <sys/time.h>

#define MAX_INDEX_NAME_LENGTH 256
#define MAX_CHUNK_NAME_LENGTH 512
#define MAX_DIRLENGTH 256

const unsigned CHUNK_STATUS_ACCESSED = 0x0001;	/* This chunk has been accessed this session */
const unsigned CHUNK_STATUS_DIRTY = 0x0002;	/* This chunk has been written this session */
const unsigned CHUNK_STATUS_RW = 0x0200;	/* This chunk was last opened read/write */
const unsigned CHUNK_STATUS_COMPRESSED = 0x1000;/* This chunk is stored compressed */
const unsigned CHUNK_STATUS_LKA_COPY = 0x4000;	/* This chunk data was fetched from the LKA cache */
const unsigned CHUNK_STATUS_PRESENT = 0x8000;	/* This chunk is present in the local cache */
const char *lev1_index_name = "index.lev1";

/* LOCALS */
struct chunk_data {
  fid_id_t fnp;		/* NULL_FID_ID if not currently open */
  unsigned status;
  unsigned char tag[HASH_LEN];	/* was called o2 earlier */
  unsigned char key[HASH_LEN];	/* was called o1 earlier */
  unsigned char *buffer;	/* File is now always read into memory */
};

struct lev1_mapping {
  char index_name[MAX_INDEX_NAME_LENGTH];
  unsigned version;
  unsigned chunksize_bytes;
  unsigned chunksperdir;
  unsigned numchunks;
  unsigned numdirs;
  vulpes_volsize_t volsize;	/* sectors */
  unsigned chunksize;		/* sectors */
  int verbose;
  struct chunk_data *cd;		/* cd[] */
};

static unsigned writes_before_read = 0;

/* AUXILLIARY FUNCTIONS */
static inline int cdp_is_rw(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_RW) == CHUNK_STATUS_RW);
}

static inline int cdp_is_accessed(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_ACCESSED) ==
	  CHUNK_STATUS_ACCESSED);
}

static inline int cdp_is_dirty(struct chunk_data * cdp)
{
  int result;

  result = ((cdp->status & CHUNK_STATUS_DIRTY) == CHUNK_STATUS_DIRTY);

  if(result && !cdp_is_rw(cdp))
    vulpes_debug(LOG_ERRORS,"cdp is dirty but not rw: %#x", cdp->status);
  if(result && !cdp_is_accessed(cdp))
    vulpes_debug(LOG_ERRORS,"cdp is dirty but not accessed: %#x", cdp->status);

  return result;
}

static inline int cdp_is_compressed(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_COMPRESSED) ==
	  CHUNK_STATUS_COMPRESSED);
}

static inline void mark_cdp_accessed(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_ACCESSED;
}

static inline void mark_cdp_dirty(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_DIRTY;
}

static inline void mark_cdp_compressed(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_COMPRESSED;
}

static inline void mark_cdp_uncompressed(struct chunk_data * cdp)
{
  cdp->status &= ~CHUNK_STATUS_COMPRESSED;
}

static inline void mark_cdp_readwrite(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_RW;
}

static inline void mark_cdp_readonly(struct chunk_data * cdp)
{
  cdp->status &= ~CHUNK_STATUS_RW;
}

static inline int cdp_present(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_PRESENT) ==
	  CHUNK_STATUS_PRESENT);
}

static inline int cdp_lka_copy(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_LKA_COPY) ==
	  CHUNK_STATUS_LKA_COPY);
}

static inline void mark_cdp_lka_copy(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_LKA_COPY;
}

static inline void mark_cdp_not_lka_copy(struct chunk_data * cdp)
{
  cdp->status &= ~CHUNK_STATUS_LKA_COPY;
}

static inline unsigned get_chunk_number(unsigned sect_num)
{
  struct lev1_mapping *spec=config.special;
  return sect_num / spec->chunksize;
}

static inline void get_dir_chunk_from_chunk_num(unsigned chunk_num,
                   unsigned *dir, unsigned *chunk)
{
  struct lev1_mapping *spec=config.special;
  *chunk = chunk_num % spec->chunksperdir;
  *dir = chunk_num / spec->chunksperdir;
}


static struct chunk_data *get_cdp_from_chunk_num(unsigned chunk_num)
{
  struct lev1_mapping *spec=config.special;
  return &(spec->cd[chunk_num]);
}


static inline void mark_cdp_present(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_PRESENT;
}

static int form_index_name(const char *dirname)
{
  struct lev1_mapping *spec=config.special;
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

static int one_chunk(const vulpes_cmdblk_t * cmdblk)
{
  unsigned start, end;	/* absolute chunk numbers */
  
  start = get_chunk_number(cmdblk->head.start_sect);
  end = get_chunk_number((cmdblk->head.start_sect + cmdblk->head.num_sect - 1));
  
  return (start == end);
}

static int form_dir_name(char *buffer, int bufsize,
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

static int form_chunk_file_name(char *buffer, int bufsize,
			 const char *rootname, unsigned chunk_num)
{
  int result;
  unsigned dir, chunk;
  
  /* Assume buffer != NULL */
  
  get_dir_chunk_from_chunk_num(chunk_num, &dir, &chunk);
  result=snprintf(buffer, bufsize, "%s/%04u/%04u", rootname, dir, chunk);
  if (result >= bufsize || result == -1) {
    /* Older versions of libc return -1 on truncation */
    return -1;
  }
  return 0;
}

#ifdef DEBUG
static void 
debug_buffer_stats(const char *msg, unsigned index, const unsigned char *buf, unsigned bufsize)
{
  unsigned char *bufhash;
  unsigned char s_bufhash[HASH_LEN_HEX];

  bufhash=digest(buf, bufsize);
  binToHex(bufhash, s_bufhash, HASH_LEN);
  free(bufhash);

  vulpes_log(LOG_CHUNKS,"%s: buffer indx: %u", msg, index);
  vulpes_log(LOG_CHUNKS,"%s: buffer addr: %#08x", msg, (unsigned)buf);
  vulpes_log(LOG_CHUNKS,"%s: buffer size: %u", msg, bufsize);
  vulpes_log(LOG_CHUNKS,"%s: buffer hash: %s", msg, s_bufhash);
}
#else
#define debug_buffer_stats(msg, idx, buf, sz) do {} while (0)
#endif

/* reads the hex keyring file into memory */
/* hex file format: "<tag> <key>\n" (82 bytes/line including newline) */
vulpes_err_t read_hex_keyring(char *userPath)
{
	struct lev1_mapping *spec=config.special;
	unsigned chunk_num;
	int fd;
	struct chunk_data *cdp;
	char buf[HASH_LEN_HEX];
	
	fd = open(userPath, O_RDONLY);
	if (fd < 0) {
		vulpes_log(LOG_ERRORS,"could not open keyring: %s",userPath);
		return VULPES_IOERR;
	}
	for (chunk_num=0; chunk_num < spec->numchunks; chunk_num++) {
		cdp=get_cdp_from_chunk_num(chunk_num);
		if (read(fd, buf, HASH_LEN_HEX) != HASH_LEN_HEX)
			goto short_read;
		hexToBin(buf, cdp->tag, HASH_LEN);
		if (read(fd, buf, HASH_LEN_HEX) != HASH_LEN_HEX)
			goto short_read;
		hexToBin(buf, cdp->key, HASH_LEN);
		mark_cdp_compressed(cdp);
	}
	if (!at_eof(fd)) {
		vulpes_log(LOG_ERRORS,"too much data in keyring %s",userPath);
		return VULPES_IOERR;
	}
	close(fd);
	vulpes_log(LOG_BASIC,"read hex keyring %s: %d keys",userPath,spec->numchunks);
	return VULPES_SUCCESS;
	
short_read:
	vulpes_log(LOG_ERRORS,"I/O error reading key from %s for chunk %d",userPath,chunk_num);
	return VULPES_IOERR;
}

/* converts to hex, writes */
static vulpes_err_t write_hex_keyring(char *userPath)
{
	struct lev1_mapping *spec=config.special;
	unsigned chunk_num;
	struct chunk_data *cdp;
	int fd;
	char buf[HASH_LEN_HEX];
	
	fd = open(userPath, O_WRONLY|O_TRUNC, 0600);
	if (fd < 0) {
		vulpes_log(LOG_ERRORS,"could not open keyring file for writeback: %s", userPath);
		return VULPES_IOERR;
	}
	for (chunk_num=0; chunk_num < spec->numchunks; chunk_num++) {
		cdp=get_cdp_from_chunk_num(chunk_num);
		binToHex(cdp->tag, buf, HASH_LEN);
		buf[HASH_LEN_HEX - 1]=' ';
		if (write(fd, buf, HASH_LEN_HEX) != HASH_LEN_HEX)
			goto short_write;
		binToHex(cdp->key, buf, HASH_LEN);
		buf[HASH_LEN_HEX - 1]='\n';
		if (write(fd, buf, HASH_LEN_HEX) != HASH_LEN_HEX)
			goto short_write;
	}
	close(fd);
	vulpes_log(LOG_BASIC,"wrote hex keyring %s: %d keys",userPath,spec->numchunks);
	return VULPES_SUCCESS;
	
short_write:
	vulpes_log(LOG_ERRORS,"failure writing keyring file: %s",userPath);
	close(fd);
	return VULPES_IOERR;
}

static vulpes_err_t read_bin_keyring(char *path)
{
  struct lev1_mapping *spec=config.special;
  struct chunk_data *cdp;
  struct kr_header hdr;
  struct kr_entry entry;
  int fd;
  unsigned chunk_num;
  
  fd=open(path, O_RDONLY);
  if (fd == -1 && errno == ENOENT)
    return VULPES_NOTFOUND;
  else if (fd == -1)
    return VULPES_IOERR;
  
  if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
    goto short_read;
  if (ntohl(hdr.magic) != KR_MAGIC) {
    vulpes_log(LOG_ERRORS, "Invalid magic number reading %s", path);
    return VULPES_BADFORMAT;
  }
  if (hdr.version != KR_VERSION) {
    vulpes_log(LOG_ERRORS, "Invalid version reading %s: expected %d, found %d", path, KR_VERSION, hdr.version);
    return VULPES_BADFORMAT;
  }
  if (ntohl(hdr.entries) != spec->numchunks) {
    vulpes_log(LOG_ERRORS, "Invalid chunk count reading %s: expected %u, found %u", path, spec->numchunks, htonl(hdr.entries));
    return VULPES_BADFORMAT;
  }
  
  for (chunk_num=0; chunk_num < spec->numchunks; chunk_num++) {
    if (read(fd, &entry, sizeof(entry)) != sizeof(entry))
      goto short_read;
    cdp=get_cdp_from_chunk_num(chunk_num);
    memcpy(cdp->key, entry.key, HASH_LEN);
    memcpy(cdp->tag, entry.tag, HASH_LEN);
    if (entry.compress == KR_COMPRESS_NONE)
      mark_cdp_uncompressed(cdp);
    else
      mark_cdp_compressed(cdp);
  }
  if (!at_eof(fd)) {
    vulpes_log(LOG_ERRORS, "Extra data at end of file: %s", path);
    return VULPES_IOERR;
  }
  close(fd);
  vulpes_log(LOG_BASIC, "read bin keyring %s: %d keys", path, spec->numchunks);
  return VULPES_SUCCESS;
  
short_read:
  vulpes_log(LOG_ERRORS, "Couldn't read %s", path);
  close(fd);
  return VULPES_IOERR;
}

static vulpes_err_t write_bin_keyring(char *path)
{
  struct lev1_mapping *spec=config.special;
  struct chunk_data *cdp;
  struct kr_header hdr;
  struct kr_entry entry;
  int fd;
  unsigned chunk_num;
  
  fd=open(path, O_CREAT|O_TRUNC|O_WRONLY, 0600);
  if (fd == -1)
    return VULPES_IOERR;
  
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic=htonl(KR_MAGIC);
  hdr.entries=htonl(spec->numchunks);
  hdr.version=KR_VERSION;
  if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
    goto short_write;
  
  memset(&entry, 0, sizeof(entry));
  for (chunk_num=0; chunk_num < spec->numchunks; chunk_num++) {
    cdp=get_cdp_from_chunk_num(chunk_num);
    memcpy(entry.key, cdp->key, HASH_LEN);
    memcpy(entry.tag, cdp->tag, HASH_LEN);
    entry.compress=cdp_is_compressed(cdp) ? KR_COMPRESS_ZLIB : KR_COMPRESS_NONE;
    if (write(fd, &entry, sizeof(entry)) != sizeof(entry))
      goto short_write;
  }
  close(fd);
  vulpes_log(LOG_BASIC, "wrote bin keyring %s: %d keys", path, spec->numchunks);
  return VULPES_SUCCESS;
  
short_write:
  vulpes_log(LOG_ERRORS, "Couldn't write %s", path);
  close(fd);
  return VULPES_IOERR;
}

static void lev1_updateKey(unsigned chunk_num, unsigned char new_key[HASH_LEN],
                           unsigned char new_tag[HASH_LEN])
{
  struct chunk_data *cdp;
  unsigned char old_tag_log[HASH_LEN_HEX], tag_log[HASH_LEN_HEX];

  cdp=get_cdp_from_chunk_num(chunk_num);
  binToHex(cdp->tag, old_tag_log, HASH_LEN);
  binToHex(new_tag, tag_log, HASH_LEN);

  if (strcmp(old_tag_log,tag_log)!=0)
    vulpes_log(LOG_KEYS,"%d %s %s",chunk_num,old_tag_log,tag_log);
  
  memcpy(cdp->tag, new_tag, HASH_LEN);
  memcpy(cdp->key, new_key, HASH_LEN);
}

static vulpes_err_t lev1_check_tag(struct chunk_data *cdp,
                                   const unsigned char *tag)
{
  return (memcmp(cdp->tag, tag, HASH_LEN) == 0) ? VULPES_SUCCESS : VULPES_TAGFAIL;
}

static void print_tag_check_error(unsigned char *expected, unsigned char *found)
{
  unsigned char s_expected[HASH_LEN_HEX];
  unsigned char s_found[HASH_LEN_HEX];
  binToHex(expected, s_expected, HASH_LEN);
  binToHex(found, s_found, HASH_LEN);
  vulpes_log(LOG_ERRORS,"expected %s, found %s",s_expected,s_found);
}

static int valid_chunk_buffer(const unsigned char *buffer, unsigned bufsize, 
		  unsigned chunk_num)
{
  int bufvalid = 0;
  unsigned char *dgst; /* hash of the buffer contents - malloc'ed by digest */
  struct chunk_data *cdp;
  
  cdp=get_cdp_from_chunk_num(chunk_num);
  dgst = digest(buffer, bufsize);
  bufvalid = (lev1_check_tag(cdp, dgst) == VULPES_SUCCESS);
  if (!bufvalid)
    print_tag_check_error(cdp->tag, dgst);
  
  free(dgst);

  return bufvalid;
}

static int lev1_copy_file(const char *src, const char *dst, unsigned chunk_num)
{
  struct lev1_mapping *spec=config.special;
  char *buf;
  int buflen;
  int fd;
  vulpes_err_t err;
  struct chunk_data *cdp;
  
  buflen=1.002*spec->chunksize_bytes+20;
  buf=malloc(buflen);
  if (buf == NULL) {
    vulpes_log(LOG_TRANSPORT,"malloc failed");
    return -1;
  }
  cdp=get_cdp_from_chunk_num(chunk_num);
  
  /* first check the lka database(s) */
  /* XXX clean this up */
  if(config.lka_svc != NULL) {
    char *lka_src_file;

#ifdef DEBUG
    {
      unsigned char s_bufhash[HASH_LEN_HEX];
      binToHex(cdp->tag, s_bufhash, HASH_LEN);
      vulpes_log(LOG_CHUNKS,"lka lookup tag: %s", s_bufhash);	  
    }
#endif

    err = vulpes_lka_lookup(LKA_TAG_SHA1, cdp->tag, buf, &buflen, &lka_src_file);
    if(err == VULPES_SUCCESS) {
      if(valid_chunk_buffer(buf, buflen, chunk_num)) {
	/* LKA hit */
	struct chunk_data *cdp;
	
	vulpes_log(LOG_CHUNKS,"lka lookup hit for %s",dst);	  
	cdp = get_cdp_from_chunk_num(chunk_num);
	mark_cdp_lka_copy(cdp);
      } else {
	/* Tag check failure */
	vulpes_log(LOG_ERRORS, "SERIOUS, NON-FATAL ERROR - lka lookup hit from %s failed tag match for %s",
		   ((lka_src_file == NULL) ? "<src>" : lka_src_file), 
		   dst);
	err = VULPES_IOERR;
      }

      /* free the source name buffer */
      if(lka_src_file != NULL) free(lka_src_file);

      if(err == VULPES_SUCCESS) goto have_data;
      /* else, fall through */
    } else {
      /* LKA miss */
      vulpes_log(LOG_CHUNKS,"lka lookup miss for %s", dst);
    }
  }
  
  vulpes_log(LOG_TRANSPORT,"begin_transport: %s %s",src,dst);
  switch (config.trxfer) {
  case LOCAL_TRANSPORT:
    err=local_get(buf, &buflen, src);
    break;
  case HTTP_TRANSPORT:
    err=http_get(buf, &buflen, src);
    break;
  default:
    vulpes_log(LOG_ERRORS,"unknown transport");
    err=VULPES_INVALID;
  }
  vulpes_log(LOG_TRANSPORT,"end_transport: %s %s",src,dst);
  if (err) {
    goto out;
  }
  /* buflen has been updated with the length of the data */
  
  /* check retrieved data for validity */
  if(!valid_chunk_buffer(buf, buflen, chunk_num)) {
    vulpes_log(LOG_ERRORS,"failure: %s buffer not valid",src);
    err=VULPES_IOERR;
    goto out;
  }

have_data:
  /* open destination cache file */
  /* XXX O_EXCL? */
  if ((fd=open(dst, O_CREAT|O_TRUNC|O_WRONLY,0660)) == -1) {
    vulpes_log(LOG_ERRORS,"unable to open output %s",dst);
    err=VULPES_IOERR;
    goto out;
  }
  
  /* write to cache */
  if(write(fd, buf, buflen) != buflen) {
      vulpes_log(LOG_ERRORS,"unable to write output %s",dst);
      /* delete the cache file */
      close(fd);
      if(unlink(dst)) {
	/* this is really serious. we've put a bad file in the cache 
	   and can't remove it.
	   XXX: ensure that we shut down from here */
	vulpes_log(LOG_ERRORS,
		   "!!! unlink failure!!!: unable to unlink output %s",dst);
      }
      err=VULPES_IOERR;
  }
  close(fd);
  vulpes_log(LOG_TRANSPORT,"end: %s %s",src,dst);
  
out:
  free(buf);
  return err ? -1 : 0;
}

int lev1_reclaim(fid_t fid, void *data, int chunk_num)
{
  struct chunk_data *cdp;
  int err;
  struct lev1_mapping *spec;
  unsigned chunksize;
  
  vulpes_debug(LOG_CHUNKS,"received spec addr: %#08x",(unsigned)data);

  spec = (struct lev1_mapping *) data;
  
  cdp = get_cdp_from_chunk_num(chunk_num);
  
  chunksize = spec->chunksize_bytes;
  
  /* We have some work to do: compress the memory buffer,
   * encrypt it, then write to file and close it. use the
   * buffer to recalculate the new keys, update the keyring,
   * free buffer and get out
   */
  
  if (!cdp) {
    vulpes_log(LOG_ERRORS,"cdp is NULL, cannot reclaim %d", chunk_num);
    /* fd = fidsvc_get(cdp->fnp); */
    return -1;
  }
  
  if (!cdp->buffer) {
    vulpes_log(LOG_ERRORS,"tried to reclaim null buffer: %d", chunk_num);
  } else {
    if (!cdp_is_dirty(cdp)) {
      /* just close the file (below) -- no changes */
      vulpes_log(LOG_CHUNKS,"clean chunk close: %d", chunk_num);
    } else {
      unsigned long compressedSize;
      unsigned encryptSize;
      int encryptedSize;
      unsigned char *compressed, *toEncrypt, *encrypted, *newkey, *newtag;
      
      compressedSize = 1.002 * chunksize+20;
      compressed = malloc(compressedSize);
      if(!compressed) {
	vulpes_log(LOG_ERRORS,"malloc() failed while trying to compress buffer: %d",chunk_num);
	return -1;
      }
      
      if (compress2(compressed, &compressedSize, cdp->buffer,
			  chunksize, Z_DEFAULT_COMPRESSION) != Z_OK) {
	vulpes_log(LOG_ERRORS,"error compressing chunk: %d",chunk_num);
	return -1;
      }
      
      /* The fudge factor takes into account padding that might be necessary
         during crypto, which should never reach twice the cipher blocksize */
      if (compressedSize > chunksize - 16) {
	mark_cdp_uncompressed(cdp);
	toEncrypt=cdp->buffer;
	encryptSize=chunksize;
	vulpes_log(LOG_CHUNKS,"Storing uncompressed: %u",chunk_num);
      } else {
	mark_cdp_compressed(cdp);
	toEncrypt=compressed;
	encryptSize=compressedSize;
      }
      
      newkey = digest(toEncrypt, encryptSize);
      vulpes_encrypt(toEncrypt, encryptSize, &encrypted,
		     &encryptedSize, newkey, HASH_LEN, cdp_is_compressed(cdp));
      newtag = digest(encrypted, encryptedSize);
      
      debug_buffer_stats("Reclaim plaintext", chunk_num, cdp->buffer, chunksize);
      vulpes_debug(LOG_CHUNKS,"compressed chunk size %lu for %d",compressed_size,chunk_num);
      debug_buffer_stats("Reclaim encrypted", chunk_num, encrypted, encryptedSize);

      lev1_updateKey(chunk_num, newkey, newtag);
      
      if (ftruncate(fid, 0) != 0) {
	vulpes_log(LOG_ERRORS,"ftruncate failed: %d",chunk_num);
	return -1;
      }
      
      lseek(fid, 0, SEEK_SET);
      if(write(fid, encrypted, encryptedSize) != encryptedSize) {
	vulpes_log(LOG_ERRORS,"chunk write failed: %d",chunk_num);
	return -1;
      }

      free(compressed);
      free(newkey);
      free(newtag);
      free(encrypted);

      vulpes_log(LOG_CHUNKS,"dirty chunk close: %d",chunk_num);
    }
  } 
  
  if (close(fid)!=0) {
    err=errno;
    if (err==EBADF)
      vulpes_log(LOG_ERRORS,"close failed ebadf");
    else
      vulpes_log(LOG_ERRORS,"close failed");
  }

  /* clean up the cdp */
  cdp->fnp = NULL_FID_ID;
  if (cdp->buffer != NULL) {
    free(cdp->buffer);
    cdp->buffer = NULL;
  }
  
  return 0;
}


/* Sets up the buffers - which essentially means that
 * we decrypt the file, decompress it and read it into
 * memory
 */
/* returns 0 if okay else -1 on bad exit */
static int open_chunk_file(const vulpes_cmdblk_t * cmdblk, int open_for_writing)
{
  char chunk_name[MAX_CHUNK_NAME_LENGTH];
  struct lev1_mapping *spec=config.special;
  unsigned chunk_num;
  int chunksPerDir;
  fid_t fid;
  struct chunk_data *cdp;
  int open_readwrite;
  unsigned char *decryptedFile=NULL, *encryptedFile=NULL, 
    *decompressedFile=NULL, *tag=NULL;
  unsigned fSize;
  unsigned long decompressedSize, compressedSize;
  int size;
  static unsigned char tag_log[HASH_LEN_HEX];
  
  chunksPerDir = spec->chunksperdir;

  chunk_num=get_chunk_number(cmdblk->head.start_sect);
  cdp = get_cdp_from_chunk_num(chunk_num);

  open_readwrite = open_for_writing;
  if(cdp_is_dirty(cdp) && !open_readwrite) {
    open_readwrite = 1;
    vulpes_debug(LOG_ERRORS,"changing mode from ro to rw: %u",chunk_num);
  }

  /* if the file is already open, return */
  if (cdp->fnp != NULL_FID_ID) {
    fid = fidsvc_get(cdp->fnp); /* Partho: redundant call, but has side-effects. DO NOT REMOVE */
    /* check if we need the file to be readwrite */
    if (open_readwrite && !cdp_is_rw(cdp)) {
      /* Close the readonly file */
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"failure while attempting to close file and reopen in rw mode");
	return -1;
      }
      
      /* Continue as if we missed the fid cache */
      /* -- Note: this algorithm fouls up the replacement policy of the fid cache */
    } else {
      if (!cdp->buffer) {
	vulpes_log(LOG_ERRORS,"null buffer in cdp: %d",chunk_num);
      }
      return 0;
    }
  }
  
  /* otherwise(file not open), form the cache filename */
  if (form_chunk_file_name(chunk_name, MAX_CHUNK_NAME_LENGTH,
			   config.cache_name, chunk_num)) {
    vulpes_log(LOG_ERRORS,"unable to form lev1 file name: %d",chunk_num);
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
	   config.master_name, chunk_num)) {
	vulpes_log(LOG_ERRORS,"unable to form lev1 remote name: %d",chunk_num);
	return -1;
      }
      
      if (lev1_copy_file(remote_name, chunk_name, chunk_num) == 0) {
	mark_cdp_present(cdp);
      } else {
	vulpes_log(LOG_ERRORS,"unable to copy %s %s",remote_name,chunk_name);
	return -1;
      }
    }
  }
  
  /* open the file */
  if (open_readwrite)
    fid = open(chunk_name,  O_RDWR);
  else
    fid = open(chunk_name,  O_RDONLY);
  if (fid < 0) {
    vulpes_log(LOG_ERRORS,"unable to open %s %d",chunk_name,chunk_num);
    return -1;
  }
  vulpes_log(LOG_CHUNKS,"open %s %s %d",(open_readwrite ? "rw" : "ro"),chunk_name,chunk_num);
  
  /* store the fid */
  cdp->fnp = fidsvc_register(fid, lev1_reclaim, spec, chunk_num);
  vulpes_debug(LOG_CHUNKS,"register spec addr %#08x",(unsigned)spec);

  /* Assume that the file will be read and written according to open_readwrite */
  mark_cdp_accessed(cdp);
  if (open_readwrite) {
    mark_cdp_readwrite(cdp);
  } else {
    mark_cdp_readonly(cdp);
  }
  
  /* Set up the buffer, decrypt using the key and then decompress it */
  if((fSize = get_filesize(fid)) == 0) {
    vulpes_log(LOG_ERRORS,"Encrypted file size is zero: %d",chunk_num);
    return -1;
  }
  lseek(fid, 0, SEEK_SET);

  vulpes_debug(LOG_CHUNKS,"compressed chunk size %d %d",fSize,chunk_num);

  encryptedFile = (unsigned char *) malloc(fSize);
  if (encryptedFile == NULL) {
    vulpes_log(LOG_ERRORS,"Could not malloc encrypted file: %d",chunk_num);
    return -1;
  }

  if (read_file(fid, encryptedFile, &fSize)) {
    vulpes_log(LOG_ERRORS,"Could not read the required number of bytes: %d",chunk_num);
    return -1;
  }

  tag = digest(encryptedFile, fSize);
  if (lev1_check_tag(cdp, tag) != VULPES_SUCCESS){
    vulpes_log(LOG_ERRORS,"lev1_check_tag() failed: %d",chunk_num);
    print_tag_check_error(cdp->tag, tag);
    free(tag);
    return -1;
  }
  binToHex(tag, tag_log, HASH_LEN);
  free(tag);
  tag=NULL;
  
  if (!vulpes_decrypt(encryptedFile, fSize, &decryptedFile, &size,
                      cdp->key, HASH_LEN, cdp_is_compressed(cdp))) {
    vulpes_log(LOG_ERRORS,"could not decrypt file into memory: %d",chunk_num);
    return -1;
  };
  
  if (open_readwrite)
    vulpes_log(LOG_KEYS,"w %d %s",chunk_num,tag_log);
  else
    vulpes_log(LOG_KEYS,"r %d %s",chunk_num,tag_log);
  
  free(encryptedFile);
  encryptedFile = NULL;
  
  if (cdp_is_compressed(cdp)) {
    decompressedFile = malloc(spec->chunksize_bytes);
    if (decompressedFile == NULL) {
      vulpes_log(LOG_ERRORS,"could not malloc space for decompressed file: %d",chunk_num);
      return -1;
    }
  
    compressedSize = size;
    decompressedSize = spec->chunksize_bytes;
    if (uncompress(decompressedFile, &decompressedSize, decryptedFile,
		 compressedSize) != Z_OK) {
      vulpes_log(LOG_ERRORS,"could not decompress file: %d",chunk_num);
      return -1;
    };
    
    if (decompressedSize!=spec->chunksize_bytes) {
      vulpes_log(LOG_ERRORS,"On decompressing, final size is NOT CHUNKSIZE: %d",chunk_num);
      return -1;
    }
    free(decryptedFile);
  
    cdp->buffer = decompressedFile;
  } else {
    vulpes_log(LOG_CHUNKS,"Reading uncompressed chunk: %u", chunk_num);
    if (size != spec->chunksize_bytes) {
      vulpes_log(LOG_ERRORS,"Chunk stored uncompressed is not %u bytes: %u",spec->chunksize_bytes,chunk_num);
      return -1;
    }
    cdp->buffer = decryptedFile;
  }

  debug_buffer_stats("Open", chunk_num, cdp->buffer, spec->chunksize_bytes);

  return 0;
}

/* INTERFACE FUNCTIONS */

vulpes_volsize_t lev1_volsize_func(void)
{
  struct lev1_mapping *spec=config.special;
  return spec->volsize;
}

int lev1_shutdown_func(void)
{
  char chunk_name[MAX_CHUNK_NAME_LENGTH];
  struct lev1_mapping *spec=config.special;
  unsigned u;
  
  unsigned dirty_chunks = 0;
  unsigned accessed_chunks = 0;
  
  
  if (spec != NULL) {
    /* deallocate the fnp array */
    if (spec->cd != NULL) {
      for (u = 0; u < spec->numchunks; u++) {
	if (cdp_is_accessed(&(spec->cd[u]))) {
	  ++accessed_chunks;
	  if (cdp_is_dirty(&(spec->cd[u]))) {
	    ++dirty_chunks;
	    if (spec->verbose) {
	      if (form_chunk_file_name(chunk_name, MAX_CHUNK_NAME_LENGTH,
		   config.cache_name, u)) {
		vulpes_log(LOG_ERRORS,"unable to form lev1 file name");
		return -1;
	      }
	      vulpes_log(LOG_CHUNKS,"MODIFIEDCLOSE %s",chunk_name);
	    }
	  }
	}
	if (spec->cd[u].fnp != NULL_FID_ID) {
	  if (fidsvc_remove(spec->cd[u].fnp)) {
	    vulpes_log(LOG_ERRORS,"%d failed in fidsvc_remove",u);
	    return -1;
	  }
	}
      }
      if (write_bin_keyring(config.bin_keyring_name)) {
	vulpes_log(LOG_ERRORS,"write_bin_keyring failed");
	return -1;
      }
      if (write_hex_keyring(config.hex_keyring_name)) {
	vulpes_log(LOG_ERRORS,"write_hex_keyring failed");
	return -1;
      }
      free(spec->cd);
      spec->cd = NULL;
    }
    config.special = NULL;
    free(spec);
  }
  
  /* Print close stats */
  vulpes_log(LOG_STATS,"CHUNKS_ACCESSED:%u",accessed_chunks);
  vulpes_log(LOG_STATS,"CHUNKS_MODIFIED:%u",dirty_chunks);
  vulpes_log(LOG_STATS,"CHUNKS_RAW:%u",writes_before_read);

  return 0;
}

int lev1_read_func(vulpes_cmdblk_t * cmdblk)
{
  struct lev1_mapping *spec=config.special;
  off_t start;
  ssize_t bytes;
  struct chunk_data *cdp=NULL;
  unsigned chunk_num;
  
  chunk_num=get_chunk_number(cmdblk->head.start_sect);

  if (!one_chunk(cmdblk)) {
    vulpes_log(LOG_ERRORS,"request crosses chunk boundary: %d",chunk_num);
    return -1;
  }
  
  cdp = get_cdp_from_chunk_num(chunk_num);

  if (open_chunk_file(cmdblk, 0) != 0) {
    vulpes_log(LOG_ERRORS,"open_chunk_file failed: %d",chunk_num);
    /* if the open returned a failure... cleanup */
    if (cdp->fnp != NULL_FID_ID) {
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"fidsvc_remove() failed during cleanup");
      }
    }
    return -1;
  };
  
  start = (cmdblk->head.start_sect % spec->chunksize) * FAUXIDE_HARDSECT_SIZE;
  bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
  
  if (start+bytes>spec->chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"trying to read beyond end of chunk %d",chunk_num);
    return -1;
  }
  
  if (cdp->buffer == NULL) {
    vulpes_log(LOG_ERRORS,"cdp buffer is null: %d",chunk_num);
    return -1;
  }

  memcpy(cmdblk->buffer, cdp->buffer + start, bytes);

  vulpes_log(LOG_FAUXIDE_REQ,"read: %d",chunk_num);
  return 0;
}

int lev1_write_func(const vulpes_cmdblk_t * cmdblk)
{
  struct lev1_mapping *spec=config.special;
  off_t start;
  ssize_t bytes;
  struct chunk_data *cdp=NULL;
  unsigned chunk_num;
  
  chunk_num=get_chunk_number(cmdblk->head.start_sect);

  if (!one_chunk(cmdblk)) {
    vulpes_log(LOG_ERRORS,"request crosses chunk boundary: %d",chunk_num);
    return -1;
  }
  
  cdp = get_cdp_from_chunk_num(chunk_num);

  if (open_chunk_file(cmdblk, 1) != 0) {
    vulpes_log(LOG_ERRORS,"open_chunk_file failed: %d",chunk_num);
    /* if the open returned a failure... cleanup */
    if (cdp->fnp != NULL_FID_ID) {
      if (fidsvc_remove(cdp->fnp)) {
	vulpes_log(LOG_ERRORS,"fidsvc_remove() failed during cleanup");
      }
    }
    return -1;
  };
  
  start = (cmdblk->head.start_sect % spec->chunksize) * FAUXIDE_HARDSECT_SIZE;
  bytes = cmdblk->head.num_sect * FAUXIDE_HARDSECT_SIZE;
  
  if (start+bytes>spec->chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"trying to write beyond end of chunk: %d",chunk_num);
    return -1;
  }
  
  if (cdp->buffer == NULL) {
    vulpes_log(LOG_ERRORS,"cdp buffer is null: %d",chunk_num);
    return -1;
  }

  /* Check for writes_before_reads */
  if (!cdp_is_accessed(cdp))
    ++writes_before_read;
  
  mark_cdp_dirty(cdp);
  memcpy(cdp->buffer + start, cmdblk->buffer, bytes);

  vulpes_log(LOG_FAUXIDE_REQ,"write: %d",chunk_num);
  return 0;
}


int initialize_lev1_mapping(void)
{
  struct lev1_mapping *spec;
  unsigned long long volsize_bytes;
  unsigned long long tmp_volsize;
  int parse_error = 0;
  FILE *f;
  unsigned u;
  char dirname[MAX_DIRLENGTH];
  
  /* Allocate special */
  spec = config.special = malloc(sizeof(struct lev1_mapping));
  if (!config.special) {
    vulpes_log(LOG_ERRORS,"malloc for config.special failed");
    return -1;
  }
  bzero(config.special, sizeof(struct lev1_mapping));
  
  switch (config.mapping) {
  case LEV1_MAPPING:
    break;
  case LEV1V_MAPPING:
    spec->verbose = 1;
    break;
  default:
    free(config.special);
    config.special = NULL;
    return -1;
  }
  
  vulpes_log(LOG_BASIC,"vulpes_cache: %s", config.cache_name);
  if ((config.proxy_name) && (config.proxy_port)) {
    vulpes_log(LOG_BASIC,"proxy: %s",config.proxy_name);
    vulpes_log(LOG_BASIC,"proxy-port: %ld",config.proxy_port);
  }
  
  if (form_index_name(config.cache_name)) {
    vulpes_log(LOG_ERRORS,"unable to form lev1 index name");
    return -1;
  }
  
  /* Open index file */
  f = fopen(spec->index_name, "r");
  if (f == NULL) {
    vulpes_log(LOG_ERRORS,"unable to open index file %s",spec->index_name);
    return -1;
  }
  
  /* Scan index file */
  if (fscanf(f, "VERSION= %u\n", &spec->version) != 1) {
    vulpes_log(LOG_ERRORS,"unable to parse version from index file %s",spec->index_name);
    fclose(f);
    return -1;
  }
  if (spec->version != 1) {
    vulpes_log(LOG_ERRORS,"unknown lev1 version number: %s",spec->index_name);
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
  
  fclose(f);
  if (parse_error) {
    vulpes_log(LOG_ERRORS,"bad parse: %s",spec->index_name);
    return -1;
  }
  
  /* compute derivative values */
  if (spec->chunksize_bytes % FAUXIDE_HARDSECT_SIZE != 0) {
    vulpes_log(LOG_ERRORS,"bad chunksize: %u",spec->chunksize_bytes);
    return -1;
  }
  spec->chunksize = spec->chunksize_bytes / FAUXIDE_HARDSECT_SIZE;
  
  tmp_volsize = spec->chunksize * spec->numchunks;
  if (tmp_volsize > MAX_VOLSIZE_VALUE) {
    vulpes_log(LOG_ERRORS,"lev1 volsize too big: %llu", tmp_volsize);
    return -1;
  }
  spec->volsize = (vulpes_volsize_t) tmp_volsize;
  
  /* Check if the cache root directory exists */
  if (!is_dir(config.cache_name)) {
    vulpes_log(LOG_ERRORS,"unable to open dir: %s", config.cache_name);
    return -1;
  }
  
  /* check the subdirectories  -- create if needed */
  for (u = 0; u < spec->numdirs; u++) {
    form_dir_name(dirname, MAX_DIRLENGTH, config.cache_name, u);
    if (!is_dir(dirname)) {
      if (mkdir(dirname, 0770)) {
	vulpes_log(LOG_ERRORS,"unable to mkdir: %s", dirname);
	return -1;
      }
    }
  }
  
  /* Allocate the chunk_data array */
  spec->cd = malloc(spec->numchunks * sizeof(struct chunk_data));
  if (spec->cd == NULL) {
    vulpes_log(LOG_ERRORS,"unable to allocate chunk_data array");
    return -1;
  }
  memset(spec->cd, 0, spec->numchunks * sizeof(struct chunk_data));
  for (u = 0; u < spec->numchunks; u++) {
    spec->cd[u].fnp = NULL_FID_ID;
  }
  
  switch (read_bin_keyring(config.bin_keyring_name)) {
  case VULPES_SUCCESS:
    break;
  case VULPES_NOTFOUND:
    vulpes_log(LOG_BASIC, "Couldn't read binary keyring; trying hex keyring");
    if (read_hex_keyring(config.hex_keyring_name)) {
      vulpes_log(LOG_ERRORS,"read_hex_keyring() failed");
      return -1;	
    }
    break;
  default:
    vulpes_log(LOG_ERRORS,"read_bin_keyring() failed");
    return -1;	
  }
  
  config.volsize_func = lev1_volsize_func;
  config.read_func = lev1_read_func;
  config.write_func = lev1_write_func;
  config.shutdown_func = lev1_shutdown_func;
  
  return 0;
}
