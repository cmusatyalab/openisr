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
#include "vulpes.h"
#include "vulpes_crypto.h"
#include "vulpes_lka.h"
#include "vulpes_log.h"
#include "vulpes_util.h"
#include "vulpes_state.h"
#include "convergent-user.h"
#include <sys/time.h>

const unsigned CHUNK_STATUS_ACCESSED = 0x0001;	/* This chunk has been accessed this session */
const unsigned CHUNK_STATUS_MODIFIED_SESSION = 0x0004; /* This chunk has been modified this session */
const unsigned CHUNK_STATUS_MODIFIED = 0x0008;  /* This chunk has been modified since cache creation */
const unsigned CHUNK_STATUS_COMPRESSED = 0x1000;/* This chunk is stored compressed */
const unsigned CHUNK_STATUS_PRESENT = 0x8000;	/* This chunk is present in the local cache */
const char *index_name = "index.lev1";
const char *image_name = "image.lev1";

/* LOCALS */
struct chunk_data {
  unsigned length;
  unsigned status;
  unsigned char tag[HASH_LEN];	/* was called o2 earlier */
  unsigned char key[HASH_LEN];	/* was called o1 earlier */
};

/* We keep this in a separate array because we don't want it in memory
   at runtime. */
struct prev_chunk_data {
  unsigned char tag[HASH_LEN];
};

static unsigned writes_before_read = 0;
static unsigned chunks_stripped = 0;

/* AUXILLIARY FUNCTIONS */
static inline int cdp_is_accessed(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_ACCESSED) ==
	  CHUNK_STATUS_ACCESSED);
}

static inline int cdp_is_modified(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_MODIFIED) ==
	  CHUNK_STATUS_MODIFIED);
}

static inline int cdp_is_modified_session(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_MODIFIED_SESSION) ==
	  CHUNK_STATUS_MODIFIED_SESSION);
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

static inline void mark_cdp_modified(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_MODIFIED | CHUNK_STATUS_MODIFIED_SESSION;
}

/* For use when the chunk tag is found to be equal to the tag on the previous
   keyring.  Does not change session statistics. */
static inline void mark_cdp_not_modified(struct chunk_data * cdp)
{
  cdp->status &= ~CHUNK_STATUS_MODIFIED;
}

static inline void mark_cdp_compressed(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_COMPRESSED;
}

static inline void mark_cdp_uncompressed(struct chunk_data * cdp)
{
  cdp->status &= ~CHUNK_STATUS_COMPRESSED;
}

static inline int cdp_present(struct chunk_data * cdp)
{
  return ((cdp->status & CHUNK_STATUS_PRESENT) ==
	  CHUNK_STATUS_PRESENT);
}

static inline void get_dir_chunk_from_chunk_num(unsigned chunk_num,
                   unsigned *dir, unsigned *chunk)
{
  *chunk = chunk_num % state.chunksperdir;
  *dir = chunk_num / state.chunksperdir;
}


static struct chunk_data *get_cdp_from_chunk_num(unsigned chunk_num)
{
  return &(state.cd[chunk_num]);
}

static struct prev_chunk_data *get_pcdp_from_chunk_num(unsigned chunk_num)
{
  return &(state.pcd[chunk_num]);
}

static uint64_t get_image_offset_from_chunk_num(unsigned chunk_num)
{
  return ((uint64_t)chunk_num) * state.chunksize_bytes + state.offset_bytes;
}

static inline void mark_cdp_present(struct chunk_data * cdp)
{
  cdp->status |= CHUNK_STATUS_PRESENT;
}

static int form_index_name(const char *dirname)
{
  int add_slash = 0;
  int result;
  
  if (dirname[strlen(dirname) - 1] != '/') {
    add_slash = 1;
  }
  
  result=snprintf(state.index_name, MAX_INDEX_NAME_LENGTH, "%s%s%s",
                        dirname, (add_slash ? "/" : ""), index_name);

  if (result >= MAX_INDEX_NAME_LENGTH || result == -1) {
    /* Older versions of libc return -1 on truncation */
    return -1;
  }
  return 0;
}

static int form_image_name(const char *dirname)
{
  int add_slash = 0;
  int result;
  
  if (dirname[strlen(dirname) - 1] != '/') {
    add_slash = 1;
  }
  
  result=snprintf(state.image_name, MAX_INDEX_NAME_LENGTH, "%s%s%s",
                        dirname, (add_slash ? "/" : ""), image_name);

  if (result >= MAX_INDEX_NAME_LENGTH || result == -1) {
    /* Older versions of libc return -1 on truncation */
    return -1;
  }
  return 0;
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

/* reads the hex keyring file into memory */
/* hex file format: "<tag> <key>\n" (82 bytes/line including newline) */
vulpes_err_t read_hex_keyring(char *userPath, int prev)
{
	unsigned chunk_num;
	int fd;
	struct chunk_data *cdp=NULL;
	struct prev_chunk_data *pcdp=NULL;
	char buf[HASH_LEN_HEX];
	
	fd = open(userPath, O_RDONLY);
	if (fd < 0) {
		vulpes_log(LOG_ERRORS,"could not open keyring: %s",userPath);
		return VULPES_IOERR;
	}
	for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
		if (prev)
			pcdp=get_pcdp_from_chunk_num(chunk_num);
		else
			cdp=get_cdp_from_chunk_num(chunk_num);
		if (read(fd, buf, HASH_LEN_HEX) != HASH_LEN_HEX)
			goto short_read;
		if (prev)
			hexToBin(buf, pcdp->tag, HASH_LEN);
		else
			hexToBin(buf, cdp->tag, HASH_LEN);
		if (read(fd, buf, HASH_LEN_HEX) != HASH_LEN_HEX)
			goto short_read;
		if (!prev) {
			hexToBin(buf, cdp->key, HASH_LEN);
			mark_cdp_compressed(cdp);
		}
	}
	if (!at_eof(fd)) {
		vulpes_log(LOG_ERRORS,"too much data in keyring %s",userPath);
		return VULPES_IOERR;
	}
	close(fd);
	vulpes_log(LOG_BASIC,"read hex keyring %s: %d keys",userPath,state.numchunks);
	return VULPES_SUCCESS;
	
short_read:
	vulpes_log(LOG_ERRORS,"I/O error reading key from %s for chunk %d",userPath,chunk_num);
	return VULPES_IOERR;
}

/* converts to hex, writes */
static vulpes_err_t write_hex_keyring(char *userPath)
{
	unsigned chunk_num;
	struct chunk_data *cdp;
	int fd;
	char buf[HASH_LEN_HEX];
	
	fd = open(userPath, O_WRONLY|O_TRUNC, 0600);
	if (fd < 0) {
		vulpes_log(LOG_ERRORS,"could not open keyring file for writeback: %s", userPath);
		return VULPES_IOERR;
	}
	for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
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
	if (fsync(fd))
		goto short_write;
	close(fd);
	vulpes_log(LOG_BASIC,"wrote hex keyring %s: %d keys",userPath,state.numchunks);
	return VULPES_SUCCESS;
	
short_write:
	vulpes_log(LOG_ERRORS,"failure writing keyring file: %s",userPath);
	close(fd);
	return VULPES_IOERR;
}

static vulpes_err_t read_bin_keyring(char *path, int prev)
{
  struct chunk_data *cdp;
  struct prev_chunk_data *pcdp;
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
  if (ntohl(hdr.entries) != state.numchunks) {
    vulpes_log(LOG_ERRORS, "Invalid chunk count reading %s: expected %u, found %u", path, state.numchunks, htonl(hdr.entries));
    return VULPES_BADFORMAT;
  }
  
  for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
    if (read(fd, &entry, sizeof(entry)) != sizeof(entry))
      goto short_read;
    if (prev) {
      pcdp=get_pcdp_from_chunk_num(chunk_num);
      memcpy(pcdp->tag, entry.tag, HASH_LEN);
    } else {
      cdp=get_cdp_from_chunk_num(chunk_num);
      memcpy(cdp->key, entry.key, HASH_LEN);
      memcpy(cdp->tag, entry.tag, HASH_LEN);
      if (entry.compress == KR_COMPRESS_NONE)
	mark_cdp_uncompressed(cdp);
      else
	mark_cdp_compressed(cdp);
    }
  }
  if (!at_eof(fd)) {
    vulpes_log(LOG_ERRORS, "Extra data at end of file: %s", path);
    return VULPES_IOERR;
  }
  close(fd);
  vulpes_log(LOG_BASIC, "read bin keyring %s: %d keys", path, state.numchunks);
  return VULPES_SUCCESS;
  
short_read:
  vulpes_log(LOG_ERRORS, "Couldn't read %s", path);
  close(fd);
  return VULPES_IOERR;
}

static vulpes_err_t write_bin_keyring(char *path)
{
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
  hdr.entries=htonl(state.numchunks);
  hdr.version=KR_VERSION;
  if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr))
    goto short_write;
  
  memset(&entry, 0, sizeof(entry));
  for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
    cdp=get_cdp_from_chunk_num(chunk_num);
    memcpy(entry.key, cdp->key, HASH_LEN);
    memcpy(entry.tag, cdp->tag, HASH_LEN);
    entry.compress=cdp_is_compressed(cdp) ? KR_COMPRESS_ZLIB : KR_COMPRESS_NONE;
    if (write(fd, &entry, sizeof(entry)) != sizeof(entry))
      goto short_write;
  }
  if (fsync(fd))
    goto short_write;
  close(fd);
  vulpes_log(LOG_BASIC, "wrote bin keyring %s: %d keys", path, state.numchunks);
  return VULPES_SUCCESS;
  
short_write:
  vulpes_log(LOG_ERRORS, "Couldn't write %s", path);
  close(fd);
  return VULPES_IOERR;
}

static vulpes_err_t write_cache_header(int fd)
{
  struct chunk_data *cdp;
  struct ca_header hdr;
  struct ca_entry entry;
  unsigned chunk_num;
  unsigned valid_count=0;
  unsigned dirty_count=0;
  
  if (lseek(fd, sizeof(hdr), SEEK_SET) != sizeof(hdr)) {
    vulpes_log(LOG_ERRORS, "Couldn't seek cache file");
    return VULPES_IOERR;
  }
  
  for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
    memset(&entry, 0, sizeof(entry));
    cdp=get_cdp_from_chunk_num(chunk_num);
    if (cdp_present(cdp)) {
      entry.flags |= CA_VALID;
      entry.length=htonl(cdp->length);
      valid_count++;
    }
    if (cdp_is_modified(cdp)) {
      entry.flags |= CA_DIRTY;
      dirty_count++;
    }
    if (write(fd, &entry, sizeof(entry)) != sizeof(entry)) {
      vulpes_log(LOG_ERRORS, "Couldn't write cache file record: %u", chunk_num);
      return VULPES_IOERR;
    }
  }
  
  if (lseek(fd, 0, SEEK_SET)) {
    vulpes_log(LOG_ERRORS, "Couldn't seek cache file");
    return VULPES_IOERR;
  }
  memset(&hdr, 0, sizeof(hdr));
  hdr.magic=htonl(CA_MAGIC);
  hdr.entries=htonl(state.numchunks);
  hdr.version=CA_VERSION;
  hdr.offset=htonl(state.offset_bytes / 512);
  hdr.valid_chunks=htonl(valid_count);
  hdr.dirty_chunks=htonl(dirty_count);
  if (write(fd, &hdr, sizeof(hdr)) != sizeof(hdr) || fsync(fd)) {
    vulpes_log(LOG_ERRORS, "Couldn't write cache file header");
    return VULPES_IOERR;
  }
  
  vulpes_log(LOG_BASIC, "Wrote cache header");
  return VULPES_SUCCESS;
}

static vulpes_err_t open_cache_file(const char *path)
{
  struct chunk_data *cdp;
  struct ca_header hdr;
  struct ca_entry entry;
  unsigned chunk_num;
  int fd;
  
  fd=open(path, O_RDWR);
  if (fd == -1 && errno == ENOENT) {
    vulpes_log(LOG_BASIC,"No existing local cache; creating");
    fd=open(path, O_CREAT|O_RDWR, 0600);
    if (fd == -1) {
      vulpes_log(LOG_ERRORS,"couldn't create cache file");
      return VULPES_IOERR;
    }
    state.offset_bytes=((sizeof(hdr) + state.numchunks * sizeof(entry))
                       + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);
    write_cache_header(fd);
    if (ftruncate(fd, state.volsize * SECTOR_SIZE + state.offset_bytes)) {
      vulpes_log(LOG_ERRORS,"couldn't extend cache file");
      return VULPES_IOERR;
    }
    state.cachefile_fd=fd;
    return VULPES_SUCCESS;
  } else if (fd == -1) {
    vulpes_log(LOG_ERRORS,"couldn't open cache file");
    return VULPES_IOERR;
  }
  
  if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
    vulpes_log(LOG_ERRORS, "Couldn't read cache file header");
    return VULPES_IOERR;
  }
  if (ntohl(hdr.magic) != CA_MAGIC) {
    vulpes_log(LOG_ERRORS, "Invalid magic number reading cache file");
    return VULPES_BADFORMAT;
  }
  if (hdr.version != CA_VERSION) {
    vulpes_log(LOG_ERRORS, "Invalid version reading cache file: expected %d, found %d", CA_VERSION, hdr.version);
    return VULPES_BADFORMAT;
  }
  if (ntohl(hdr.entries) != state.numchunks) {
    vulpes_log(LOG_ERRORS, "Invalid chunk count reading cache file: expected %u, found %u", state.numchunks, htonl(hdr.entries));
    return VULPES_BADFORMAT;
  }
  state.offset_bytes=ntohl(hdr.offset) * SECTOR_SIZE;
  state.valid_chunks_on_open=ntohl(hdr.valid_chunks);
  state.dirty_chunks_on_open=ntohl(hdr.dirty_chunks);
  
  for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
    if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
      vulpes_log(LOG_ERRORS, "Couldn't read cache file record: %u", chunk_num);
      return VULPES_IOERR;
    }
    cdp=get_cdp_from_chunk_num(chunk_num);
    if (entry.flags & CA_VALID) {
      mark_cdp_present(cdp);
      cdp->length=ntohl(entry.length);
    }
    if (entry.flags & CA_DIRTY)
      mark_cdp_modified(cdp);
  }
  vulpes_log(LOG_BASIC, "Read cache header");
  state.cachefile_fd=fd;
  return VULPES_SUCCESS;
}

static void updateKey(unsigned chunk_num, const unsigned char *new_key,
                      const unsigned char *new_tag)
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

static vulpes_err_t check_tag(struct chunk_data *cdp, const unsigned char *tag)
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
  bufvalid = (check_tag(cdp, dgst) == VULPES_SUCCESS);
  if (!bufvalid)
    print_tag_check_error(cdp->tag, dgst);
  
  free(dgst);

  return bufvalid;
}

static vulpes_err_t strip_compression(unsigned chunk_num, char **buf,
                                      unsigned buf_len)
{
  struct chunk_data *cdp;
  void *decompressed, *newkey, *newtag;
  unsigned char *decrypted, *encrypted;
  int decryptedSize, encryptedSize;
  unsigned long decompressedSize;
  
  vulpes_log(LOG_CHUNKS,"stripping compression from chunk %u: %u bytes",chunk_num,buf_len);
  cdp=get_cdp_from_chunk_num(chunk_num);
  if (!cdp_is_compressed(cdp)) {
    vulpes_log(LOG_ERRORS,"chunk is already uncompressed: %u", chunk_num);
    return VULPES_INVALID;
  }
  if (buf_len < state.chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"compressed buffer too small: %u", buf_len);
    return VULPES_INVALID;
  }
  
  if (!vulpes_decrypt(*buf, buf_len, &decrypted, &decryptedSize,
                      cdp->key, 16, 1)) {
    vulpes_log(LOG_ERRORS,"could not decrypt file: %d",chunk_num);
    return VULPES_BADFORMAT;
  };
  
  decompressed = malloc(state.chunksize_bytes);
  if (decompressed == NULL) {
    vulpes_log(LOG_ERRORS,"malloc failed: %d",chunk_num);
    return VULPES_NOMEM;
  }

  decompressedSize = state.chunksize_bytes;
  if (uncompress(decompressed, &decompressedSize, decrypted, decryptedSize)
                 != Z_OK) {
    vulpes_log(LOG_ERRORS,"could not decompress file: %d",chunk_num);
    return VULPES_BADFORMAT;
  };
  if (decompressedSize != state.chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"decompressed to invalid length %d: %d",decompressedSize,chunk_num);
    return VULPES_BADFORMAT;
  }
  free(decrypted);
  
  newkey = digest(decompressed, decompressedSize);
  vulpes_encrypt(decompressed, decompressedSize, &encrypted, &encryptedSize,
                 newkey, 16, 0);
  if (encryptedSize != state.chunksize_bytes) {
    vulpes_log(LOG_ERRORS,"encrypted to invalid length %d: %d",encryptedSize,chunk_num);
    return VULPES_BADFORMAT;
  }
  newtag = digest(encrypted, encryptedSize);
  free(decompressed);
  
  updateKey(chunk_num, newkey, newtag);
  free(newkey);
  free(newtag);
  mark_cdp_uncompressed(cdp);
  mark_cdp_modified(cdp);
  chunks_stripped++;
  free(*buf);
  *buf=encrypted;
  return VULPES_SUCCESS;
}

static int retrieve_chunk(const char *src, unsigned chunk_num)
{
  char *buf;
  int buflen;
  vulpes_err_t err;
  struct chunk_data *cdp;
  
  buflen=1.002*state.chunksize_bytes+20;
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
	
	vulpes_log(LOG_CHUNKS,"lka lookup hit for %u",chunk_num);
	cdp = get_cdp_from_chunk_num(chunk_num);
      } else {
	/* Tag check failure */
	vulpes_log(LOG_ERRORS, "SERIOUS, NON-FATAL ERROR - lka lookup hit from %s failed tag match for %u",
		   ((lka_src_file == NULL) ? "<src>" : lka_src_file), chunk_num);
	err = VULPES_IOERR;
      }

      /* free the source name buffer */
      if(lka_src_file != NULL) free(lka_src_file);

      if(err == VULPES_SUCCESS) goto have_data;
      /* else, fall through */
    } else {
      /* LKA miss */
      vulpes_log(LOG_CHUNKS,"lka lookup miss for %u", chunk_num);
    }
  }
  
  err=transport_get(buf, &buflen, src, chunk_num);
  if (err)
    goto out;
  /* buflen has been updated with the length of the data */
  
  /* check retrieved data for validity */
  if(!valid_chunk_buffer(buf, buflen, chunk_num)) {
    vulpes_log(LOG_ERRORS,"failure: %s buffer not valid",src);
    err=VULPES_IOERR;
    goto out;
  }

have_data:
  if (cdp_is_compressed(cdp) && buflen >= state.chunksize_bytes) {
    err=strip_compression(chunk_num, &buf, buflen);
    if (err) goto out;
    buflen=state.chunksize_bytes;
  }
  
  /* write to cache */
  if(pwrite(state.loopdev_fd, buf, buflen, get_image_offset_from_chunk_num(chunk_num))
           != buflen) {
      vulpes_log(LOG_ERRORS,"unable to write cache for %u: %s",chunk_num,strerror(errno));
      err=VULPES_IOERR;
  }
  cdp->length=buflen;
  vulpes_log(LOG_TRANSPORT,"end: %s %u",src,chunk_num);
  
out:
  free(buf);
  return err ? -1 : 0;
}

static vulpes_err_t load_keyring(int prev)
{
  char *hex=prev ? config.old_hex_keyring_name : config.hex_keyring_name;
  char *bin=prev ? config.old_bin_keyring_name : config.bin_keyring_name;
  vulpes_err_t ret;
  
  ret=read_bin_keyring(bin, prev);
  switch (ret) {
  case VULPES_SUCCESS:
    break;
  case VULPES_NOTFOUND:
    vulpes_log(LOG_BASIC, "Couldn't read binary keyring; trying hex keyring");
    ret=read_hex_keyring(hex, prev);
    if (ret)
      vulpes_log(LOG_ERRORS,"read_hex_keyring() failed");
    break;
  default:
    vulpes_log(LOG_ERRORS,"read_bin_keyring() failed");
    break;
  }
  return ret;
}

/* If the new tag for a chunk is identical to the old one, remove the modified
   bit since we don't need to re-upload.  This might happen if the
   guest writes out data identical to the data already in the chunk. */
static vulpes_err_t scrub_modified_flag(void)
{
  struct chunk_data *cdp;
  struct prev_chunk_data *pcdp;
  unsigned chunk_num;
  vulpes_err_t ret;
  
  if (state.pcd == NULL) {
    state.pcd=malloc(state.numchunks * sizeof(struct prev_chunk_data));
    if (state.pcd == NULL) {
      vulpes_log(LOG_ERRORS,"malloc failed");
      return VULPES_NOMEM;
    }
    memset(state.pcd, 0, state.numchunks * sizeof(struct prev_chunk_data));
    ret=load_keyring(1);
    if (ret)
      return ret;
  }
  
  for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
    cdp=get_cdp_from_chunk_num(chunk_num);
    if (cdp_is_modified(cdp)) {
      pcdp=get_pcdp_from_chunk_num(chunk_num);
      if (check_tag(cdp, pcdp->tag) == VULPES_SUCCESS) {
	vulpes_log(LOG_CHUNKS,"Chunk modified but tag equal; marking unmodified: %u",chunk_num);
	mark_cdp_not_modified(cdp);
      }
    }
  }
  return VULPES_SUCCESS;
}

/* INTERFACE FUNCTIONS */

/* XXX we need better error handling here */
vulpes_err_t cache_shutdown(void)
{
  struct chunk_data *cdp;
  vulpes_err_t ret;
  unsigned chunk_num;
  
  unsigned modified_chunks = 0;
  unsigned accessed_chunks = 0;
  
  if (state.cd == NULL) {
    vulpes_log(LOG_ERRORS,"cache_shutdown() called with no chunk_data array");
    return 0;
  }
  
  /* Write the new keyrings */
  ret=write_bin_keyring(config.bin_keyring_name);
  if (ret) {
    vulpes_log(LOG_ERRORS,"write_bin_keyring failed");
    return ret;
  }
  ret=write_hex_keyring(config.hex_keyring_name);
  if (ret) {
    vulpes_log(LOG_ERRORS,"write_hex_keyring failed");
    return ret;
  }
  
  /* Update modified flag based on the old keyring */
  if (scrub_modified_flag()) {
    vulpes_log(LOG_ERRORS,"couldn't update modified flags");
    /* Non-fatal.  Upload will fail its consistency check later, but an
       intervening resume will fix it. */
  }
  
  /* Gather statistics */
  for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
    cdp=get_cdp_from_chunk_num(chunk_num);
    if (cdp_is_accessed(cdp))
      ++accessed_chunks;
    if (cdp_is_modified_session(cdp))
      ++modified_chunks;
  }
  
  /* Update and close cache file */
  write_cache_header(state.cachefile_fd);
  close(state.cachefile_fd);
  free(state.cd);
  state.cd = NULL;
  
  /* Print close stats */
  vulpes_log(LOG_STATS,"CHUNKS_ACCESSED:%u",accessed_chunks);
  vulpes_log(LOG_STATS,"CHUNKS_MODIFIED:%u",modified_chunks);
  vulpes_log(LOG_STATS,"CHUNKS_RAW:%u",writes_before_read);
  vulpes_log(LOG_STATS,"CHUNKS_STRIPPED:%u",chunks_stripped);

  return VULPES_SUCCESS;
}

int cache_get(const struct isr_message *req, struct isr_message *reply)
{
  struct chunk_data *cdp;
  
  cdp = get_cdp_from_chunk_num(req->chunk);

  /* check if the file is present in the cache */
  if (!cdp_present(cdp)) {
    /* the file has not been copied yet */
    char remote_name[MAX_CHUNK_NAME_LENGTH];
    if (form_chunk_file_name(remote_name, MAX_CHUNK_NAME_LENGTH,
	 config.master_name, req->chunk)) {
      vulpes_log(LOG_ERRORS,"unable to form cache remote name: %llu",req->chunk);
      return -1;
    }
    
    if (retrieve_chunk(remote_name, req->chunk) == 0) {
      mark_cdp_present(cdp);
    } else {
      vulpes_log(LOG_ERRORS,"unable to copy %s %llu",remote_name,req->chunk);
      return -1;
    }
  }
  
  mark_cdp_accessed(cdp);
  if (cdp_is_compressed(cdp))
    reply->compression=ISR_COMPRESS_ZLIB;
  else
    reply->compression=ISR_COMPRESS_NONE;
  memcpy(reply->key, cdp->key, HASH_LEN);
  memcpy(reply->tag, cdp->tag, HASH_LEN);
  reply->length=cdp->length;
  
  vulpes_log(LOG_CHUNKS,"get: %llu (size %u)",req->chunk,cdp->length);
  return 0;
}

int cache_update(const struct isr_message *req)
{
  struct chunk_data *cdp=NULL;
  
  cdp = get_cdp_from_chunk_num(req->chunk);

  mark_cdp_present(cdp);
  if (!cdp_is_accessed(cdp)) {
    mark_cdp_accessed(cdp);
    writes_before_read++;
  }
  mark_cdp_modified(cdp);
  if (req->compression == ISR_COMPRESS_NONE)
    mark_cdp_uncompressed(cdp);
  else
    mark_cdp_compressed(cdp);
  updateKey(req->chunk, req->key, req->tag);
  cdp->length=req->length;

  vulpes_log(LOG_CHUNKS,"update: %llu (size %u)",req->chunk,cdp->length);
  return 0;
}

int cache_init(void)
{
  unsigned long long volsize_bytes;
  int parse_error = 0;
  FILE *f;
  
  vulpes_log(LOG_BASIC,"vulpes_cache: %s", config.cache_name);
  if ((config.proxy_name) && (config.proxy_port)) {
    vulpes_log(LOG_BASIC,"proxy: %s",config.proxy_name);
    vulpes_log(LOG_BASIC,"proxy-port: %ld",config.proxy_port);
  }
  
  if (form_index_name(config.cache_name)) {
    vulpes_log(LOG_ERRORS,"unable to form cache index name");
    return -1;
  }
  
  /* Open index file */
  f = fopen(state.index_name, "r");
  if (f == NULL) {
    vulpes_log(LOG_ERRORS,"unable to open index file %s",state.index_name);
    return -1;
  }
  
  /* Scan index file */
  if (fscanf(f, "VERSION= %u\n", &state.version) != 1) {
    vulpes_log(LOG_ERRORS,"unable to parse version from index file %s",state.index_name);
    fclose(f);
    return -1;
  }
  if (state.version != 2) {
    vulpes_log(LOG_ERRORS,"unknown cache version number: %s",state.index_name);
    fclose(f);
    return -1;
  }
  
  if (fscanf(f, "CHUNKSIZE= %u\n", &state.chunksize_bytes) != 1)
    parse_error = 1;
  if (fscanf(f, "CHUNKSPERDIR= %u\n", &state.chunksperdir) != 1)
    parse_error = 1;
  if (fscanf(f, "VOLSIZE= %llu\n", &volsize_bytes) != 1)
    parse_error = 1;
  if (fscanf(f, "NUMCHUNKS= %u\n", &state.numchunks) != 1)
    parse_error = 1;
  if (fscanf(f, "NUMDIRS= %u\n", &state.numdirs) != 1)
    parse_error = 1;
  
  fclose(f);
  if (parse_error) {
    vulpes_log(LOG_ERRORS,"bad parse: %s",state.index_name);
    return -1;
  }
  
  /* compute derivative values */
  if (state.chunksize_bytes % SECTOR_SIZE != 0) {
    vulpes_log(LOG_ERRORS,"bad chunksize: %u",state.chunksize_bytes);
    return -1;
  }
  state.chunksize = state.chunksize_bytes / SECTOR_SIZE;
  state.volsize = state.chunksize * state.numchunks;
  
  /* Check if the cache root directory exists */
  if (!is_dir(config.cache_name)) {
    vulpes_log(LOG_ERRORS,"unable to open dir: %s", config.cache_name);
    return -1;
  }
  
  /* Allocate the chunk_data array */
  state.cd = malloc(state.numchunks * sizeof(struct chunk_data));
  if (state.cd == NULL) {
    vulpes_log(LOG_ERRORS,"unable to allocate chunk_data array");
    return -1;
  }
  memset(state.cd, 0, state.numchunks * sizeof(struct chunk_data));
  
  if (load_keyring(0))
    return -1;
  
  if (form_image_name(config.cache_name)) {
    vulpes_log(LOG_ERRORS,"unable to form image name");
    return -1;
  }
  if (open_cache_file(state.image_name))
    return -1;
  
  return 0;
}

int copy_for_upload(void)
{
  char name[MAX_CHUNK_NAME_LENGTH];
  char *buf;
  unsigned u;
  struct chunk_data *cdp;
  int fd;
  unsigned examined_chunks=0;
  unsigned modified_chunks=0;
  uint64_t modified_bytes=0;
  FILE *fp;
  char *calc_tag;
  
  vulpes_log(LOG_BASIC,"Copying chunks to upload directory %s",config.dest_dir_name);
  buf=malloc(state.chunksize_bytes);
  if (buf == NULL) {
    vulpes_log(LOG_ERRORS,"malloc failed");
    return 1;
  }
  /* check the subdirectories  -- create if needed */
  for (u = 0; u < state.numdirs; u++) {
    form_dir_name(name, sizeof(name), config.dest_dir_name, u);
    if (!is_dir(name)) {
      if (mkdir(name, 0770)) {
	vulpes_log(LOG_ERRORS,"unable to mkdir: %s", name);
	return 1;
      }
    }
  }
  for (u=0; u < state.numchunks; u++) {
    cdp=get_cdp_from_chunk_num(u);
    if (cdp_is_modified(cdp)) {
      print_progress(++examined_chunks, state.dirty_chunks_on_open);
      if (!cdp_present(cdp)) {
	vulpes_log(LOG_ERRORS,"Chunk modified but not present: %u",u);
	continue;
      }
      if (form_chunk_file_name(name, sizeof(name), config.dest_dir_name, u)) {
	vulpes_log(LOG_ERRORS,"Couldn't form chunk filename: %u",u);
	return 1;
      }
      if (pread(state.cachefile_fd, buf, cdp->length, get_image_offset_from_chunk_num(u))
	       != cdp->length) {
        vulpes_log(LOG_ERRORS,"Couldn't read chunk from local cache: %u",u);
	return 1;
      }
      calc_tag=digest(buf, cdp->length);
      if (calc_tag == NULL) {
	vulpes_log(LOG_ERRORS,"Couldn't calculate hash for chunk: %u",u);
	return 1;
      }
      if (check_tag(cdp, calc_tag) == VULPES_TAGFAIL) {
	vulpes_log(LOG_ERRORS,"Chunk %u: tag mismatch.  Data corruption has occurred; skipping chunk",u);
	print_tag_check_error(cdp->tag, calc_tag);
	return 1;
      }
      free(calc_tag);
      fd=open(name, O_WRONLY|O_CREAT|O_TRUNC, 0600);
      if (fd == -1) {
	vulpes_log(LOG_ERRORS,"Couldn't open chunk file: %s",name);
	return 1;
      }
      if (write(fd, buf, cdp->length) != cdp->length) {
	vulpes_log(LOG_ERRORS,"Couldn't write chunk file: %s",name);
	return 1;
      }
      if (close(fd) && errno != EINTR) {
	vulpes_log(LOG_ERRORS,"Couldn't write chunk file: %s",name);
	return 1;
      }
      modified_chunks++;
      modified_bytes += cdp->length;
    }
  }
  printf("\n");
  free(buf);
  /* Write statistics */
  snprintf(name, sizeof(name), "%s/stats", config.dest_dir_name);
  fp=fopen(name, "w");
  if (fp == NULL) {
    vulpes_log(LOG_ERRORS,"Couldn't open stats file: %s",name);
    return 1;
  }
  fprintf(fp, "%u\n%llu\n", modified_chunks, modified_bytes);
  fclose(fp);
  vulpes_log(LOG_STATS,"Copied %u modified chunks, %llu bytes",modified_chunks,modified_bytes);
  return 0;
}

int checktags(void)
{
  void *buf;
  unsigned chunk_num;
  char *tag;
  struct chunk_data *cdp;
  unsigned processed=0;
  
  vulpes_log(LOG_BASIC,"Checking cache consistency");
  buf=malloc(state.chunksize_bytes);
  if (buf == NULL) {
    vulpes_log(LOG_ERRORS,"malloc failed");
    return 1;
  }
  for (chunk_num=0; chunk_num < state.numchunks; chunk_num++) {
    cdp=get_cdp_from_chunk_num(chunk_num);
    if (!cdp_present(cdp)) {
      continue;
    }
    if (pread(state.cachefile_fd, buf, cdp->length,
              get_image_offset_from_chunk_num(chunk_num)) != cdp->length) {
      vulpes_log(LOG_ERRORS,"Couldn't read chunk from local cache: %u",chunk_num);
      return 1;
    }
    tag=digest(buf, cdp->length);
    if (tag == NULL) {
      vulpes_log(LOG_ERRORS,"Couldn't calculate hash for chunk: %u",chunk_num);
      return 1;
    }
    if (check_tag(cdp, tag) == VULPES_TAGFAIL) {
      vulpes_log(LOG_ERRORS,"Chunk %u: tag check failure",chunk_num);
      print_tag_check_error(cdp->tag, tag);
    }
    free(tag);
    print_progress(++processed, state.valid_chunks_on_open);
  }
  free(buf);
  printf("\n");
  return 0;
}
