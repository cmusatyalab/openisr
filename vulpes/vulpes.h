#ifndef VULPES_H
#define VULPES_H

/* This header is sort of hacked-together.  Eventually, when we get cleaner
   interfaces, this should be cleaned up a bit. */

#include <stdio.h>

#undef VERBOSE_DEBUG
#ifdef VERBOSE_DEBUG
#define VULPES_DEBUG(fmt, args...)     {printf("[vulpes] " fmt, ## args); fflush(stdout);}
#else
#define VULPES_DEBUG(fmt, args...)     ;
#endif

extern const char *svn_revision;
extern const char *svn_branch;

typedef enum vulpes_err {
  VULPES_SUCCESS=0,
  VULPES_OVERFLOW,
  VULPES_IOERR,
  VULPES_NOTFOUND,
  VULPES_INVALID,
  VULPES_NOMEM,
  VULPES_NOKEY,
  VULPES_TAGFAIL,
  VULPES_BADFORMAT,
  VULPES_CALLFAIL,
  VULPES_PROTOFAIL,
  VULPES_NETFAIL,  /* Used instead of IOERR if a retry might fix it */
} vulpes_err_t;

enum transfer_type {
  NO_TRANSPORT=0,
  LOCAL_TRANSPORT,
  HTTP_TRANSPORT,
};

/* Set by command line parser in main() */
extern struct vulpes_config {
  enum transfer_type trxfer;
  char* proxy_name;
  long  proxy_port;
  
  char *master_name;
  char *cache_name;
  char *hex_keyring_name;
  char *bin_keyring_name;
  char *old_hex_keyring_name;
  char *old_bin_keyring_name;
  char *dest_dir_name;

  int verbose;			/* currently not used */
  struct lka_svc *lka_svc;
  
  char *log_file_name;
  char *log_infostr;
  unsigned log_file_mask;
  unsigned log_stdout_mask;
} config;

#define MAX_PATH_LENGTH 512
#define SECTOR_SIZE 512

extern struct vulpes_state {
  char index_name[MAX_PATH_LENGTH];
  char image_name[MAX_PATH_LENGTH];
  char loopdev_name[MAX_PATH_LENGTH];
  unsigned version;
  unsigned chunksize_bytes;
  unsigned chunksperdir;
  unsigned numchunks;
  unsigned numdirs;
  unsigned long long volsize;	/* sectors */
  unsigned chunksize;		/* sectors */
  unsigned valid_chunks_on_open;
  unsigned dirty_chunks_on_open;
  int cachefile_fd;
  int chardev_fd;
  int loopdev_fd;
  int signal_fds[2];
  FILE *log_fp;
  unsigned offset_bytes;
  struct chunk_data *cd;		/* cd[] */
  struct prev_chunk_data *pcd;		/* pcd[] */
  unsigned long long request_count;
  struct curl_connection *curl_conn;
} state;

struct isr_message;

/* XXX miscellaneous exported functions */
vulpes_err_t driver_init(void);
void driver_run(void);
void driver_shutdown(void);
vulpes_err_t transport_init(void);
vulpes_err_t transport_get(void *buf, int *bufsize, const char *src,
			   unsigned chunk_num);
void transport_shutdown(void);
int copy_for_upload(void);
int checktags(void);
vulpes_err_t cache_init(void);
vulpes_err_t cache_get(const struct isr_message *req, struct isr_message *reply);
void cache_update(const struct isr_message *req);
vulpes_err_t cache_shutdown(void);

#endif
