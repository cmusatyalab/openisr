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
} vulpes_err_t;

enum transfer_type {
  NO_TRANSPORT=0,
  LOCAL_TRANSPORT,
  HTTP_TRANSPORT,
};

extern struct vulpes_config {
  enum transfer_type trxfer;	/* Set by main */
  char* proxy_name;             /* Set by main */
  long  proxy_port;             /* set by main */
  
  char *master_name;		/* Set by main */
  char *cache_name;		/* Set by main */
  char *dest_name;              /* Set by main */
  char *old_keyring_name;	/* Set by main */
  char *hex_keyring_name;	/* Set by main */
  char *bin_keyring_name;	/* Set by main */

  int verbose;			/* Set by main -- currently not used */
  int doUpload;                 /* Set by main */
  int doCheck;                  /* Set by main */
  struct lka_svc *lka_svc;      /* Set by main */
} config;

/* XXX */
#define MAX_INDEX_NAME_LENGTH 256
#define MAX_CHUNK_NAME_LENGTH 512
#define MAX_DIRLENGTH 256
#define SECTOR_SIZE 512

extern struct vulpes_state {
  char index_name[MAX_INDEX_NAME_LENGTH];
  char image_name[MAX_INDEX_NAME_LENGTH];
  char loopdev_name[MAX_INDEX_NAME_LENGTH];
  unsigned version;
  unsigned chunksize_bytes;
  unsigned chunksperdir;
  unsigned numchunks;
  unsigned numdirs;
  unsigned long long volsize;	/* sectors */
  unsigned chunksize;		/* sectors */
  int cachefile_fd;
  int chardev_fd;
  int loopdev_fd;
  unsigned offset_bytes;
  struct chunk_data *cd;		/* cd[] */
} state;

struct isr_message;

/* XXX miscellaneous exported functions */
vulpes_err_t driver_init(void);
void driver_run(void);
void driver_shutdown(void);
vulpes_err_t local_get(char *buf, int *bufsize, const char *file);
vulpes_err_t http_get(char *buf, int *bufsize, const char *url);
void copy_for_upload(char *oldkr, char *dest);
void checktags(void);
int initialize_cache(void);
int cache_get(struct isr_message *msg);
int cache_update(const struct isr_message *msg);
int cache_shutdown(void);

#endif
