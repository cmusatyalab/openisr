#ifndef VULPES_H
#define VULPES_H

/* This header is sort of hacked-together.  Eventually, when we get cleaner
   interfaces, this should be cleaned up a bit. */

#include <stdio.h>
#include "fauxide.h"

#define VULPES_SIMPLE_DEFINED

#undef VERBOSE_DEBUG
#ifdef VERBOSE_DEBUG
#define VULPES_DEBUG(fmt, args...)     {printf("[vulpes] " fmt, ## args); fflush(stdout);}
#else
#define VULPES_DEBUG(fmt, args...)     ;
#endif

extern volatile int exit_pending;

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
} vulpes_err_t;

enum transfer_type {
  NO_TRANSPORT=0,
  LOCAL_TRANSPORT,
  HTTP_TRANSPORT,
};

enum mapping_type {
  NO_MAPPING=0,
  SIMPLE_FILE_MAPPING,
  SIMPLE_DISK_MAPPING,
  LEV1_MAPPING,
};

typedef vulpes_volsize_t(*vulpes_volsize_func_t) (void);
typedef int (*vulpes_read_func_t) (vulpes_cmdblk_t *);
typedef int (*vulpes_write_func_t) (const vulpes_cmdblk_t *);
typedef int (*vulpes_shutdown_func_t) (void);

extern struct vulpes_config {
  enum transfer_type trxfer;	/* Set by main */
  enum mapping_type mapping;    /* Set by main */
  char* proxy_name;             /* Set by main */
  long  proxy_port;             /* set by main */
  
  char *device_name;		/* Set by main */
  char *master_name;		/* Set by main */
  char *cache_name;		/* Set by main */
  char *dest_name;              /* Set by main */
  char *old_keyring_name;	/* Set by main */
  char *hex_keyring_name;	/* Set by main */
  char *bin_keyring_name;	/* Set by main */

  int vulpes_device;		/* Set by device driver */
  
  vulpes_registration_t reg;	        /* Set in open_func */
  vulpes_volsize_func_t volsize_func;	/* Set in initialize */
  vulpes_read_func_t read_func;	        /* Set in initialize */
  vulpes_write_func_t write_func;	/* Set in initialize */
  vulpes_shutdown_func_t shutdown_func;	/* Set in initialize */
  
  int verbose;			/* Set by main -- currently not used */
  int doUpload;                 /* Set by main */
  struct lka_svc *lka_svc;     /* Set by main */
  void *special;		/* Set in open_func */
} config;

/* XXX miscellaneous exported functions */
int set_signal_handler(int sig, void (*handler)(int sig));
void tally_sector_accesses(unsigned write, unsigned num);
int initialize_lev1_mapping(void);
#ifdef VULPES_SIMPLE_DEFINED
int initialize_simple_mapping(void);
#endif
int fauxide_init(void);
void fauxide_run(void);
void fauxide_shutdown(void);
int fauxide_rescue(const char *device_name);
vulpes_err_t local_get(char *buf, int *bufsize, const char *file);
vulpes_err_t http_get(char *buf, int *bufsize, const char *url);
void copy_for_upload(char *oldkr, char *dest);

#endif
