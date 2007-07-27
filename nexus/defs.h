/* defs.h - struct/symbol definitions, utility fns, exported fn prototypes */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (TM)
 *         system
 * 
 * Copyright (C) 2006-2007 Carnegie Mellon University
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as published
 * by the Free Software Foundation.  A copy of the GNU General Public License
 * should have been distributed along with this program in the file
 * LICENSE.GPL.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef NEXUS_DEFS_H
#define NEXUS_DEFS_H
#ifdef __KERNEL__

#define DEBUG
#define MAX_SEGS_PER_IO 32
#define MAX_CHUNKS_PER_IO 32
#define MIN_CONCURRENT_REQS 2  /* XXX */
#define MAX_CHUNKSIZE 131072  /* XXX hack for preallocated tfm scratch space */
#define DEVICES 16  /* If this is more than 26, ctr will need to be fixed */
#define MINORS_PER_DEVICE 16
#define MAX_DEV_ALLOCATION_MULT 1  /* don't allocate > 10% RAM per device */
#define MAX_DEV_ALLOCATION_DIV 10
#define MAX_ALLOCATION_MULT 3  /* don't allocate > 30% RAM total */
#define MAX_ALLOCATION_DIV 10
#define LOWMEM_WAIT_TIME (HZ/10)
#define MODULE_NAME "openisr"
#define DEVICE_NAME "openisr"
#define KTHREAD_NAME "kopenisrd"
#define IOTHREAD_NAME "kopenisriod"
#define REQTHREAD_NAME "kopenisrblockd"
#define CD_NR_STATES 14  /* must shadow NR_STATES in chunkdata.c */

#include <linux/blkdev.h>
#include <linux/workqueue.h>
#include "nexus.h"

/**
 * struct tfm_suite_info - read-only parameter block for a crypto suite
 * @user_name         : the name seen by the user (e.g. in sysfs)
 * @cipher_name       : cryptoapi cipher name
 * @cipher_mode       : cryptoapi cipher mode constant (for <= 2.6.18)
 * @cipher_mode_name  : cryptoapi cipher mode name     (for >= 2.6.19)
 * @cipher_block      : this cipher's block size
 * @cipher_iv         : this cipher's IV size
 * @key_len           : how much of the hash to use for the key
 * @hash_name         : cryptoapi hash name
 * @hash_len          : this hash algorithm's hash length
 **/
struct tfm_suite_info {
	char *user_name;
	char *cipher_name;
	unsigned cipher_mode;
	char *cipher_mode_name;
	unsigned cipher_block;
	unsigned cipher_iv;
	unsigned key_len;
	char *hash_name;
	unsigned hash_len;
};

/* This needs access to tfm_suite_info */
#include "kcompat.h"

/**
 * struct tfm_compress_info - read-only parameter block for a compression alg
 * @user_name    : the name seen by the user (e.g. in sysfs)
 **/
struct tfm_compress_info {
	char *user_name;
};

typedef sector_t chunk_t;

/**
 * struct nexus_stats - per-device statistics
 * @state_count         : number of chunkdata chunks in each state
 * @state_time_us       : total time spent in each state since counters cleared
 * @state_time_samples  : number of transitions out of each state since cleared
 * @cache_hits          : io_chunk reservations against chunks already in cache
 * @cache_misses        : io_chunk reservations against chunks not in cache
 * @cache_alloc_failures: chunkdata alloc attempts when every cd was busy
 * @chunk_reads         : chunk reads from chunk store
 * @chunk_writes        : chunk writebacks to chunk store
 * @data_bytes_written  : (compressed) bytes of data written to chunk store
 * @whole_chunk_updates : writes to an entire chunk from a single nexus_io
 * @encrypted_discards  : expirations of chunkdata lines in ST_ENCRYPTED
 * @chunk_errors        : entries of chunks into ST_ERROR
 * @sectors_read        : sectors of completed read I/O through request queue
 * @sectors_written     : sectors of completed write I/O through request queue
 **/
struct nexus_stats {
	unsigned state_count[CD_NR_STATES];
	unsigned state_time_us[CD_NR_STATES];
	unsigned state_time_samples[CD_NR_STATES];
	unsigned cache_hits;
	unsigned cache_misses;
	unsigned cache_alloc_failures;
	unsigned chunk_reads;
	unsigned chunk_writes;
	u64      data_bytes_written;
	unsigned whole_chunk_updates;
	unsigned encrypted_discards;
	unsigned chunk_errors;
	unsigned sectors_read;
	unsigned sectors_written;
};

/**
 * struct nexus_tfm_state - per-CPU pre-allocated transform buffers
 * @cipher              : cipher transforms
 * @hash                : hash transforms
 * @zlib_sg             : zlib - scratch sg for newly (un)compressed data
 * @zlib_deflate        : zlib - deflate workspace
 * @zlib_inflate        : zlib - inflate workspace
 * @lzf_buf_compressed  : LZF - bounce buffer for compressed chunk data
 * @lzf_buf_uncompressed: LZF - bounce buffer for uncompressed chunk data
 * @lzf_compress        : LZF - compress workspace
 **/
struct nexus_tfm_state {
	struct crypto_blkcipher *cipher[NEXUS_NR_CRYPTO];
	struct crypto_hash *hash[NEXUS_NR_CRYPTO];
	struct scatterlist *zlib_sg;
	void *zlib_deflate;
	void *zlib_inflate;
	void *lzf_buf_compressed;
	void *lzf_buf_uncompressed;
	void *lzf_compress;
};

/**
 * struct nexus_dev - one Nexus block device
 * @lh_devs              : list head for list of active devices (state.lock)
 * @lh_run_requests      : list head for request thread (queues.lock)
 * @class_dev            : for device model
 * @gendisk              : for block layer
 * @queue                : request queue for our block device (*)
 * @queue_lock           : spinlock associated with @queue
 * @chunk_bdev           : &block_device for our chunk store
 * @cb_add_disk          : workqueue callback for ctr
 * @requests             : queue for nexus_run_requests() (requests_lock)
 * @requests_lock        : lock for @requests
 * @requests_oom_timer   : out-of-memory callback for nexus_run_requests() (*)
 * @lock                 : master device lock (r/w)
 * @chunksize            : size of one chunk in bytes
 * @cachesize            : size of chunkdata cache in entries
 * @offset               : offset of first chunk in chunk store, in sectors
 * @chunks               : number of chunks in this device
 * @devnum               : device ID -- maps to range of minor numbers
 * @owner                : UID that opened the character device
 * @flags                : DEV_ flags (atomic bit operations)
 * @stats                : various statistics (dev lock)
 * @suite                : cipher suite
 * @default_compression  : compress alg to use for new chunks
 * @supported_compression: bitmask of compress algs we must support
 * @chunkdata            : chunkdata table pointer
 * @need_user            : "refcount" for userspace process (dev lock)
 * @waiting_users        : wait queue for chardev (r/w)
 *
 * Fields must only be manipulated as specified in parentheses.  Fields not
 * labeled should be considered read-only, and should not be manipulated except
 * by the ctr/dtr and routines called by them.  Fields marked (*) have
 * manipulation rules not easily summarized in 80 characters; see the code.
 **/
struct nexus_dev {
	struct list_head lh_devs;
	struct list_head lh_run_requests;
	
	struct class_device *class_dev;
	struct gendisk *gendisk;
	struct request_queue *queue;
	struct block_device *chunk_bdev;
	struct work_struct cb_add_disk;
	
	struct list_head requests;
	spinlock_t requests_lock;
	struct timer_list requests_oom_timer;
	
	MUTEX lock;
	unsigned chunksize;
	unsigned cachesize;
	sector_t offset;
	chunk_t chunks;
	int devnum;
	uid_t owner;
	unsigned long flags;
	struct nexus_stats stats;
	
	enum nexus_crypto suite;
	enum nexus_compress default_compression;
	compressmask_t supported_compression;
	
	struct chunkdata_table *chunkdata;
	unsigned need_user;
	wait_queue_head_t waiting_users;
};

/* nexus_dev flags */
enum dev_bits {
	__DEV_HAVE_CD_REF,    /* chunkdata holds a dev reference */
	__DEV_THR_REGISTERED, /* registered with thread.c */
	__DEV_REQ_PENDING,    /* a nexus_run_requests() job is pending */
};
#define dev_is_shutdown(dev) (list_empty(&dev->lh_devs))

/**
 * struct nexus_io_chunk - the part of a &nexus_io that applies to one chunk
 * @lh_pending : list head for &chunkdata pending queue
 * @parent     : the &nexus_io that contains us
 * @cid        : the chunk number
 * @orig_offset: byte offset into parent->orig_sg
 * @offset     : byte offset into chunk
 * @len        : length in bytes
 * @flags      : CHUNK_ flags
 * @error      : error code on I/O error, or zero
 **/
struct nexus_io_chunk {
	struct list_head lh_pending;
	struct nexus_io *parent;
	chunk_t cid;
	unsigned orig_offset;
	unsigned offset;
	unsigned len;
	unsigned flags;
	int error;
};

enum chunk_bits {
	__CHUNK_READ,         /* Needs to be read in before I/O starts */
	__CHUNK_STARTED,      /* I/O has been initiated */
	__CHUNK_COMPLETED,    /* I/O complete */
	__CHUNK_DEAD,         /* endio called */
};

/* nexus_io_chunk flags */
#define CHUNK_READ            (1 << __CHUNK_READ)
#define CHUNK_STARTED         (1 << __CHUNK_STARTED)
#define CHUNK_COMPLETED       (1 << __CHUNK_COMPLETED)
#define CHUNK_DEAD            (1 << __CHUNK_DEAD)

/**
 * struct nexus_io - wrapper data structure for a &struct request
 * @dev      : the parent device
 * @flags    : IO_ flags
 * @first_cid: the first chunk to which this io applies
 * @last_cid : the last chunk to which this io applies
 * @prio     : the I/O priority from @orig_req
 * @orig_req : the request we received from the block layer
 * @orig_sg  : mapping of the bio/bio_vec tree into a scatterlist
 * @chunks   : data structures for each chunk in the io
 *
 * A single &nexus_io consists of either a read or a write to a contiguous
 * range of sectors, and may span multiple chunks.  Each chunk within the
 * io is represented by a &struct nexus_io_chunk, and is processed
 * independently until completion.  Completion is in-order to satisfy
 * block-layer rules.
 **/
struct nexus_io {
	struct nexus_dev *dev;
	unsigned flags;
	chunk_t first_cid;
	chunk_t last_cid;
	unsigned prio;
	struct request *orig_req;
	struct scatterlist orig_sg[MAX_SEGS_PER_IO];
	struct nexus_io_chunk chunks[MAX_CHUNKS_PER_IO];
};

enum io_bits {
	__IO_WRITE,        /* Is a write request */
};

/* nexus_io flags */
#define IO_WRITE           (1 << __IO_WRITE)

/* enumerated from highest to lowest priority */
enum callback {
	CB_COMPLETE_IO,      /* completion of I/O to chunk store */
	CB_UPDATE_CHUNK,     /* chunkdata state machine */
	CB_CRYPTO,           /* encryption and decryption */
	NR_CALLBACKS
};

/**
 * mutex_lock_thread - lock a mutex from kthread context
 * @lock: the mutex
 *
 * Kernel threads can't receive signals, so they should never be interrupted.
 * On the other hand, if they're in uninterruptible sleep they contribute to
 * the load average.  So from thread context, we do an interruptible sleep
 * with no provision for catching signals.
 **/
static inline void mutex_lock_thread(MUTEX *lock)
{
	if (mutex_lock_interruptible(lock))
		BUG();
}

#ifdef CONFIG_LBD
#define SECTOR_FORMAT "%llu"
#else
#define SECTOR_FORMAT "%lu"
#endif

#define DBG_ANY		0xffffffff	/* Print if any debugging is enabled */
#define DBG_INIT	0x00000001	/* Module init and shutdown */
#define DBG_CTR		0x00000002	/* Constructor and destructor */
#define DBG_REFCOUNT	0x00000004	/* Device refcounting */
#define DBG_THREAD	0x00000008	/* Thread operations */
#define DBG_TFM		0x00000010	/* Crypto/compress operations */
#define DBG_REQUEST	0x00000020	/* Request processing */
#define DBG_CHARDEV	0x00000040	/* Character device */
#define DBG_CD		0x00000080	/* Chunkdata */
#define DBG_IO		0x00000100	/* Backing device I/O */

#define log(prio, msg, args...) printk(prio MODULE_NAME ": " msg "\n", ## args)
#define log_limit(prio, msg, args...) do { \
		if (printk_ratelimit()) \
			log(prio, msg, ## args); \
	} while (0)
#ifdef DEBUG
#define debug(type, msg, args...) do { \
		if ((type) & debug_mask) \
			log(KERN_DEBUG, msg, ## args); \
	} while (0)
#else
#define debug(args...) do {} while (0)
#endif
#define ndebug(args...) do {} while (0)

/**
 * chunk_sectors - return the number of 512-byte sectors in one chunk
 **/
static inline sector_t chunk_sectors(struct nexus_dev *dev)
{
	return dev->chunksize/512;
}

/**
 * chunk_pages - return the number of PAGE_SIZE-sized pages per chunk
 *
 * We round up in case of a partial page.
 **/
static inline unsigned chunk_pages(struct nexus_dev *dev)
{
	return (dev->chunksize + PAGE_SIZE - 1) / PAGE_SIZE;
}

/**
 * chunk_start - return the sector# of the start of the chunk containing @sect
 **/
static inline sector_t chunk_start(struct nexus_dev *dev, sector_t sect)
{
	/* We can't use the divide operator on a sector_t, because sector_t
	   might be 64 bits and 32-bit kernels need do_div() for 64-bit
	   divides */
	return sect & ~(chunk_sectors(dev) - 1);
}

/**
 * chunk_offset - return the byte offset of sector @sect within its chunk
 **/
static inline unsigned chunk_offset(struct nexus_dev *dev, sector_t sect)
{
	return 512 * (sect - chunk_start(dev, sect));
}

/**
 * chunk_remaining - return the number of bytes between @offset and chunk end
 * @offset: the offset into the chunk
 **/
static inline unsigned chunk_remaining(struct nexus_dev *dev, unsigned offset)
{
	return dev->chunksize - offset;
}

/**
 * chunk_of - return the chunk number of @sect
 **/
static inline chunk_t chunk_of(struct nexus_dev *dev, sector_t sect)
{
	/* Again, no division allowed */
	unsigned shift=fls(chunk_sectors(dev)) - 1;
	return sect >> shift;
}

/**
 * chunk_to_sector - return sector number for the first sector of chunk @cid
 **/
static inline sector_t chunk_to_sector(struct nexus_dev *dev, chunk_t cid)
{
	unsigned shift=fls(chunk_sectors(dev)) - 1;
	return cid << shift;
}

/**
 * io_chunks - return the number of chunks in this io
 **/
static inline unsigned io_chunks(struct nexus_io *io)
{
	return io->last_cid - io->first_cid + 1;
}

/* init.c */
extern int blk_major;
extern unsigned debug_mask;
struct nexus_dev *nexus_dev_ctr(char *devnode, unsigned chunksize,
			unsigned cachesize, sector_t offset,
			enum nexus_crypto crypto,
			enum nexus_compress default_compress,
			compressmask_t supported_compress);
void nexus_dev_get(struct nexus_dev *dev);
void nexus_dev_put(struct nexus_dev *dev, int unlink);
void user_get(struct nexus_dev *dev);
void user_put(struct nexus_dev *dev);
int shutdown_dev(struct nexus_dev *dev, int force);

/* request.c */
int request_start(void);
void request_shutdown(void);
void kick_elevator(struct nexus_dev *dev);
void nexus_request(struct request_queue *q);
void nexus_run_requests(struct list_head *entry);
void nexus_process_chunk(struct nexus_io_chunk *chunk,
			struct scatterlist *chunk_sg);
void oom_timer_fn(unsigned long data);

/* chardev.c */
int chardev_start(void);
void chardev_shutdown(void);

/* chunkdata.c */
int chunkdata_start(void);
void chunkdata_shutdown(void);
int chunkdata_alloc_table(struct nexus_dev *dev);
void chunkdata_free_table(struct nexus_dev *dev);
int have_usermsg(struct nexus_dev *dev);
struct chunkdata *next_usermsg(struct nexus_dev *dev, msgtype_t *type);
void fail_usermsg(struct chunkdata *cd);
void end_usermsg(struct chunkdata *cd);
void shutdown_usermsg(struct nexus_dev *dev);
void get_usermsg_get_meta(struct chunkdata *cd, unsigned long long *cid);
void get_usermsg_update_meta(struct chunkdata *cd, unsigned long long *cid,
			unsigned *length, enum nexus_compress *compression,
			char key[], char tag[]);
void set_usermsg_set_meta(struct nexus_dev *dev, chunk_t cid, unsigned length,
			enum nexus_compress compression, char key[],
			char tag[]);
void set_usermsg_meta_err(struct nexus_dev *dev, chunk_t cid);
int reserve_chunks(struct nexus_io *io);
void unreserve_chunk(struct nexus_io_chunk *chunk);
void run_chunk(struct list_head *entry);
void run_all_chunks(struct nexus_dev *dev);
void chunkdata_complete_io(struct list_head *entry);
void chunk_tfm(struct nexus_tfm_state *ts, struct list_head *entry);
struct scatterlist *alloc_scatterlist(unsigned nbytes);
void free_scatterlist(struct scatterlist *sg, unsigned nbytes);

/* transform.c */
int transform_validate(struct nexus_dev *dev);
int crypto_cipher(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, char key[], unsigned len,
			int dir, int doPad);
int crypto_hash(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, unsigned nbytes, u8 *out);
int compress_chunk(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, enum nexus_compress type);
int decompress_chunk(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, enum nexus_compress type,
			unsigned len);
int compression_type_ok(struct nexus_dev *dev, enum nexus_compress compress);
int suite_add(struct nexus_tfm_state *ts, enum nexus_crypto suite);
void suite_remove(struct nexus_tfm_state *ts, enum nexus_crypto suite);
int compress_add(struct nexus_tfm_state *ts, enum nexus_compress alg);
void compress_remove(struct nexus_tfm_state *ts, enum nexus_compress alg);
const struct tfm_suite_info *suite_info(enum nexus_crypto suite);
const struct tfm_compress_info *compress_info(enum nexus_compress alg);

/* thread.c */
int thread_start(void);
void thread_shutdown(void);
int thread_register(struct nexus_dev *dev);
void thread_unregister(struct nexus_dev *dev);
void schedule_callback(enum callback type, struct list_head *entry);
void schedule_io(struct bio *bio);
void schedule_request_callback(struct list_head *entry);
void wake_all_threads(void);

/* sysfs.c */
extern struct class_attribute class_attrs[];
extern struct class_device_attribute class_dev_attrs[];

/* revision.c */
extern char *rcs_revision;

#else  /* __KERNEL__ */
#error This header is not exported outside the Nexus implementation
#endif /* __KERNEL__ */
#endif /* NEXUS_DEFS_H */
