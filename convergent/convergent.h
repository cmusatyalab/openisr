#ifndef LINUX_CONVERGENT_H
#define LINUX_CONVERGENT_H

#define DEBUG
#define MAX_SEGS_PER_IO 32
#define MAX_CHUNKS_PER_IO 32
#define MIN_CONCURRENT_REQS 2  /* XXX */
#define DEVICES 16  /* If this is more than 26, ctr will need to be fixed */
#define MINORS_PER_DEVICE 16
#define CD_MAX_CHUNKS 8192  /* XXX make this based on MB RAM in the box */
#define CLEANER_SWEEP (HZ/2)
#define MODULE_NAME "isr-convergent"
#define DEVICE_NAME "openisr"
#define SUBMIT_QUEUE "convergent-io"

#define SUPPORTED_COMPRESSION (ISR_COMPRESS_NONE | ISR_COMPRESS_ZLIB)

#include <linux/blkdev.h>
#include "convergent-user.h"

/* XXX convert chunk_t canonical name from chunk to cid */

typedef sector_t chunk_t;

struct convergent_dev {
	struct gendisk *gendisk;
	request_queue_t *queue;
	spinlock_t lock;
	struct block_device *chunk_bdev;
	
	unsigned chunksize;
	unsigned cachesize;
	sector_t offset;
	chunk_t chunks;
	int devnum;
	unsigned flags;	/* XXX racy */
	atomic_t refcount;
	
	struct crypto_tfm *cipher;
	unsigned cipher_block;
	struct crypto_tfm *hash;
	unsigned hash_len;
	
	compress_t compression;
	void *buf_compressed;
	void *buf_uncompressed;
	void *zlib_deflate;
	void *zlib_inflate;
	
	struct chunkdata_table *chunkdata;
	wait_queue_head_t waiting_users;
	
	/* XXX make this a global object?  we'd need a list of devs */
	struct timer_list cleaner;
	struct list_head freed_ios;
};

enum dev_bits {
	__DEV_KILLCLEANER,  /* Cleaner should not reschedule itself */
	__DEV_LOWMEM,       /* Queue stopped until requests freed */
	__DEV_SHUTDOWN,     /* Userspace keying daemon has gone away */
};

/* convergent_dev flags */
#define DEV_KILLCLEANER     (1 << __DEV_KILLCLEANER)
#define DEV_LOWMEM          (1 << __DEV_LOWMEM)
#define DEV_SHUTDOWN        (1 << __DEV_SHUTDOWN)

struct convergent_io_chunk {
	struct list_head lh_pending;
	struct convergent_io *parent;
	struct tasklet_struct callback;
	chunk_t chunk;
	unsigned orig_offset;  /* byte offset into orig_sg */
	unsigned offset;       /* byte offset into chunk */
	unsigned len;          /* bytes */
	unsigned flags;
	int error;
};

enum chunk_bits {
	__CHUNK_READ,         /* Needs to be read in before I/O starts */
	__CHUNK_STARTED,      /* I/O has been initiated */
	__CHUNK_COMPLETED,    /* I/O complete */
	__CHUNK_DEAD,         /* endio called */
};

/* convergent_io_chunk flags */
#define CHUNK_READ            (1 << __CHUNK_READ)
#define CHUNK_STARTED         (1 << __CHUNK_STARTED)
#define CHUNK_COMPLETED       (1 << __CHUNK_COMPLETED)
#define CHUNK_DEAD            (1 << __CHUNK_DEAD)

struct convergent_io {
	struct list_head lh_freed;
	struct convergent_dev *dev;
	unsigned flags;
	chunk_t first_chunk;
	chunk_t last_chunk;
	unsigned prio;
	struct request *orig_req;
	struct scatterlist orig_sg[MAX_SEGS_PER_IO];
	struct convergent_io_chunk chunks[MAX_CHUNKS_PER_IO];
};

enum io_bits {
	__IO_WRITE,        /* Is a write request */
};

/* convergent_io flags */
#define IO_WRITE           (1 << __IO_WRITE)

#ifdef CONFIG_LBD
#define SECTOR_FORMAT "%llu"
#else
#define SECTOR_FORMAT "%lu"
#endif

#define log(prio, msg, args...) printk(prio MODULE_NAME ": " msg "\n", ## args)
#ifdef DEBUG
#define debug(msg, args...) log(KERN_DEBUG, msg, ## args)
#else
#define debug(args...) do {} while (0)
#endif
#define ndebug(args...) do {} while (0)

/* XXX clean these out */

/* 512-byte sectors per chunk */
static inline sector_t chunk_sectors(struct convergent_dev *dev)
{
	return dev->chunksize/512;
}

/* PAGE_SIZE-sized pages per chunk, rounding up in case of a partial page */
static inline unsigned chunk_pages(struct convergent_dev *dev)
{
	return (dev->chunksize + PAGE_SIZE - 1) / PAGE_SIZE;
}

/* The sector number of the beginning of the chunk containing @sect */
static inline sector_t chunk_start(struct convergent_dev *dev, sector_t sect)
{
	/* We can't use the divide operator on a sector_t, because sector_t
	   might be 64 bits and 32-bit kernels need do_div() for 64-bit
	   divides */
	return sect & ~(chunk_sectors(dev) - 1);
}

/* The byte offset of sector @sect within its chunk */
static inline unsigned chunk_offset(struct convergent_dev *dev, sector_t sect)
{
	return 512 * (sect - chunk_start(dev, sect));
}

/* The number of bytes between @offset and the end of the chunk */
static inline unsigned chunk_remaining(struct convergent_dev *dev,
			unsigned offset)
{
	return dev->chunksize - offset;
}

/* The chunk number of @sect */
static inline chunk_t chunk_of(struct convergent_dev *dev, sector_t sect)
{
	/* Again, no division allowed */
	unsigned shift=fls(chunk_sectors(dev)) - 1;
	return sect >> shift;
}

/* The sector number corresponding to the first sector of @chunk */
static inline sector_t chunk_to_sector(struct convergent_dev *dev,
			chunk_t chunk)
{
	unsigned shift=fls(chunk_sectors(dev)) - 1;
	return chunk << shift;
}

/* The number of chunks in this io */
static inline unsigned io_chunks(struct convergent_io *io)
{
	return io->last_chunk - io->first_chunk + 1;
}

/* The number of pad bytes needed for data of length @len bytes */
static inline unsigned crypto_pad(struct convergent_dev *dev, unsigned len)
{
	unsigned partial=len % dev->cipher_block;
	if (partial)
		return dev->cipher_block - partial;
	else
		return 0;
}

/* convergent.c */
extern int blk_major;
struct convergent_dev *convergent_dev_ctr(char *devnode, unsigned chunksize,
			unsigned cachesize, sector_t offset,
			cipher_t cipher, hash_t hash, compress_t compress);
void convergent_dev_dtr(struct convergent_dev *dev);

/* chardev.c */
int chardev_start(void);
void chardev_shutdown(void);

/* workqueue.c */
int workqueue_start(void);
void workqueue_shutdown(void);
void submit(struct bio *bio);
int delayed_add_disk(struct gendisk *disk);

/* chunkdata.c */
int chunkdata_start(void);
void chunkdata_shutdown(void);
int chunkdata_alloc_table(struct convergent_dev *dev);
void chunkdata_free_table(struct convergent_dev *dev);
struct chunkdata *next_usermsg(struct convergent_dev *dev, msgtype_t *type);
void fail_usermsg(struct chunkdata *cd);
void end_usermsg(struct chunkdata *cd);
void get_usermsg_get_meta(struct chunkdata *cd, unsigned long long *cid);
void get_usermsg_update_meta(struct chunkdata *cd, unsigned long long *cid,
			unsigned *length, compress_t *compression, char key[]);
void set_usermsg_set_meta(struct convergent_dev *dev, chunk_t cid,
			unsigned length, compress_t compression, char key[]);
int reserve_chunks(struct convergent_io *io);
void unreserve_chunk(struct convergent_io_chunk *chunk);
struct scatterlist *get_scatterlist(struct convergent_io_chunk *chunk);

/* transform.c */
int transform_alloc(struct convergent_dev *dev, cipher_t cipher, hash_t hash,
			compress_t compress);
void transform_free(struct convergent_dev *dev);
int compress_chunk(struct convergent_dev *dev, struct scatterlist *sg,
			compress_t type);
int decompress_chunk(struct convergent_dev *dev, struct scatterlist *sg,
			compress_t type, unsigned len);

/* revision.c */
extern char *svn_branch;
extern char *svn_revision;

#endif
