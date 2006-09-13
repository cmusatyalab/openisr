#ifndef LINUX_CONVERGENT_H
#define LINUX_CONVERGENT_H

#define DEBUG
#define MAX_INPUT_SEGS 512
#define MAX_SEGS_PER_IO 32
#define MIN_CONCURRENT_REQS 2
#define DEVICES 16  /* If this is more than 26, ctr will need to be fixed */
#define MINORS_PER_DEVICE 16
#define CD_HASH_BUCKETS 4096
#define CD_MAX_CHUNKS 2048
#define CLEANER_SWEEP (HZ/2)
#define NAME_BUFLEN 32
#define MODULE_NAME "isr-convergent"
#define DEVICE_NAME "openisr"
#define SUBMIT_QUEUE "convergent-io"

#include <linux/blkdev.h>

typedef sector_t chunk_t;

struct convergent_dev {
	struct gendisk *gendisk;
	request_queue_t *queue;
	spinlock_t queue_lock;
	struct block_device *chunk_bdev;
	/* Protected by queue_lock */
	struct scatterlist setup_sg[MAX_INPUT_SEGS];
	
	unsigned chunksize;
	sector_t offset;
	int devnum;
	unsigned flags;	/* XXX racy */
	atomic_t refcount;
	
	struct crypto_tfm *cipher;
	struct crypto_tfm *hash;
	struct crypto_tfm *compress;
	spinlock_t tfm_lock;
	
	/* XXX make this a global object? */
	mempool_t *page_pool;
	kmem_cache_t *io_cache;
	mempool_t *io_pool;
	char *io_cache_name;
	
	/* Must be accessed with queue lock held */
	struct chunkdata_table *chunkdata;
	struct list_head pending_reserved;  /* requests */
	
	/* XXX make this a global object?  we'd need a list of devs */
	struct timer_list cleaner;
	struct list_head freed_ios;
	spinlock_t freed_lock;
};

/* convergent_dev flags */
#define DEV_KILLCLEANER  0x00000001  /* Cleaner should not reschedule itself */
#define DEV_LOWMEM       0x00000002  /* Queue stopped until requests freed */
#define DEV_SHUTDOWN     0x00000004  /* Userspace keying daemon has gone away */

struct convergent_io {
	struct list_head lh_freed;
	struct convergent_dev *dev;
	struct tasklet_struct callback;
	atomic_t completed;    /* bytes */
	int error;
	unsigned flags;
	chunk_t chunk;
	chunk_t last_chunk;    /* multiple-chunk requests */
	unsigned offset;       /* byte offset into chunk */
	unsigned len;          /* bytes */
	unsigned prio;
	struct request *orig_req;
	struct scatterlist orig_sg[MAX_SEGS_PER_IO];
	/* XXX hack that lets us not manage yet another allocation */
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct scatterlist chunk_sg[0];
};

/* convergent_io flags */
#define IO_RMW       0x00000001  /* Is in the read phase of read-modify-write */
#define IO_WRITE     0x00000002  /* Is a write request */
#define IO_KEEPCHUNK 0x00000004  /* Don't unreserve the chunk when done */

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

/* The number of bytes between the start of @sect and the end of the chunk */
static inline unsigned chunk_space(struct convergent_dev *dev, sector_t sect)
{
	return dev->chunksize - chunk_offset(dev, sect);
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

/* convergent.c */
extern int blk_major;
struct convergent_dev *convergent_dev_ctr(char *devnode,
			unsigned chunksize, sector_t offset);
void convergent_dev_dtr(struct convergent_dev *dev);

/* chardev.c */
int chardev_start(void);
void chardev_shutdown(void);

/* submitter.c */
int submitter_start(void);
void submitter_shutdown(void);
void submit(struct bio *bio);

/* chunkdata.c */
int chunkdata_start(void);
void chunkdata_shutdown(void);
struct chunkdata_table *chunkdata_alloc_table(void);
void chunkdata_free_table(struct chunkdata_table *table);
int reserve_chunks(struct chunkdata_table *table, chunk_t start,
			chunk_t end);
int unreserve_chunk(struct chunkdata_table *table, chunk_t chunk);
int unreserve_chunks(struct chunkdata_table *table, chunk_t start,
			chunk_t end);

/* revision.c */
extern char *svn_branch;
extern char *svn_revision;

#endif
