#ifndef LINUX_CONVERGENT_H
#define LINUX_CONVERGENT_H

#define DEBUG
#define MAX_INPUT_SEGS 32
#define MIN_CONCURRENT_REQS 2
#define MINORS 16
#define HASH_BUCKETS 128
#define CLEANER_SWEEP (HZ/2)
#define MODULE_NAME "isr-convergent"
#define SUBMIT_QUEUE "convergent-io"

#include <linux/blkdev.h>

typedef sector_t chunk_t;

/* XXX what spin_lock primitives should we use when we're using softirqs? */

struct convergent_dev {
	struct gendisk *gendisk;
	request_queue_t *queue;
	spinlock_t queue_lock;
	struct block_device *chunk_bdev;
	
	unsigned chunksize;
	sector_t offset;
	unsigned flags;
	
	struct crypto_tfm *cipher;
	struct crypto_tfm *hash;
	struct crypto_tfm *compress;
	spinlock_t tfm_lock;
	
	/* XXX make this a global object? */
	mempool_t *page_pool;
	kmem_cache_t *req_cache;
	mempool_t *req_pool;
	
	/* Must be accessed with queue lock held */
	struct registration_table *pending;
	
	/* XXX make this a global object?  we'd need a list of devs */
	struct timer_list cleaner;
	struct list_head freed_reqs;
	spinlock_t freed_lock;
};

/* convergent_dev flags */
#define DEV_KILLCLEANER  0x00000001  /* Cleaner should not reschedule itself */
#define DEV_LOWMEM       0x00000002  /* Queue stopped until requests freed */

struct convergent_req {
	struct list_head lh_freed;
	struct convergent_dev *dev;
	struct tasklet_struct callback;
	atomic_t completed;
	int error;
	unsigned flags;
	chunk_t chunk;
	chunk_t last_chunk;
	unsigned offset;  /* byte offset into chunk */
	unsigned len;     /* bytes */
	unsigned prio;
	struct request *orig_io;
	struct scatterlist orig_sg[MAX_INPUT_SEGS];
	/* XXX hack that lets us not manage yet another allocation */
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct scatterlist chunk_sg[0];
};

/* convergent_req flags */
#define REQ_RMW    0x00000001  /* Is in the read phase of read-modify-write */
#define REQ_WRITE  0x00000002  /* Is a write request */

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

extern char *svn_branch;
extern char *svn_revision;

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

int submitter_start(void);
void submitter_shutdown(void);
void submit(struct bio *bio);

void registration_shutdown(void);
int registration_start(void);
struct registration_table *registration_alloc(void);
void registration_free(struct registration_table *table);
int register_chunks(struct registration_table *table, chunk_t start, chunk_t end);
int unregister_chunk(struct registration_table *table, chunk_t chunk);

#endif
