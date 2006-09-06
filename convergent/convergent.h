#ifndef LINUX_CONVERGENT_H
#define LINUX_CONVERGENT_H

#define DEBUG
#define MAX_INPUT_SEGS 32
#define MIN_CONCURRENT_REQS 2
#define MINORS 16
#define HASH_BUCKETS 128
#define MODULE_NAME "isr-convergent"

typedef sector_t chunk_t;

struct convergent_dev {
	struct gendisk *gendisk;
	request_queue_t *queue;
	struct block_device *chunk_bdev;
	
	unsigned chunksize;
	sector_t offset;
	
	struct crypto_tfm *cipher;
	struct crypto_tfm *hash;
	struct crypto_tfm *compress;
	spinlock_t tfm_lock;
	
	/* XXX make this a global object? */
	mempool_t *page_pool;
	kmem_cache_t *req_cache;
	mempool_t *req_pool;
	
	struct list_head pending_reqs[HASH_BUCKETS];
	spinlock_t pending_lock;
};

struct convergent_req {
	struct list_head lh_bucket;
	struct list_head lh_chained;
	struct convergent_dev *dev;
	struct work_struct work;
	atomic_t completed;
	int error;
	unsigned flags;
	/* XXX this member contains redundant information - eliminate? */
	chunk_t chunk;
	struct bio *orig_bio;
	struct scatterlist orig_sg[MAX_INPUT_SEGS];
	/* XXX hack that lets us not manage yet another allocation */
	/* THIS MUST BE THE LAST MEMBER OF THE STRUCTURE */
	struct scatterlist chunk_sg[0];
};

/* convergent_req flags */
#define REQ_RMW    0x00000001  /* Is in the read phase of read-modify-write */

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

/* The chunk number of @sect */
static inline chunk_t chunk_of(struct convergent_dev *dev, sector_t sect)
{
	/* Again, no division allowed */
	unsigned shift=fls(chunk_sectors(dev)) - 1;
	return sect >> shift;
}

#endif
