#ifndef LINUX_CONVERGENT_H
#define LINUX_CONVERGENT_H

#define DEBUG
#define MAX_INPUT_SEGS 512
#define MAX_SEGS_PER_IO 32
#define MAX_CHUNKS_PER_IO 32
#define MIN_CONCURRENT_REQS 2  /* XXX */
#define DEVICES 16  /* If this is more than 26, ctr will need to be fixed */
#define MINORS_PER_DEVICE 16
#define CD_MAX_CHUNKS 8192  /* XXX make this based on MB RAM in the box */
#define CLEANER_SWEEP (HZ/2)
#define NAME_BUFLEN 32
#define MODULE_NAME "isr-convergent"
#define DEVICE_NAME "openisr"
#define SUBMIT_QUEUE "convergent-io"

#include <linux/blkdev.h>

/* XXX convert chunk_t canonical name from chunk to cid */

typedef sector_t chunk_t;

struct convergent_dev {
	struct gendisk *gendisk;
	request_queue_t *queue;
	spinlock_t queue_lock;
	struct block_device *chunk_bdev;
	
	struct scatterlist setup_sg[MAX_INPUT_SEGS];
	spinlock_t setup_lock;
	
	unsigned chunksize;
	unsigned cachesize;
	sector_t offset;
	int devnum;
	unsigned flags;	/* XXX racy */
	atomic_t refcount;
	
	struct crypto_tfm *cipher;
	struct crypto_tfm *hash;
	struct crypto_tfm *compress;
	spinlock_t tfm_lock;
	
	/* XXX this can be made global */
	kmem_cache_t *io_cache;
	mempool_t *io_pool;
	char *io_cache_name;
	
	/* Must be accessed with queue lock held */
	struct chunkdata_table *chunkdata;
	
	/* XXX make this a global object?  we'd need a list of devs */
	struct timer_list cleaner;
	struct list_head freed_ios;
	spinlock_t freed_lock;
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
	__CHUNK_COMPLETED,    /* I/O complete */
	__CHUNK_DEAD,         /* endio called */
};

/* convergent_io_chunk flags */
#define CHUNK_READ            (1 << __CHUNK_READ)
#define CHUNK_COMPLETED       (1 << __CHUNK_COMPLETED)
#define CHUNK_DEAD            (1 << __CHUNK_DEAD)

/* XXX (tune performance *before* doing userspace crypto, since
   we'll need the data structures.)  move chunk page lifecycle management
   into chunkdata, so that io processing becomes just requesting chunks and
   then chunkdata doing a single callback into convergent.c to do whatever
   I/O is pending for those chunks.  IOW, read-chunk-from-disk and
   write-chunk-to-disk become the responsibility of chunkdata.c. */
/* XXX coarser-grained locking */
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
	spinlock_t lock;
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

/* convergent.c */
extern int blk_major;
struct convergent_dev *convergent_dev_ctr(char *devnode, unsigned chunksize,
			unsigned cachesize, sector_t offset);
void convergent_dev_dtr(struct convergent_dev *dev);
void convergent_process_io(struct convergent_io *io);

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
int chunkdata_alloc_table(struct convergent_dev *dev);
void chunkdata_free_table(struct convergent_dev *dev);
int reserve_chunks(struct convergent_io *io);
void unreserve_chunk(struct convergent_io_chunk *chunk);
struct scatterlist *get_scatterlist(struct convergent_io_chunk *chunk);

/* revision.c */
extern char *svn_branch;
extern char *svn_revision;

#endif
