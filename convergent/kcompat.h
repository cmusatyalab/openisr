#ifndef ISR_KCOMPAT_H
#define ISR_KCOMPAT_H

#include <linux/version.h>

/***** Supported-version checks **********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
#error Kernels older than 2.6.13 are not supported
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#error Kernels newer than 2.6.18 are not supported
#endif

/***** Memory allocation *****************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
typedef unsigned gfp_t;
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#include <linux/types.h>
static inline void *kzalloc(size_t size, gfp_t gfp)
{
	void *ptr=kmalloc(size, gfp);
	if (ptr != NULL)
		memset(ptr, 0, size);
	return ptr;
}
#endif

/***** Mutexes ***************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#include <asm/semaphore.h>
#define MUTEX struct semaphore
#define mutex_init(lock) init_MUTEX(lock)
#define mutex_lock(lock) down(lock)
#define mutex_lock_interruptible(lock) down_interruptible(lock)
#define mutex_unlock(lock) up(lock)

static inline int mutex_is_locked(MUTEX *lock)
{
	if (down_trylock(lock)) {
		return 1;
	} else {
		up(lock);
		return 0;
	}
}
#else
#define MUTEX struct mutex
#endif

/***** Device model/sysfs ****************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
/* XXX class registration interface */
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#define class_device_create(cls, parent, devt, dev, fmt, args...) \
	class_device_create(cls, devt, dev, fmt, ## args)

/* In 2.6.15 and up, struct class_device has its own per-dev release method
   which is called in preference to the one in the class, and which is
   also *set by the initialization code* for reasons passing understanding.
   Older kernels just use the parent class' device release method. */
static inline void class_dev_set_release(struct class_device *cd,
			void (*func)(struct class_device *dev)) {}
#else
static inline void class_dev_set_release(struct class_device *cd,
			void (*func)(struct class_device *dev))
{
	cd->release=func;
}
#endif

/***** Request queue/bio *****************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#define BIO_DESTRUCTOR(name, bioset)
/* The default destructor handles this, since struct bio has a bi_set member
   which points to the bioset into which the bio should be freed. */
#define bio_set_destructor(bio, dtr) do {} while (0)
#else
#define BIO_DESTRUCTOR(name, bioset) \
		static void name(struct bio *bio) {bio_free(bio, bioset);}

static inline void bio_set_destructor(struct bio *bio,
			void (*dtr)(struct bio *bio))
{
	bio->bi_destructor=dtr;
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define end_that_request_last(req, uptodate) end_that_request_last(req)
#endif

/***** Request queue barriers ************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
/* XXX blk_queue_ordered() flags */
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
/* XXX barrier request handling changes */
#endif

/***** Callbacks/deferred work ***********************************************/

/* XXX 2.6.19 workqueue changes */

/***** file_operations methods ***********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
/* XXX nonseekable_open() */
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* XXX unlocked_ioctl(), compat_ioctl().  do we need to register a
   compatibility shim for the ioctls to work on mixed-mode systems? */
#endif

/***** cryptoapi *************************************************************/

/* XXX 2.6.19 */

/*****************************************************************************/

#endif
