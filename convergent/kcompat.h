#ifndef ISR_KCOMPAT_H
#define ISR_KCOMPAT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#error Kernels older than 2.6.16 are not supported
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,16)
#error Kernels newer than 2.6.16 are not supported
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
/* XXX nonseekable_open() */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* XXX unlocked_ioctl(), compat_ioctl().  do we need to register a
   compatibility shim for the ioctls to work on mixed-mode systems? */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
/* XXX blk_queue_ordered() flags */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
/* XXX class registration interface */
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
typedef unsigned gfp_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#include <linux/types.h>
static inline void kzalloc(size_t size, gfp_t gfp)
{
	void *ptr=kmalloc(size, gfp);
	if (ptr != NULL)
		memset(ptr, 0, size);
	return ptr;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
/* XXX barrier request handling changes */

#define end_that_request_last(req, uptodate) end_that_request_last(req)
#endif

/* XXX cryptoapi will significantly change in 2.6.19 */

#endif
