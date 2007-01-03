#ifndef NEXUS_KCOMPAT_H
#define NEXUS_KCOMPAT_H
#ifdef __KERNEL__

#include <linux/version.h>

/***** Supported-version checks **********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#error Kernels older than 2.6.8 are not supported
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

/* As of 2.6.18, there are three cases.  There are expected to be more in
   the future.
   
   < 2.6.13: There are no provided functions for dynamically allocating
   classes and class devices.  Classes' and classdevs' release functions are
   pointed to by the class.
   
   2.6.13-14: There are functions for dynamically allocating classes and
   classdevs, but the release function pointers are still in the class.
   Default release functions (that just call kfree) are provided for the
   class and classdev.
   
   >= 2.6.15: The classdev release function pointer is now stored in both the
   class and the classdev, with the one in the classdev used preferentially.
   *Both* pointers are automatically set to the default release function,
   for reasons passing understanding.
   
   According to Greg KH, we're supposed to start treating classes as opaque
   objects, so we need to allocate them dynamically, but we need to make
   sure the release function is properly configured even if we can't reach
   into the class struct.  So, we have both the class and class_dev
   constructor wrappers take a function pointer; the pointer in the classdev
   will be set if it exists, and the one in the class will be used
   otherwise. */

typedef void (*class_dev_rel_func)(struct class_device *);


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
static inline struct class *create_class(char *name, class_dev_rel_func func)
{
	struct class *cls;
	int ret;
	
	cls=kzalloc(sizeof(*cls), GFP_KERNEL);
	if (cls == NULL) {
		ret=-ENOMEM;
		goto bad;
	}
	cls->name=name;
	cls->class_release=(void (*)(struct class *))kfree;  /* evil */
	cls->release=func;
	ret=class_register(cls);
	if (ret)
		goto bad;
	return cls;
	
bad:
	kfree(cls);
	return ERR_PTR(ret);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
static inline struct class *create_class(char *name, class_dev_rel_func func)
{
	struct class *cls=class_create(THIS_MODULE, name);
	if (IS_ERR(cls))
		return cls;
	cls->release=func;
	return cls;
}
#else
static inline struct class *create_class(char *name, class_dev_rel_func func)
{
	return class_create(THIS_MODULE, name);
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
static inline struct class_device *create_class_dev(struct class *cls,
			class_dev_rel_func func, char *fmt, ...)
{
	struct class_device *class_dev=kzalloc(sizeof(*class_dev), GFP_KERNEL);
	va_list ap;
	int ret;
	
	if (class_dev == NULL)
		return ERR_PTR(-ENOMEM);
	class_dev->class=cls;
	va_start(ap, fmt);
	vsnprintf(class_dev->class_id, sizeof(class_dev->class_id), fmt, ap);
	va_end(ap);
	
	ret=class_device_register(class_dev);
	if (ret) {
		kfree(class_dev);
		return ERR_PTR(ret);
	}
	return class_dev;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#define create_class_dev(cls, func, fmt, args...) \
			class_device_create(cls, 0, NULL, fmt, ## args)
#else
/* Note: different parameter list for class_device_create() */
#define create_class_dev(cls, func, fmt, args...) ({ \
	struct class_device *class_dev=class_device_create(cls, NULL, 0, \
				NULL, fmt, ## args); \
	if (!IS_ERR(class_dev)) \
		class_dev->release=func; \
	class_dev; \
})
#endif

/***** Request queue/bio *****************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
/* XXX this may introduce low-memory deadlocks.  theoretically we could
   reimplement bio_alloc() to avoid this. */
#define bio_alloc_bioset(mask, vecs, set) bio_alloc(mask, vecs)
#define bioset_create_wrapper(biosz, bvecsz, scale) (NULL)
#define bioset_free(bset) do {} while (0)
#else
static inline struct bio_set *bioset_create_wrapper(int bio_cnt, int bvec_cnt,
			int scale)
{
	struct bio_set *bset=bioset_create(bio_cnt, bvec_cnt, scale);
	if (bset == NULL)
		return ERR_PTR(-ENOMEM);
	return bset;
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
/* I/O priorities appear to be unimplemented */
#define bio_set_prio(bio, prio) do {} while (0)
#define req_get_prio(req) (0)
#else
#define req_get_prio(req) (req->ioprio)
#endif


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

/***** CPU hotplug ***********************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define for_each_possible_cpu(cpu) for_each_cpu(cpu)
#endif

/***** file_operations methods ***********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* XXX do we need to register a compatibility shim for old-style ioctls to
   work on mixed-mode systems? */
/* XXX implicit cast when converting from old ioctl on 64-bit systems? */
#endif

/***** cryptoapi *************************************************************/

#if (!defined(CONFIG_X86) && !defined(CONFIG_UML_X86)) || defined(CONFIG_64BIT)
struct crypto_tfm;
static inline int sha1_impl_is_suboptimal(struct crypto_tfm *tfm)
{
	/* No optimized implementation exists */
	return 0;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/crypto.h>
static inline int sha1_impl_is_suboptimal(struct crypto_tfm *tfm)
{
	/* There's a driver name field we can look at */
	return strcmp(tfm->__crt_alg->cra_driver_name, "sha1-i586") ? 1 : 0;
}
#else
#include <linux/crypto.h>
static inline int sha1_impl_is_suboptimal(struct crypto_tfm *tfm)
{
	/* There's no driver name field, but optimized sha1 can never be
	   compiled into the kernel, so we look at struct module */
	if (tfm->__crt_alg->cra_module == NULL)
		return 1;
	return strcmp(tfm->__crt_alg->cra_module->name, "sha1_i586") ? 1 : 0;
}
#endif


/* XXX 2.6.19 */

/*****************************************************************************/

#else  /* __KERNEL__ */
#error This header is not exported outside the Nexus implementation
#endif /* __KERNEL__ */
#endif /* NEXUS_KCOMPAT_H */
