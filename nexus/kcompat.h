/* kcompat.h - compatibility macros for different kernel versions */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (R)
 *         system
 * 
 * Copyright (C) 2006-2008 Carnegie Mellon University
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

#ifndef NEXUS_KCOMPAT_H
#define NEXUS_KCOMPAT_H
#ifdef __KERNEL__

#include <linux/version.h>

/***** Supported-version checks **********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8)
#error Kernels older than 2.6.8 are not supported
#endif

/* We (optimistically) don't check for kernel releases that are too new; the
   module will either build or it won't.  We are known to support <= 2.6.25. */

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


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
static inline char *kstrdup(const char *str, gfp_t flags)
{
	size_t len;
	char *new;
	
	if (str == NULL)
		return NULL;
	len=strlen(str);
	new=kmalloc(len + 1, flags);
	if (new == NULL)
		return NULL;
	memcpy(new, str, len + 1);
	return new;
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
/* This is struct kmem_cache_s up to 2.6.14 and struct kmem_cache thereafter.
   "#define kmem_cache kmem_cache_s" would pick up every instance of that
   string, not just the struct names, so we don't do it. */
typedef kmem_cache_t kmem_cache;
#else
typedef struct kmem_cache kmem_cache;
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#define kmem_cache_create(name, size, align, flags, ctor) \
			kmem_cache_create(name, size, align, flags, ctor, NULL)
#endif

/***** Mutexes ***************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#include <asm/semaphore.h>
#define MUTEX struct semaphore
#define mutex_init(lock) init_MUTEX(lock)
#define mutex_lock(lock) down(lock)
#define mutex_lock_interruptible(lock) down_interruptible(lock)
#define mutex_unlock(lock) up(lock)
#define mutex_trylock(lock) (!down_trylock(lock))

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

/***** Linked lists **********************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define list_first_entry(head, type, field) \
			list_entry((head)->next, type, field)
#endif

/***** Device model/sysfs ****************************************************/

/**
 * read_refcount_debug - return the current refcount of @kobj
 *
 * This is for debug use only.
 **/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
static inline int read_refcount_debug(struct kobject *kobj)
{
	return atomic_read(&kobj->refcount);
}
#else
static inline int read_refcount_debug(struct kobject *kobj)
{
	return atomic_read(&kobj->kref.refcount);
}
#endif


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

/* The CFQ I/O scheduler in kernels 2.6.10 and above can hold request queue
   references for a very long time: if a process (e.g. kblockd) has ever done
   I/O to a block device, the process will hold a reference to its queue
   until it exits.  At that time, the request queue spinlock will be locked,
   which means we can't have freed the lock while shutting down the block
   device.  Kernels 2.6.12 and above allow us to pass a NULL spinlock pointer
   to blk_init_queue(), which will allocate a spinlock along with the request
   queue structure, thus maintaining these lifetime rules.  For older kernels,
   we pass a static spinlock instead, in an attempt to ensure that the spinlock
   lasts as long as we need it to.  For kernels 2.6.10 and above, we also
   disallow module unloading, since we can make no assumptions about the
   lifetimes of all processes which ever opened our block device.  According to
   Jens Axboe, the block layer core may also hold a reference to the request
   queue after the device is gone, but only for a short time, so for < 2.6.10
   we take the risk of an unload race and allow the module to be unloaded.
   
   Note that this approach prevents request functions for multiple block
   devices from running at the same time, for kernels < 2.6.12. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#define NEXUS_NO_UNLOAD
#endif
#define init_request_queue(reqfn, lock) blk_init_queue(reqfn, lock)
#define GLOBAL_QUEUE_LOCK(lockname) static spinlock_t lockname
#define INIT_QUEUE_LOCK(lockname) spin_lock_init(lockname)
#else
#define init_request_queue(reqfn, lock) blk_init_queue(reqfn, NULL)
#define GLOBAL_QUEUE_LOCK(lockname)
#define INIT_QUEUE_LOCK(lockname)
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
/* XXX this may introduce low-memory deadlocks.  theoretically we could
   reimplement bio_alloc() to avoid this. */
#define bio_alloc_bioset(mask, vecs, set) bio_alloc(mask, vecs)
#define bioset_create_wrapper(biosz, bvecsz) (NULL)
#define bioset_free(bset) do {} while (0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
static inline struct bio_set *bioset_create_wrapper(int bio_cnt, int bvec_cnt)
{
	/* For consistency across kernel versions, set the "scale" parameter
	   high enough that no scaling will take place. */
	struct bio_set *bset=bioset_create(bio_cnt, bvec_cnt, 32);
	if (bset == NULL)
		return ERR_PTR(-ENOMEM);
	return bset;
}
#else
static inline struct bio_set *bioset_create_wrapper(int bio_cnt, int bvec_cnt)
{
	struct bio_set *bset=bioset_create(bio_cnt, bvec_cnt);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* As of 2.6.24 the bio_endio callback is only called once when all IO
 * has completed. */
#define NEXUS_ENDIO_FUNC nexus_endio_func
#define NEXUS_ENDIO_WRAP
#else
#define NEXUS_ENDIO_FUNC nexus_endio
#define NEXUS_ENDIO_WRAP \
	static void nexus_endio(struct bio *bio, int error) { \
		unsigned bytes_done=bio->bi_size; bio->bi_size=0; \
		nexus_endio_func(bio, bytes_done, error); }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
static inline int __blk_end_request(struct request *req, int error,
			int nr_bytes)
{
	int uptodate = (error == 0) ? 1 : (error == -EIO) ? 0 : error;
	int nr_sectors = (nr_bytes+511)>>9;
	if (end_that_request_first(req, uptodate, nr_sectors))
		return 1;
	end_that_request_last(req, uptodate);
	return 0;
}
#endif


/***** Scatterlists **********************************************************/

#include <linux/scatterlist.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define sg_next(sg) ((sg)++)
#define sg_page(sg) ((sg)->page)
static inline void sg_init_table(struct scatterlist *sg, unsigned int nents)
{
	memset(sg, 0, sizeof(*sg) * nents);
}
static inline void sg_set_page(struct scatterlist *sg, struct page *page,
				unsigned int length, unsigned int offset)
{
	sg->page = page;
	sg->offset = offset;
	sg->length = length;
}
#endif

/***** Request queue barriers ************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
/* XXX blk_queue_ordered() flags */
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
/* XXX barrier request handling changes */
#endif

/***** Callbacks/deferred work ***********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
static inline void setup_timer(struct timer_list *timer,
			void (*func)(unsigned long), unsigned long data)
{
	init_timer(timer);
	timer->function=func;
	timer->data=data;
}
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
typedef void work_t;
#define WORK_INIT(work, func) INIT_WORK(work, func, work)
#else
typedef struct work_struct work_t;
#define WORK_INIT(work, func) INIT_WORK(work, func)
#endif

/***** CPU hotplug ***********************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
/* CPU_DOWN_PREPARE callback doesn't exist.  Define the constant anyway, such
   that all plausible comparisons to it return false. */
#define CPU_DOWN_PREPARE 0xbadda7a
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
/* for_each_possible_cpu() was added in the middle of the 2.6.16 stable
   series */
#ifndef for_each_possible_cpu
#define for_each_possible_cpu(cpu) for_each_cpu(cpu)
#endif
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define register_hotcpu_notifier(nb) register_cpu_notifier(nb)
#define unregister_hotcpu_notifier(nb) unregister_cpu_notifier(nb)
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define get_online_cpus() lock_cpu_hotplug()
#define put_online_cpus() unlock_cpu_hotplug()
#endif

/***** file_operations methods ***********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)
/* XXX do we need to register a compatibility shim for old-style ioctls to
   work on mixed-mode systems? */
/* XXX implicit cast when converting from old ioctl on 64-bit systems? */
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define fops_flush_method(name, filp) int name(struct file *filp)
#else
#define fops_flush_method(name, filp) \
	int name(struct file *filp, fl_owner_t ignored)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define nd_path_dentry(nd) (nd).dentry
#else
#define nd_path_dentry(nd) (nd).path.dentry
#define path_release(ndp) path_put(&(ndp)->path);
#endif

/***** Software suspend ******************************************************/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
/* This used to be in sched.h */
#include <linux/freezer.h>
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static inline void set_nonfreezable(void)
{
	current->flags |= PF_NOFREEZE;
}
#else
/* Kernel threads are non-freezable by default */
#define set_nonfreezable() do {} while (0)
#endif

/***** cryptoapi *************************************************************/

#include <linux/crypto.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
/* Older kernels just check for in_softirq() or in_atomic(), so no flag needs
   to be set */
#define CRYPTO_TFM_REQ_MAY_SLEEP 0
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define crypto_blkcipher crypto_tfm
#define crypto_hash      crypto_tfm
#define crypto_blkcipher_set_iv(tfm, iv, size) \
	crypto_cipher_set_iv(tfm, iv, size)
#define crypto_blkcipher_setkey(tfm, key, size) \
	crypto_cipher_setkey(tfm, key, size)
#define cryptoapi_encrypt(tfm, dst, src, len) \
	crypto_cipher_encrypt(tfm, dst, src, len)
#define cryptoapi_decrypt(tfm, dst, src, len) \
	crypto_cipher_decrypt(tfm, dst, src, len)
#define crypto_free_blkcipher(tfm) crypto_free_tfm(tfm)
#define crypto_free_hash(tfm) crypto_free_tfm(tfm)

static inline struct crypto_blkcipher
		*cryptoapi_alloc_cipher(const struct tfm_suite_info *info)
{
	struct crypto_blkcipher *ret;
	ret=crypto_alloc_tfm(info->cipher_name,
				info->cipher_mode | CRYPTO_TFM_REQ_MAY_SLEEP);
	if (ret == NULL)
		return ERR_PTR(-EINVAL);
	return ret;
}

static inline struct crypto_hash
			*cryptoapi_alloc_hash(const struct tfm_suite_info *info)
{
	struct crypto_hash *ret;
	ret=crypto_alloc_tfm(info->hash_name, CRYPTO_TFM_REQ_MAY_SLEEP);
	if (ret == NULL)
		return ERR_PTR(-EINVAL);
	return ret;
}

/* XXX verify this against test vectors */
static inline int cryptoapi_hash(struct crypto_hash *tfm,
			struct scatterlist *sg, unsigned nbytes, u8 *out)
{
	int i;
	unsigned saved;
	
	/* For some reason, the old-style digest function expects nsg rather
	   than nbytes.  However, we may want the hash to include only part of
	   a page.  Thus this nonsense. */
	for (i=0; sg[i].length < nbytes; i++)
		nbytes -= sg[i].length;
	saved=sg[i].length;
	sg[i].length=nbytes;
	crypto_digest_digest(tfm, sg, i + 1, out);
	sg[i].length=saved;
	return 0;
}
#else
#ifndef CRYPTO_TFM_MODE_CBC
/* The old crypto mode constants have been removed starting in 2.6.21.  We
   don't use them when compiled against the new cryptoapi, but they're still
   included in the tfm_suite_info struct, so we have to define them anyway. */
#define CRYPTO_TFM_MODE_CBC 0
#endif

#define cryptoapi_alloc_hash(info) \
	crypto_alloc_hash(info->hash_name, 0, CRYPTO_ALG_ASYNC)

static inline struct crypto_blkcipher
		*cryptoapi_alloc_cipher(const struct tfm_suite_info *info)
{
	char alg[CRYPTO_MAX_ALG_NAME];
	snprintf(alg, sizeof(alg), "%s(%s)", info->cipher_mode_name,
				info->cipher_name);
	return crypto_alloc_blkcipher(alg, 0, CRYPTO_ALG_ASYNC);
}

static inline int cryptoapi_encrypt(struct crypto_blkcipher *tfm,
			struct scatterlist *dst, struct scatterlist *src,
			unsigned len)
{
	struct blkcipher_desc desc;
	desc.tfm=tfm;
	desc.flags=CRYPTO_TFM_REQ_MAY_SLEEP;
	return crypto_blkcipher_encrypt(&desc, dst, src, len);
}

static inline int cryptoapi_decrypt(struct crypto_blkcipher *tfm,
			struct scatterlist *dst, struct scatterlist *src,
			unsigned len)
{
	struct blkcipher_desc desc;
	desc.tfm=tfm;
	desc.flags=CRYPTO_TFM_REQ_MAY_SLEEP;
	return crypto_blkcipher_decrypt(&desc, dst, src, len);
}

static inline int cryptoapi_hash(struct crypto_hash *tfm,
			struct scatterlist *sg, unsigned nbytes, u8 *out)
{
	struct hash_desc desc;
	desc.tfm=tfm;
	desc.flags=CRYPTO_TFM_REQ_MAY_SLEEP;
	return crypto_hash_digest(&desc, sg, nbytes, out);
}
#endif


/**
 * sha1_impl_is_suboptimal - return true if we want a better SHA-1
 *
 * Checks the underlying implementation of the supplied @tfm.  If @tfm
 * uses the generic C implementation and we're on an architecture that has
 * an optimized assembly implementation, returns true.  Otherwise returns
 * false.
 **/
#if (defined(CONFIG_X86) || defined(CONFIG_UML_X86))
#ifdef CONFIG_64BIT
#define SHA1_ACCEL_ARCH "x86_64"
#else
#define SHA1_ACCEL_ARCH "i586"
#endif
#endif

#ifndef SHA1_ACCEL_ARCH
#define SHA1_ACCEL_ARCH "unknown"
/* No optimized implementation exists */
#define sha1_impl_is_suboptimal(tfm) (0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
static inline int sha1_impl_is_suboptimal(struct crypto_hash *tfm)
{
	/* There's no driver name field, but optimized sha1 can never be
	   compiled into the kernel, so we look at struct module */
	if (tfm->__crt_alg->cra_module == NULL)
		return 1;
	return strcmp(tfm->__crt_alg->cra_module->name, "sha1_" SHA1_ACCEL_ARCH)
				? 1 : 0;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static inline int sha1_impl_is_suboptimal(struct crypto_hash *tfm)
{
	/* There's a driver name field we can look at */
	return strcmp(tfm->__crt_alg->cra_driver_name, "sha1-" SHA1_ACCEL_ARCH)
				? 1 : 0;
}
#else
static inline int sha1_impl_is_suboptimal(struct crypto_hash *tfm)
{
	/* We need to extract the crypto_tfm from the crypto_hash */
	return strcmp(crypto_hash_tfm(tfm)->__crt_alg->cra_driver_name,
				"sha1-" SHA1_ACCEL_ARCH) ? 1 : 0;
}
#endif


/**
 * aes_impl_is_suboptimal - return true if we want a better AES
 *
 * Checks the underlying implementation of the supplied @tfm.  If @tfm
 * uses the generic C implementation and we're on an architecture that
 * experiences dramatic performance improvements with an assembly
 * implementation, returns true.  Otherwise returns false.
 *
 * x86-64 is not considered, since the performance improvements provided
 * by the optimized implementation appear to be minimal.
 **/
#if (defined(CONFIG_X86) || defined(CONFIG_UML_X86)) && !defined(CONFIG_64BIT)
#define AES_ACCEL_ARCH "i586"
#endif

#ifndef AES_ACCEL_ARCH
#define AES_ACCEL_ARCH "unknown"
/* No sufficiently-optimized implementation exists */
#define aes_impl_is_suboptimal(info, tfm) (0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
/* For architectures with optimized AES, Kconfig does not offer to build the
   generic version.  If we have AES, it's optimized. */
#define aes_impl_is_suboptimal(info, tfm) (0)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static inline int aes_impl_is_suboptimal(const struct tfm_suite_info *info,
			struct crypto_blkcipher *tfm)
{
	/* Look at the driver name field */
	return strcmp(tfm->__crt_alg->cra_driver_name, "aes-" AES_ACCEL_ARCH)
				? 1 : 0;
}
#else
static inline int aes_impl_is_suboptimal(const struct tfm_suite_info *info,
			struct crypto_blkcipher *tfm)
{
	/* Look at the driver name field in the crypto_tfm, which needs to be
	   extracted from the crypto_blkcipher.  The driver name contains the
	   cipher mode. */
	char buf[CRYPTO_MAX_ALG_NAME];
	snprintf(buf, sizeof(buf), "%s(aes-" AES_ACCEL_ARCH ")",
				info->cipher_mode_name);
	return strcmp(crypto_blkcipher_tfm(tfm)->__crt_alg->cra_driver_name,
				buf) ? 1 : 0;
}
#endif

/*****************************************************************************/

#else  /* __KERNEL__ */
#error This header is not exported outside the Nexus implementation
#endif /* __KERNEL__ */
#endif /* NEXUS_KCOMPAT_H */
