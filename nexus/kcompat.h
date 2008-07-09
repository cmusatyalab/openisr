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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#error Kernels older than 2.6.15 are not supported
#endif

/* We (optimistically) don't check for kernel releases that are too new; the
   module will either build or it won't.  We are known to support <= 2.6.25. */

/***** Memory allocation *****************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
static inline mempool_t *mempool_create_slab_pool(int min_nr,
			struct kmem_cache *cache)
{
	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
				cache);
}
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
typedef struct class_device kdevice_t;
typedef struct class_device_attribute kdevice_attribute_t;
#define kdevice_create(cls, fmt, args...) \
	class_device_create(cls, NULL, 0, NULL, fmt, ## args)
#define kdevice_get(kdevice) \
	class_device_get(kdevice)
#define kdevice_put(kdevice) \
	class_device_put(kdevice)
#define kdevice_unregister(kdevice) \
	class_device_unregister(kdevice)
#define kdevice_get_name(kdevice) \
	(kdevice->class_id)
#define kdevice_get_data(kdevice) \
	class_get_devdata(kdevice)
#define kdevice_set_data(kdevice, data) \
	class_set_devdata(kdevice, data)
#define kdevice_create_file(kdevice, attr) \
	class_device_create_file(kdevice, attr)
#define declare_kdevice_show(name, kdevice_p, buf_p) \
	ssize_t name(kdevice_t *kdevice_p, char *buf_p)
#define declare_kdevice_store(name, kdevice_p, buf_p, len_p) \
	ssize_t name(kdevice_t *kdevice_p, const char *buf_p, size_t len_p)
#else
typedef struct device kdevice_t;
typedef struct device_attribute kdevice_attribute_t;
#define kdevice_create(cls, fmt, args...) \
	device_create(cls, NULL, 0, fmt, ## args)
#define kdevice_get(kdevice) \
	get_device(kdevice)
#define kdevice_put(kdevice) \
	put_device(kdevice)
#define kdevice_unregister(kdevice) \
	device_unregister(kdevice)
#define kdevice_get_name(kdevice) \
	(kdevice->bus_id)
#define kdevice_get_data(kdevice) \
	dev_get_drvdata(kdevice)
#define kdevice_set_data(kdevice, data) \
	dev_set_drvdata(kdevice, data)
#define kdevice_create_file(kdevice, attr) \
	device_create_file(kdevice, attr)
#define declare_kdevice_show(name, kdevice_p, buf_p) \
	ssize_t name(kdevice_t *kdevice_p, kdevice_attribute_t *attr, \
				char *buf_p)
#define declare_kdevice_store(name, kdevice_p, buf_p, len_p) \
	ssize_t name(kdevice_t *kdevice_p, kdevice_attribute_t *attr, \
				const char *buf_p, size_t len_p)
#endif

/***** Request queue/bio *****************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define end_that_request_last(req, uptodate) end_that_request_last(req)
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
/* For consistency across kernel versions, set the "scale" parameter high
   enough that no scaling will take place. */
#define bioset_create(bios, bvecs) bioset_create(bios, bvecs, 32)
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define NEXUS_ENDIO_FUNC \
	static int nexus_endio_func(struct bio *bio, unsigned nbytes, \
				int error) \
	{ \
		nexus_endio(bio, nbytes, error, bio->bi_size == 0); \
		return 0; \
	}
#else
/* As of 2.6.24 the bio_endio callback is only called once when all IO
 * has completed. */
#define NEXUS_ENDIO_FUNC \
	static void nexus_endio_func(struct bio *bio, int error) \
	{ \
		struct bio_vec *bvec; \
		int i; \
		unsigned bytes_done=0; \
		__bio_for_each_segment(bvec, bio, i, 0) \
			bytes_done += bvec->bv_len; \
		nexus_endio(bio, bytes_done, error, 1); \
	}
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define sg_next(sg) ((sg) + 1)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
/* XXX barrier request handling changes */
#endif

/***** Callbacks/deferred work ***********************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
typedef void work_t;
#define WORK_INIT(work, func) INIT_WORK(work, func, work)
#else
typedef struct work_struct work_t;
#define WORK_INIT(work, func) INIT_WORK(work, func)
#endif

/***** CPU hotplug ***********************************************************/

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
