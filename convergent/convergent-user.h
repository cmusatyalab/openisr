#ifndef LINUX_CONVERGENT_USER_H
#define LINUX_CONVERGENT_USER_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define ISR_MAX_DEVICE_LEN 64
#define ISR_MAX_HASH_LEN 32

#define ISR_IOC_REGISTER      _IOWR(0x1a, 0, struct isr_setup)
#define ISR_IOC_UNREGISTER      _IO(0x1a, 1)

#define ISR_INTERFACE_VERSION 3

typedef __u16 crypto_t;
typedef __u16 compress_t;
typedef __u16 msgtype_t;

/* This structure must have an identical layout on 32-bit and 64-bit systems */
struct isr_setup {
	__u8 chunk_device[ISR_MAX_DEVICE_LEN];/* to kernel */
	__u64 offset;                         /* to kernel */
	__u32 chunksize;                      /* to kernel */
	__u32 cachesize;                      /* to kernel */
	crypto_t crypto;                      /* to kernel */
	compress_t compress_default;          /* to kernel */
	compress_t compress_required;         /* to kernel */
	__u16 pad;
	__u64 chunks;                         /* to user */
	__u32 major;                          /* to user */
	__u32 first_minor;                    /* to user */
	__u32 minors;                         /* to user */
	__u8 hash_len;                        /* to user */
};

#define ISR_CRYPTO_BLOWFISH_SHA1        ((crypto_t)  0x0001)
#define ISR_CRYPTO_BLOWFISH_SHA1_COMPAT ((crypto_t)  0x0002)
#define ISR_COMPRESS_NONE               ((compress_t)0x0001)
#define ISR_COMPRESS_ZLIB               ((compress_t)0x0002)
#define ISR_COMPRESS_LZF                ((compress_t)0x0004)

/* This structure must have an identical layout on 32-bit and 64-bit systems */
struct isr_message {
	__u64 chunk;
	__u32 length;
	msgtype_t type;
	compress_t compression;
	__u8 key[ISR_MAX_HASH_LEN];
	__u8 tag[ISR_MAX_HASH_LEN];
};

/* Kernel to user */
#define ISR_MSGTYPE_GET_META     ((msgtype_t) 0x0000)
#define ISR_MSGTYPE_UPDATE_META  ((msgtype_t) 0x0001)
/* User to kernel */
#define ISR_MSGTYPE_SET_META     ((msgtype_t) 0x1000)
#define ISR_MSGTYPE_META_HARDERR ((msgtype_t) 0x1001)

#endif
