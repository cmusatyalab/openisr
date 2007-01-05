#ifndef ISR_NEXUS_H
#define ISR_NEXUS_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define NEXUS_MAX_DEVICE_LEN 64
#define NEXUS_MAX_HASH_LEN 32

#define NEXUS_IOC_REGISTER      _IOWR(0x1a, 0, struct nexus_setup)
#define NEXUS_IOC_UNREGISTER      _IO(0x1a, 1)

#define NEXUS_INTERFACE_VERSION 5

typedef __u16 compressmask_t;
typedef __u16 msgtype_t;

/* The numeric values of these symbols are not guaranteed to remain constant!
   Don't use them in an on-disk format! */
enum nexus_crypto {
	NEXUS_CRYPTO_BLOWFISH_SHA1,
	NEXUS_CRYPTO_BLOWFISH_SHA1_COMPAT,
	NEXUS_NR_CRYPTO
};

enum nexus_compress {
	NEXUS_COMPRESS_NONE,
	NEXUS_COMPRESS_ZLIB,
	NEXUS_COMPRESS_LZF,
	NEXUS_NR_COMPRESS
};

/* This structure must have an identical layout on 32-bit and 64-bit systems.
   We don't use enum types for crypto and compress fields because the compiler
   could pick any size for them */
struct nexus_setup {
	__u8 chunk_device[NEXUS_MAX_DEVICE_LEN]; /* to kernel */
	__u64 offset;                            /* to kernel */
	__u32 chunksize;                         /* to kernel */
	__u32 cachesize;                         /* to kernel */
	__u8 crypto;                      /* to kernel, enum nexus_crypto */
	__u8 compress_default;            /* to kernel, enum nexus_compress */
	compressmask_t compress_required; /* to kernel, bitmask */
	__u32 pad;
	__u64 chunks;                            /* to user */
	__u32 major;                             /* to user */
	__u32 num_minors;                        /* to user */
	__u32 index;                             /* to user */
	__u8 hash_len;                           /* to user */
};

/* This structure must have an identical layout on 32-bit and 64-bit systems.
   We don't use enum types for crypto and compress fields because the compiler
   could pick any size for them */
struct nexus_message {
	__u64 chunk;
	__u32 length;
	msgtype_t type;
	__u8 compression;                  /* enum nexus_compress */
	__u8 key[NEXUS_MAX_HASH_LEN];
	__u8 tag[NEXUS_MAX_HASH_LEN];
};

/* Kernel to user */
#define NEXUS_MSGTYPE_GET_META     ((msgtype_t) 0x0000)
#define NEXUS_MSGTYPE_UPDATE_META  ((msgtype_t) 0x0001)
/* User to kernel */
#define NEXUS_MSGTYPE_SET_META     ((msgtype_t) 0x1000)
#define NEXUS_MSGTYPE_META_HARDERR ((msgtype_t) 0x1001)


#ifdef __KERNEL__
static inline void __nexus_h_sanity_check(void)
{
	struct nexus_setup setup;
	struct nexus_message message;
	
	/* Make sure the relevant structure fields are big enough to hold
	   every possible value of their corresponding enums */
	BUILD_BUG_ON((1 << (8 * sizeof(setup.crypto))) < NEXUS_NR_CRYPTO);
	BUILD_BUG_ON((1 << (8 * sizeof(setup.compress_default)))
				< NEXUS_NR_COMPRESS);
	BUILD_BUG_ON((1 << (8 * sizeof(message.compression)))
				< NEXUS_NR_COMPRESS);
	BUILD_BUG_ON(8 * sizeof(compressmask_t) < NEXUS_NR_COMPRESS);
	
	/* Alignment of struct nexus_setup depends on this */
	BUILD_BUG_ON(NEXUS_MAX_DEVICE_LEN % 8 != 0);
}
#endif

#endif
