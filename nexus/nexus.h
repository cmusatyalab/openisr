/* nexus.h - interface exported to userspace via character device */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (R)
 *         system
 * 
 * Copyright (C) 2006-2007 Carnegie Mellon University
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

#ifndef ISR_NEXUS_H
#define ISR_NEXUS_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define NEXUS_MAX_DEVICE_LEN 64
#define NEXUS_MAX_HASH_LEN 32

/* ioctls */
#define NEXUS_IOC_REGISTER      _IOWR(0x1a, 0, struct nexus_setup)
#define NEXUS_IOC_UNREGISTER      _IO(0x1a, 1)
#define NEXUS_IOC_CONFIG_THREAD   _IO(0x1a, 2)

#define NEXUS_INTERFACE_VERSION 7

typedef __u16 compressmask_t;
typedef __u16 msgtype_t;

/* The numeric values of these symbols are not guaranteed to remain constant!
   Don't use them in an on-disk format! */
enum nexus_crypto {
	NEXUS_CRYPTO_NONE_SHA1,
	NEXUS_CRYPTO_BLOWFISH_SHA1,
	NEXUS_CRYPTO_AES_SHA1,
	NEXUS_NR_CRYPTO
};

enum nexus_compress {
	NEXUS_COMPRESS_NONE,
	NEXUS_COMPRESS_ZLIB,
	NEXUS_COMPRESS_LZF,
	NEXUS_NR_COMPRESS
};

/**
 * struct nexus_setup - information exchanged during NEXUS_IOC_REGISTER
 * @ident            : unique identifier for this device (null-terminated) (k)
 * @chunk_device     : path to the chunk-store block device (k)
 * @offset           : starting sector of first chunk in chunk store (k)
 * @chunksize        : chunk size in bytes (k)
 * @cachesize        : size of in-core chunk cache in entries (k)
 * @crypto           : &enum nexus_crypto choice for this device (k)
 * @compress_default : &enum nexus_compress choice for new chunks (k)
 * @compress_required: bitmask of compression algorithms we must support (k)
 * @pad              : reserved
 * @chunks           : number of chunks the chunk store will hold (u)
 * @major            : the major number of the allocated block device (u)
 * @num_minors       : number of minor numbers given to each Nexus blkdev (u)
 * @index            : the index of this block device (u)
 * @hash_len         : length of key and tag values in bytes (u)
 *
 * Fields labeled (k) are provided to the kernel on NEXUS_IOC_REGISTER.
 * Fields labeled (u) are filled in by the kernel when the ioctl returns.
 *
 * @index can be used to determine the name of the device node (e.g.,
 * printf("/dev/openisr%c", 'a' + index)).
 *
 * @compress_required is a bitmask with bits of the form
 * (1 << NEXUS_COMPRESS_FOO).
 *
 * This structure must have an identical layout on 32-bit and 64-bit systems.
 * We don't use enum types for crypto and compress fields because the compiler
 * is allowed to pick any size for them.
 **/
struct nexus_setup {
	/* To kernel: */
	__u8 ident[NEXUS_MAX_DEVICE_LEN];
	__u8 chunk_device[NEXUS_MAX_DEVICE_LEN];
	__u64 offset;
	__u32 chunksize;
	__u32 cachesize;
	__u8 crypto;
	__u8 compress_default;
	compressmask_t compress_required;
	
	__u32 pad;
	
	/* To user: */
	__u64 chunks;
	__u32 major;
	__u32 num_minors;
	__u32 index;
	__u8 hash_len;
};

/**
 * struct nexus_message - a message sent over the character device
 * @chunk      : the chunk number
 * @length     : the data length (may be < chunksize if compressed)
 * @type       : message type
 * @compression: compression type for this chunk (&enum nexus_compress)
 * @key        : encryption key
 * @tag        : CAS tag
 *
 * This structure must have an identical layout on 32-bit and 64-bit systems.
 * We don't use enum types for crypto and compress fields because the compiler
 * is allowed to pick any size for them.
 *
 * NEXUS_MSGTYPE_GET_META:
 * Sent from kernel to userspace to request information on a chunk.  @chunk is
 * valid.  Userspace must respond with SET_META or META_HARDERR.  Responses do
 * not need to be in the same order as requests.
 *
 * NEXUS_MSGTYPE_UPDATE_META:
 * Sent from kernel to userspace to report new metadata for a chunk.  All
 * fields are valid.  No reply is necessary.
 *
 * NEXUS_MSGTYPE_SET_META:
 * Sent from userspace to kernel to supply requested information for a chunk.
 * May only be sent in response to GET_META; unsolicited SET_META is not
 * allowed.  All fields must be valid.
 *
 * NEXUS_MSGTYPE_META_HARDERR:
 * Sent from userspace to kernel to report inability to supply the information
 * requested via GET_META.  May only be sent in response to GET_META.  Only
 * @chunk need be valid.  This causes the chunk to enter an state in which all
 * I/O to the chunk will be failed with an I/O error.  The chunk will remain
 * in this state until it ages out of cache or the entire chunk is overwritten
 * in a single I/O.
 **/
struct nexus_message {
	__u64 chunk;
	__u32 length;
	msgtype_t type;
	__u8 compression;
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
