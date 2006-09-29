#ifndef LINUX_CONVERGENT_USER_H
#define LINUX_CONVERGENT_USER_H

#define MAX_DEVICE_LEN 64
#define MAX_HASH_LEN 32

/* XXX consider 64-bit kernel with 32-bit userland */

/* XXX should be unique */
#define ISR_REGISTER	1
#define ISR_UNREGISTER	2

#define ISR_INTERFACE_VERSION 0

typedef unsigned short cipher_t;
typedef unsigned short hash_t;
typedef unsigned short compress_t;
typedef unsigned short msgtype_t;

struct isr_setup {
	char chunk_device[MAX_DEVICE_LEN];    /* to kernel */
	unsigned chunksize;                   /* to kernel */
	unsigned cachesize;                   /* to kernel */
	unsigned long long offset;            /* to kernel */
	unsigned short cipher;                /* to kernel */
	unsigned short hash;                  /* to kernel */
	unsigned short compress_default;      /* to kernel */
	unsigned short compress_required;     /* to kernel */  /* XXX not checked */
	int major;                            /* to user */
	int first_minor;                      /* to user */
	int minors;                           /* to user */
	unsigned long long chunks;            /* to user */
	unsigned hash_len;                    /* to user */
};

#define ISR_CIPHER_BLOWFISH      ((cipher_t)  0x0001)
#define ISR_HASH_SHA1            ((hash_t)    0x0001)
#define ISR_COMPRESS_NONE        ((compress_t)0x0001)
#define ISR_COMPRESS_ZLIB        ((compress_t)0x0002)

struct isr_message {
	msgtype_t type;
	compress_t compression;
	unsigned long long chunk;
	unsigned length;
	char key[MAX_HASH_LEN];
};

/* Kernel to user */
#define ISR_MSGTYPE_GET_META     ((msgtype_t) 0x0000)
#define ISR_MSGTYPE_UPDATE_META  ((msgtype_t) 0x0001)
/* User to kernel */
#define ISR_MSGTYPE_SET_META     ((msgtype_t) 0x1000)

#endif
