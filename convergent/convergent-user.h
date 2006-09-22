#ifndef LINUX_CONVERGENT_USER_H
#define LINUX_CONVERGENT_USER_H

#define MAX_DEVICE_LEN 64
#define MAX_HASH_LEN 32

/* XXX temporary */
#define HASH_LEN 20

/* XXX consider 64-bit kernel with 32-bit userland */

/* XXX should be unique */
#define ISR_VERSION	0
#define ISR_REGISTER	1
#define ISR_UNREGISTER	2

struct isr_setup {
	char chunk_device[MAX_DEVICE_LEN];
	unsigned chunksize;
	unsigned cachesize;
	unsigned long long offset;
	int major;
	int first_minor;
	int minors;
	unsigned long long chunks;
};

struct isr_message {
	unsigned long long chunk;
	char key[MAX_HASH_LEN];
	unsigned flags;
};

#define ISR_MSG_HAVE_KEY  0x00000001
#define ISR_MSG_WANT_KEY  0x00000002

#endif
