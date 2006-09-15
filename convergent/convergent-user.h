#ifndef LINUX_CONVERGENT_USER_H
#define LINUX_CONVERGENT_USER_H

#define MAX_DEVICE_LEN 64

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
};

#if 0
struct isr_message {
	chunk_t chunk;
	key_t key;
	hash_t hash;
	unsigned flags;
};
#endif

#endif
