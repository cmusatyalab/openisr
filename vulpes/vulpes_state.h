#ifndef VULPES_KEYRING_H
#define VULPES_KEYRING_H

#include <stdint.h>

/*** Cache state ***/

#define CA_MAGIC 0x51528038
#define CA_VERSION 0

/* All u32's in network byte order */
struct ca_header {
  uint32_t magic;
  uint32_t entries;
  uint32_t offset;  /* beginning of data, in 512-byte blocks */
  uint32_t valid_chunks;
  uint32_t dirty_chunks;
  uint8_t version;
  uint8_t reserved[491];
};

#define CA_VALID 0x01
#define CA_DIRTY 0x02

struct ca_entry {
  uint32_t length;
  uint8_t flags;
};

/*** Keyring ***/

#define KR_MAGIC 0x51528039
#define KR_VERSION 0

/* All u32's in network byte order */
struct kr_header {
  uint32_t magic;
  uint32_t entries;
  uint8_t version;
  uint8_t reserved[31];
};

#define KR_COMPRESS_NONE 0
#define KR_COMPRESS_ZLIB 1
#define KR_HASH_LEN 20

struct kr_entry {
  uint8_t compress;
  uint8_t tag[KR_HASH_LEN];
  uint8_t key[KR_HASH_LEN];
};

#endif
