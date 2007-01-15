#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/crypto.h>
#include <linux/zlib.h>
#include "defs.h"
#include "lzf.h"

/* Must be in the same order as the nexus_crypto enum */
static const struct tfm_suite_info suite_desc[] = {
	{
		.user_name = "blowfish-sha1",
		.cipher_name = "blowfish",
		.cipher_mode = CRYPTO_TFM_MODE_CBC,
		.cipher_block = 8,
		.key_len = 20,
		.hash_name = "sha1",
		.hash_len = 20
	},
	{
		.user_name = "blowfish-sha1-compat",
		.cipher_name = "blowfish",
		.cipher_mode = CRYPTO_TFM_MODE_CBC,
		.cipher_block = 8,
		.key_len = 16,
		.hash_name = "sha1",
		.hash_len = 20
	}
};

/* Must be in the same order as the nexus_compress enum */
static const struct tfm_compress_info compress_desc[] = {
	{
		.user_name = "none"
	},
	{
		.user_name = "zlib"
	},
	{
		.user_name = "lzf"
	}
};

const struct tfm_suite_info *suite_info(enum nexus_crypto suite)
{
	BUILD_BUG_ON((sizeof(suite_desc)/sizeof(suite_desc[0])) !=
				NEXUS_NR_CRYPTO);
	BUG_ON(suite < 0 || suite >= NEXUS_NR_CRYPTO);
	return &suite_desc[suite];
}

const struct tfm_compress_info *compress_info(enum nexus_compress alg)
{
	BUILD_BUG_ON((sizeof(compress_desc)/sizeof(compress_desc[0])) !=
				NEXUS_NR_COMPRESS);
	BUG_ON(alg < 0 || alg >= NEXUS_NR_COMPRESS);
	return &compress_desc[alg];
}

/* XXX this needs to go away. */
static void scatterlist_transfer(struct nexus_dev *dev, struct scatterlist *sg,
			void *buf, int dir)
{
	void *page;
	int i;
	
	/* We use KM_USER0 */
	BUG_ON(in_interrupt());
	for (i=0; i<chunk_pages(dev); i++) {
		BUG_ON(sg[i].offset != 0);
		page=kmap_atomic(sg[i].page, KM_USER0);
		if (dir == READ)
			memcpy(buf + i * PAGE_SIZE, page, sg[i].length);
		else
			memcpy(page, buf + i * PAGE_SIZE, sg[i].length);
		kunmap_atomic(page, KM_USER0);
	}
}

/* Return the number of bytes of padding which need to be added to
   data of length @datalen if padding is used */
static inline unsigned crypto_pad_len(struct nexus_dev *dev, unsigned datalen)
{
	unsigned cipher_block=suite_info(dev->suite)->cipher_block;
	return cipher_block - (datalen % cipher_block);
}

/* Perform PKCS padding on a scatterlist.  Return the new length. */
static unsigned crypto_pad(struct nexus_dev *dev, struct scatterlist *sg,
			unsigned datalen)
{
	unsigned padlen=crypto_pad_len(dev, datalen);
	unsigned offset=datalen;
	unsigned char *page;
	unsigned i;
	
	BUG_ON(datalen + padlen > dev->chunksize);
	/* We use KM_USER0 */
	BUG_ON(in_interrupt());
	ndebug("Pad %u", padlen);
	
	while (offset >= sg->length) {
		offset -= sg->length;
		sg++;
	}
	offset += sg->offset;
	page=kmap_atomic(sg->page, KM_USER0);
	for (i=0; i<padlen; i++) {
		if (offset >= sg->offset + sg->length) {
			kunmap_atomic(page, KM_USER0);
			sg++;
			page=kmap_atomic(sg->page, KM_USER0);
			offset=sg->offset;
		}
		page[offset++]=padlen;
	}
	kunmap_atomic(page, KM_USER0);
	return datalen + padlen;
}

/* Perform PKCS unpadding on a scatterlist.  Return the new length. */
static int crypto_unpad(struct nexus_dev *dev, struct scatterlist *sg, int len)
{
	unsigned cipher_block=suite_info(dev->suite)->cipher_block;
	unsigned char *page;
	unsigned padlen;
	unsigned offset=len - 1;
	unsigned i;
	int ret=-EINVAL;
	
	BUG_ON(len == 0);
	/* We use KM_USER0 */
	BUG_ON(in_interrupt());
	
	while (offset >= sg->length) {
		offset -= sg->length;
		sg++;
	}
	offset += sg->offset;
	page=kmap_atomic(sg->page, KM_USER0);
	padlen=page[offset--];
	if (padlen == 0 || padlen > cipher_block || padlen > len)
		goto out;
	ndebug("Unpad %u", padlen);
	for (i=1; i<padlen; i++) {
		if (offset < sg->offset) {
			kunmap_atomic(page, KM_USER0);
			sg--;
			page=kmap_atomic(sg->page, KM_USER0);
			offset=sg->offset + sg->length - 1;
		}
		if (page[offset--] != padlen)
			goto out;
	}
	ret=len - padlen;
out:
	kunmap_atomic(page, KM_USER0);
	return ret;
}

/* XXX consolidate duplicate code between this and lzf? */
/* XXX this should be converted to use scatterlists rather than a vmalloc
   buffer */
static int compress_chunk_zlib(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg)
{
	z_stream strm;
	int ret;
	int ret2;
	int size;
	
	scatterlist_transfer(dev, sg, ts->buf_uncompressed, READ);
	strm.workspace=ts->zlib_deflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK) {
		debug("zlib_deflateInit failed");
		return -EIO;
	}
	strm.next_in=ts->buf_uncompressed;
	strm.avail_in=dev->chunksize;
	strm.next_out=ts->buf_compressed;
	strm.avail_out=dev->chunksize;
	ret=zlib_deflate(&strm, Z_FINISH);
	size=strm.total_out;
	ret2=zlib_deflateEnd(&strm);
	if (ret == Z_OK) {
		/* Compressed data larger than uncompressed data */
		return -EFBIG;
	} else if (ret != Z_STREAM_END || ret2 != Z_OK) {
		debug("zlib compression failed");
		return -EIO;
	} else if (size + crypto_pad_len(dev, size) >= dev->chunksize) {
		/* If padding would bring us exactly to the length of
		   the buffer, we refuse to do it.  Rationale: we're only
		   doing padding if we're doing compression, and compression
		   failed to reduce the size of the chunk after padding,
		   so we're better off just not compressing. */
		return -EFBIG;
	}
	/* We write the whole chunk out to disk, so make sure we're not
	   leaking data. */
	memset(ts->buf_compressed + size, 0, dev->chunksize - size);
	scatterlist_transfer(dev, sg, ts->buf_compressed, WRITE);
	return size;
}

/* XXX this should be converted to use scatterlists rather than a vmalloc
   buffer */
static int decompress_chunk_zlib(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg,
			unsigned len)
{
	z_stream strm;
	int ret;
	int ret2;
	
	/* XXX don't need to transfer whole scatterlist */
	scatterlist_transfer(dev, sg, ts->buf_compressed, READ);
	strm.workspace=ts->zlib_inflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_inflateInit(&strm);
	if (ret != Z_OK) {
		debug("zlib_inflateInit failed");
		return -EIO;
	}
	strm.next_in=ts->buf_compressed;
	strm.avail_in=len;
	strm.next_out=ts->buf_uncompressed;
	strm.avail_out=dev->chunksize;
	ret=zlib_inflate(&strm, Z_FINISH);
	len=strm.total_out;
	ret2=zlib_inflateEnd(&strm);
	if (ret != Z_STREAM_END || ret2 != Z_OK)
		return -EIO;
	if (len != dev->chunksize)
		return -EIO;
	scatterlist_transfer(dev, sg, ts->buf_uncompressed, WRITE);
	return 0;
}

static int compress_chunk_lzf(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg)
{
	int size;
	
	scatterlist_transfer(dev, sg, ts->buf_uncompressed, READ);
	size=lzf_compress(ts->buf_uncompressed, dev->chunksize,
				ts->buf_compressed, dev->chunksize,
				ts->lzf_compress);
	if (size == 0) {
		/* Compressed data larger than uncompressed data */
		return -EFBIG;
	} else if (size + crypto_pad_len(dev, size) >= dev->chunksize) {
		/* Padding would make the compressed data at least as large
		   as the uncompressed data */
		return -EFBIG;
	}
	/* We write the whole chunk out to disk, so make sure we're not
	   leaking data. */
	memset(ts->buf_compressed + size, 0, dev->chunksize - size);
	scatterlist_transfer(dev, sg, ts->buf_compressed, WRITE);
	return size;
}

static int decompress_chunk_lzf(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg,
			unsigned len)
{
	/* XXX don't need to transfer whole scatterlist */
	scatterlist_transfer(dev, sg, ts->buf_compressed, READ);
	len=lzf_decompress(ts->buf_compressed, len,
				ts->buf_uncompressed, dev->chunksize);
	if (len != dev->chunksize)
		return -EIO;
	scatterlist_transfer(dev, sg, ts->buf_uncompressed, WRITE);
	return 0;
}

int compress_chunk(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, enum nexus_compress type)
{
	switch (type) {
	case NEXUS_COMPRESS_NONE:
		return dev->chunksize;
	case NEXUS_COMPRESS_ZLIB:
		return compress_chunk_zlib(dev, ts, sg);
	case NEXUS_COMPRESS_LZF:
		return compress_chunk_lzf(dev, ts, sg);
	case NEXUS_NR_COMPRESS:
		BUG();
	}
	return -EIO;
}

int decompress_chunk(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, enum nexus_compress type,
			unsigned len)
{
	switch (type) {
	case NEXUS_COMPRESS_NONE:
		if (len != dev->chunksize)
			return -EIO;
		return 0;
	case NEXUS_COMPRESS_ZLIB:
		return decompress_chunk_zlib(dev, ts, sg, len);
	case NEXUS_COMPRESS_LZF:
		return decompress_chunk_lzf(dev, ts, sg, len);
	case NEXUS_NR_COMPRESS:
		BUG();
	}
	return -EIO;
}

/* For some reason, the cryptoapi digest functions expect nsg rather than
   nbytes.  However, when we're hashing compressed data, we may want the
   hash to include only part of a page.  Thus this nonsense. */
/* XXX verify this against test vectors */
void crypto_hash(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, unsigned nbytes, u8 *out)
{
	struct crypto_tfm *tfm=ts->hash[dev->suite];
	int i;
	unsigned saved;
	
	for (i=0; sg[i].length < nbytes; i++)
		nbytes -= sg[i].length;
	saved=sg[i].length;
	sg[i].length=nbytes;
	crypto_digest_digest(tfm, sg, i + 1, out);
	sg[i].length=saved;
}

/* Returns the new data size, or error */
int crypto_cipher(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, char key[], unsigned len,
			int dir, int doPad)
{
	struct crypto_tfm *tfm=ts->cipher[dev->suite];
	char iv[8]={0}; /* XXX */
	int ret;
	unsigned key_len=suite_info(dev->suite)->key_len;
	
	crypto_cipher_set_iv(tfm, iv, sizeof(iv));
	BUG_ON(key_len > suite_info(dev->suite)->hash_len);  /* XXX */
	ret=crypto_cipher_setkey(tfm, key, key_len);
	if (ret)
		return ret;
	
	if (dir == READ) {
		ret=crypto_cipher_decrypt(tfm, sg, sg, len);
		if (ret)
			return ret;
		if (doPad)
			return crypto_unpad(dev, sg, len);
		else
			return len;
	} else {
		if (doPad)
			len=crypto_pad(dev, sg, len);
		ret=crypto_cipher_encrypt(tfm, sg, sg, len);
		if (ret)
			return ret;
		return len;
	}
}

int compression_type_ok(struct nexus_dev *dev, enum nexus_compress compress)
{
	/* Make sure we're within enum range */
	if (compress < 0 || compress >= NEXUS_NR_COMPRESS)
		return 0;
	/* Make sure we have been configured to accept the algorithm */
	if (!((1 << compress) & dev->supported_compression))
		return 0;
	return 1;
}

int suite_add(struct nexus_tfm_state *ts, enum nexus_crypto suite)
{
	const struct tfm_suite_info *info;
	struct crypto_tfm *cipher;
	struct crypto_tfm *hash;
	
	BUG_ON(ts->cipher[suite] != NULL);
	
	info=suite_info(suite);
	cipher=crypto_alloc_tfm(info->cipher_name, info->cipher_mode);
	if (cipher == NULL)
		return -EINVAL;
	hash=crypto_alloc_tfm(info->hash_name, 0);
	if (hash == NULL) {
		crypto_free_tfm(cipher);
		return -EINVAL;
	}
	ts->cipher[suite]=cipher;
	ts->hash[suite]=hash;
	
	if (!strcmp("sha1", info->hash_name) &&
				sha1_impl_is_suboptimal(hash)) {
		/* Actually, the presence of sha1-i586.ko only matters
		   when the tfm is first allocated.  Does anyone have better
		   wording for this? */
		log(KERN_NOTICE, "Using unoptimized SHA1; load sha1-i586.ko "
					"to improve performance");
	}
	return 0;
}

void suite_remove(struct nexus_tfm_state *ts, enum nexus_crypto suite)
{
	BUG_ON(ts->cipher[suite] == NULL);
	crypto_free_tfm(ts->cipher[suite]);
	ts->cipher[suite]=NULL;
	crypto_free_tfm(ts->hash[suite]);
	ts->hash[suite]=NULL;
}

static int bounce_buffer_get(struct nexus_tfm_state *ts)
{
	if (ts->buf_refcount == 0) {
		ndebug("Allocating compression bounce buffer");
		/* XXX this is not ideal, but there's no good way to support
		   scatterlists in LZF without hacking the code. */
		/* XXX We always allocate a buffer of size MAX_CHUNKSIZE,
		   which is defined for this purpose.  (There's no other
		   reason the chunksize couldn't be larger.)  We should
		   dynamically resize the vmalloc area to fit the largest
		   chunksize we actually need at the moment, rather than
		   using an arbitrary constant, but really we should find
		   a way to eliminate the bounce buffers. */
		ts->buf_compressed=vmalloc(MAX_CHUNKSIZE);
		if (ts->buf_compressed == NULL)
			return -ENOMEM;
		ts->buf_uncompressed=vmalloc(MAX_CHUNKSIZE);
		if (ts->buf_uncompressed == NULL) {
			vfree(ts->buf_compressed);
			ts->buf_compressed=NULL;
			return -ENOMEM;
		}
	}
	ts->buf_refcount++;
	return 0;
}

static void bounce_buffer_put(struct nexus_tfm_state *ts)
{
	if (--ts->buf_refcount == 0) {
		ndebug("Freeing compression bounce buffer");
		BUG_ON(ts->buf_compressed == NULL);
		vfree(ts->buf_compressed);
		ts->buf_compressed=NULL;
		vfree(ts->buf_uncompressed);
		ts->buf_uncompressed=NULL;
	}
}

int compress_add(struct nexus_tfm_state *ts, enum nexus_compress alg)
{
	int err;
	
	switch (alg) {
	case NEXUS_COMPRESS_NONE:
		/* NONE is special: we never allocate bounce buffers for it */
		return 0;
	case NEXUS_COMPRESS_ZLIB:
		/* The deflate workspace size is too large for kmalloc */
		ts->zlib_deflate=vmalloc(zlib_deflate_workspacesize());
		if (ts->zlib_deflate == NULL)
			return -ENOMEM;
		ts->zlib_inflate=kmalloc(zlib_inflate_workspacesize(),
					GFP_KERNEL);
		if (ts->zlib_inflate == NULL) {
			vfree(ts->zlib_deflate);
			ts->zlib_deflate=NULL;
			return -ENOMEM;
		}
		break;
	case NEXUS_COMPRESS_LZF:
		ts->lzf_compress=kmalloc(sizeof(LZF_STATE), GFP_KERNEL);
		if (ts->lzf_compress == NULL)
			return -ENOMEM;
		break;
	case NEXUS_NR_COMPRESS:
		BUG();
	}
	
	err=bounce_buffer_get(ts);
	if (err)
		return err;
	return 0;
}

void compress_remove(struct nexus_tfm_state *ts, enum nexus_compress alg)
{
	switch (alg) {
	case NEXUS_COMPRESS_NONE:
		/* Special case: don't decrement bounce buffer refcount */
		return;
	case NEXUS_COMPRESS_ZLIB:
		BUG_ON(ts->zlib_inflate == NULL);
		kfree(ts->zlib_inflate);
		ts->zlib_inflate=NULL;
		vfree(ts->zlib_deflate);
		ts->zlib_deflate=NULL;
		break;
	case NEXUS_COMPRESS_LZF:
		BUG_ON(ts->lzf_compress == NULL);
		kfree(ts->lzf_compress);
		ts->lzf_compress=NULL;
		break;
	case NEXUS_NR_COMPRESS:
		BUG();
	}
	bounce_buffer_put(ts);
}

int transform_validate(struct nexus_dev *dev)
{
	compressmask_t supported_algs=(1 << NEXUS_NR_COMPRESS) - 1;
	
	if (dev->suite < 0 || dev->suite >= NEXUS_NR_CRYPTO) {
		log(KERN_ERR, "Unsupported crypto suite requested");
		return -EINVAL;
	}
	if (dev->supported_compression == 0) {
		log(KERN_ERR, "No compression algorithms requested");
		return -EINVAL;
	}
	if ((dev->supported_compression & supported_algs)
				!= dev->supported_compression) {
		log(KERN_ERR, "Unsupported compression algorithm requested");
		return -EINVAL;
	}
	if (!compression_type_ok(dev, dev->default_compression)) {
		log(KERN_ERR, "Requested unreasonable default compression "
					"algorithm");
		return -EINVAL;
	}
	return 0;
}
