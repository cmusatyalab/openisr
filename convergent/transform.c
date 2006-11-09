#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/crypto.h>
#include <linux/zlib.h>
#include "convergent.h"
#include "lzf.h"

/* XXX this needs to go away. */
static void scatterlist_transfer(struct convergent_dev *dev,
			struct scatterlist *sg, void *buf, int dir)
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
static inline unsigned crypto_pad_len(struct convergent_dev *dev,
			unsigned datalen)
{
	return dev->cipher_block - (datalen % dev->cipher_block);
}

/* Perform PKCS padding on a scatterlist.  Return the new length. */
static unsigned crypto_pad(struct convergent_dev *dev, struct scatterlist *sg,
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
static int crypto_unpad(struct convergent_dev *dev, struct scatterlist *sg,
			int len)
{
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
	if (padlen == 0 || padlen > dev->cipher_block || padlen > len)
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
static int compress_chunk_zlib(struct convergent_dev *dev,
			struct scatterlist *sg)
{
	z_stream strm;
	int ret;
	int ret2;
	int size;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	scatterlist_transfer(dev, sg, dev->buf_uncompressed, READ);
	strm.workspace=dev->zlib_deflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK) {
		debug("zlib_deflateInit failed");
		return -EIO;
	}
	strm.next_in=dev->buf_uncompressed;
	strm.avail_in=dev->chunksize;
	strm.next_out=dev->buf_compressed;
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
	memset(dev->buf_compressed + size, 0, dev->chunksize - size);
	scatterlist_transfer(dev, sg, dev->buf_compressed, WRITE);
	return size;
}

/* XXX this should be converted to use scatterlists rather than a vmalloc
   buffer */
static int decompress_chunk_zlib(struct convergent_dev *dev,
			struct scatterlist *sg, unsigned len)
{
	z_stream strm;
	int ret;
	int ret2;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	/* XXX don't need to transfer whole scatterlist */
	scatterlist_transfer(dev, sg, dev->buf_compressed, READ);
	strm.workspace=dev->zlib_inflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_inflateInit(&strm);
	if (ret != Z_OK) {
		debug("zlib_inflateInit failed");
		return -EIO;
	}
	strm.next_in=dev->buf_compressed;
	strm.avail_in=len;
	strm.next_out=dev->buf_uncompressed;
	strm.avail_out=dev->chunksize;
	ret=zlib_inflate(&strm, Z_FINISH);
	len=strm.total_out;
	ret2=zlib_inflateEnd(&strm);
	if (ret != Z_STREAM_END || ret2 != Z_OK)
		return -EIO;
	if (len != dev->chunksize)
		return -EIO;
	scatterlist_transfer(dev, sg, dev->buf_uncompressed, WRITE);
	return 0;
}

static int compress_chunk_lzf(struct convergent_dev *dev,
			struct scatterlist *sg)
{
	int size;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	scatterlist_transfer(dev, sg, dev->buf_uncompressed, READ);
	size=lzf_compress(dev->buf_uncompressed, dev->chunksize,
				dev->buf_compressed, dev->chunksize,
				dev->lzf_compress);
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
	memset(dev->buf_compressed + size, 0, dev->chunksize - size);
	scatterlist_transfer(dev, sg, dev->buf_compressed, WRITE);
	return size;
}

static int decompress_chunk_lzf(struct convergent_dev *dev,
			struct scatterlist *sg, unsigned len)
{
	BUG_ON(!mutex_is_locked(&dev->lock));
	/* XXX don't need to transfer whole scatterlist */
	scatterlist_transfer(dev, sg, dev->buf_compressed, READ);
	len=lzf_decompress(dev->buf_compressed, len,
				dev->buf_uncompressed, dev->chunksize);
	if (len != dev->chunksize)
		return -EIO;
	scatterlist_transfer(dev, sg, dev->buf_uncompressed, WRITE);
	return 0;
}

/* Guaranteed to return data which is an even multiple of the crypto
   block size. */
int compress_chunk(struct convergent_dev *dev, struct scatterlist *sg,
			compress_t type)
{
	BUG_ON(!mutex_is_locked(&dev->lock));
	switch (type) {
	case ISR_COMPRESS_NONE:
		return dev->chunksize;
	case ISR_COMPRESS_ZLIB:
		return compress_chunk_zlib(dev, sg);
	case ISR_COMPRESS_LZF:
		return compress_chunk_lzf(dev, sg);
	default:
		BUG();
		return -EIO;
	}
}

int decompress_chunk(struct convergent_dev *dev, struct scatterlist *sg,
			compress_t type, unsigned len)
{
	BUG_ON(!mutex_is_locked(&dev->lock));
	switch (type) {
	case ISR_COMPRESS_NONE:
		if (len != dev->chunksize)
			return -EIO;
		return 0;
	case ISR_COMPRESS_ZLIB:
		return decompress_chunk_zlib(dev, sg, len);
	case ISR_COMPRESS_LZF:
		return decompress_chunk_lzf(dev, sg, len);
	default:
		BUG();
		return -EIO;
	}
}

/* For some reason, the cryptoapi digest functions expect nsg rather than
   nbytes.  However, when we're hashing compressed data, we may want the
   hash to include only part of a page.  Thus this nonsense. */
/* XXX verify this against test vectors */
void crypto_hash(struct convergent_dev *dev, struct scatterlist *sg,
			unsigned nbytes, u8 *out)
{
	int i;
	unsigned saved;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	for (i=0; sg[i].length < nbytes; i++)
		nbytes -= sg[i].length;
	saved=sg[i].length;
	sg[i].length=nbytes;
	crypto_digest_digest(dev->hash, sg, i + 1, out);
	sg[i].length=saved;
}

/* Returns the new data size, or error */
int crypto_cipher(struct convergent_dev *dev, struct scatterlist *sg,
			char key[], unsigned len, int dir, int doPad)
{
	char iv[8]={0}; /* XXX */
	int ret;
	
	BUG_ON(!mutex_is_locked(&dev->lock));
	crypto_cipher_set_iv(dev->cipher, iv, sizeof(iv));
	BUG_ON(dev->key_len > dev->hash_len);  /* XXX */
	ret=crypto_cipher_setkey(dev->cipher, key, dev->key_len);
	if (ret)
		return ret;
	
	if (dir == READ) {
		ret=crypto_cipher_decrypt(dev->cipher, sg, sg, len);
		if (ret)
			return ret;
		if (doPad)
			return crypto_unpad(dev, sg, len);
		else
			return len;
	} else {
		if (doPad)
			len=crypto_pad(dev, sg, len);
		ret=crypto_cipher_encrypt(dev->cipher, sg, sg, len);
		if (ret)
			return ret;
		return len;
	}
}

#define set_if_requested(lhs, rhs) do {if (lhs != NULL) *lhs=rhs;} while (0)
static int suite_lookup(crypto_t suite, char **user_name, char **cipher_name,
			unsigned *cipher_mode, unsigned *key_len,
			char **hash_name)
{
	switch (suite) {
	case ISR_CRYPTO_BLOWFISH_SHA1:
		set_if_requested(user_name, "blowfish-sha1");
		set_if_requested(cipher_name, "blowfish");
		set_if_requested(cipher_mode, CRYPTO_TFM_MODE_CBC);
		set_if_requested(key_len, 20);
		set_if_requested(hash_name, "sha1");
		break;
	case ISR_CRYPTO_BLOWFISH_SHA1_COMPAT:
		set_if_requested(user_name, "blowfish-sha1-compat");
		set_if_requested(cipher_name, "blowfish");
		set_if_requested(cipher_mode, CRYPTO_TFM_MODE_CBC);
		set_if_requested(key_len, 16);
		set_if_requested(hash_name, "sha1");
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

char *get_suite_name(struct convergent_dev *dev)
{
	char *ret;
	if (!suite_lookup(dev->suite, &ret, NULL, NULL, NULL, NULL))
		return ret;
	return "unknown";
}

static int compression_lookup(compress_t type, char **user_name)
{
	switch (type) {
	case ISR_COMPRESS_NONE:
		set_if_requested(user_name, "none");
		break;
	case ISR_COMPRESS_ZLIB:
		set_if_requested(user_name, "zlib");
		break;
	case ISR_COMPRESS_LZF:
		set_if_requested(user_name, "lzf");
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

char *get_default_compression_name(struct convergent_dev *dev)
{
	char *ret;
	if (!compression_lookup(dev->default_compression, &ret))
		return ret;
	return "unknown";
}

int compression_type_ok(struct convergent_dev *dev, compress_t compress)
{
	/* Make sure only one bit is set */
	if (compress & (compress - 1))
		return 0;
	/* Make sure we have been configured to accept the bit */
	if (!(compress & dev->supported_compression))
		return 0;
	return 1;
}

#define SUPPORTED_COMPRESSION  (ISR_COMPRESS_NONE | \
				ISR_COMPRESS_ZLIB | \
				ISR_COMPRESS_LZF)
int transform_alloc(struct convergent_dev *dev)
{
	char *cipher_name;
	unsigned cipher_mode;
	unsigned keylen;
	char *hash_name;
	int ret;
	
	ret=suite_lookup(dev->suite, NULL, &cipher_name, &cipher_mode,
				&keylen, &hash_name);
	if (ret) {
		log(KERN_ERR, "Unsupported crypto suite requested");
		return ret;
	}
	
	if ((dev->supported_compression & SUPPORTED_COMPRESSION)
				!= dev->supported_compression) {
		log(KERN_ERR, "Unsupported compression algorithm requested");
		return -EINVAL;
	}
	if (!compression_type_ok(dev, dev->default_compression)) {
		log(KERN_ERR, "Requested invalid default compression "
					"algorithm");
		return -EINVAL;
	}
	
	dev->cipher=crypto_alloc_tfm(cipher_name, cipher_mode);
	dev->hash=crypto_alloc_tfm(hash_name, 0);
	if (dev->cipher == NULL || dev->hash == NULL)
		return -EINVAL;
	dev->cipher_block=crypto_tfm_alg_blocksize(dev->cipher);
	dev->key_len=keylen;
	dev->hash_len=crypto_tfm_alg_digestsize(dev->hash);
	if (!strcmp("sha1", hash_name) && sha1_impl_is_suboptimal(dev->hash)) {
		/* Actually, the presence of sha1-i586.ko only matters
		   when the device is created, since that's when the tfm
		   is allocated.  Does anyone have better wording for this? */
		printk(KERN_NOTICE "%s: Using unoptimized SHA1; load "
					"sha1-i586.ko to improve performance\n",
					dev->class_dev->class_id);
	}
	
	if (dev->supported_compression != ISR_COMPRESS_NONE) {
		/* XXX this is not ideal, but there's no good way to support
		   scatterlists in LZF without hacking the code. */
		dev->buf_compressed=vmalloc(dev->chunksize);
		dev->buf_uncompressed=vmalloc(dev->chunksize);
		if (dev->buf_compressed == NULL ||
					dev->buf_uncompressed == NULL)
			return -ENOMEM;
	}
	
	if (dev->supported_compression & ISR_COMPRESS_ZLIB) {
		/* The deflate workspace size is too large for kmalloc */
		dev->zlib_deflate=vmalloc(zlib_deflate_workspacesize());
		dev->zlib_inflate=kmalloc(zlib_inflate_workspacesize(),
					GFP_KERNEL);
		if (dev->zlib_deflate == NULL || dev->zlib_inflate == NULL)
			return -ENOMEM;
	}
	
	if (dev->supported_compression & ISR_COMPRESS_LZF) {
		dev->lzf_compress=kmalloc(sizeof(LZF_STATE), GFP_KERNEL);
		if (dev->lzf_compress == NULL)
			return -ENOMEM;
	}
	return 0;
}

void transform_free(struct convergent_dev *dev)
{
	if (dev->lzf_compress)
		kfree(dev->lzf_compress);
	if (dev->zlib_inflate)
		kfree(dev->zlib_inflate);
	if (dev->zlib_deflate)
		vfree(dev->zlib_deflate);
	if (dev->buf_uncompressed)
		vfree(dev->buf_uncompressed);
	if (dev->buf_compressed)
		vfree(dev->buf_compressed);
	if (dev->hash)
		crypto_free_tfm(dev->hash);
	if (dev->cipher)
		crypto_free_tfm(dev->cipher);
}
