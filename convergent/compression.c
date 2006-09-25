#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/zlib.h>
#include "convergent.h"

/* XXX rename to transform.c, move chunk_tfm in */

/* XXX this needs to go away. */
static void scatterlist_transfer(struct convergent_dev *dev,
			struct scatterlist *sg, void *buf, int dir)
{
	void *page;
	int i;
	
	for (i=0; i<chunk_pages(dev); i++) {
		BUG_ON(sg[i].offset != 0);
		page=kmap_atomic(sg[i].page, KM_SOFTIRQ0);
		if (dir == READ)
			memcpy(buf + i * PAGE_SIZE, page, sg[i].length);
		else
			memcpy(page, buf + i * PAGE_SIZE, sg[i].length);
		kunmap_atomic(page, KM_SOFTIRQ0);
	}
}

/* Compress one chunk */
/* XXX this should be converted to use scatterlists rather than a vmalloc
   buffer */
static int compress_zlib(struct convergent_dev *dev, struct scatterlist *sg)
{
	z_stream strm;
	int ret;
	int ret2;
	int size;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	scatterlist_transfer(dev, sg, dev->buf_uncompressed, READ);
	strm.workspace=dev->zlib_deflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK)
		return -ENOMEM; /* XXX */
	strm.next_in=dev->buf_uncompressed;
	strm.avail_in=dev->chunksize;
	strm.next_out=dev->buf_compressed;
	strm.avail_out=dev->chunksize;
	ret=zlib_deflate(&strm, Z_FINISH);
	ret2=zlib_deflateEnd(&strm);
	if (ret == Z_OK) {
		/* Compressed data larger than uncompressed data */
		return -EFBIG;
	} else if (ret != Z_STREAM_END || ret2 != Z_OK) {
		return -EIO;
	}
	size=strm.total_out;
	/* XXX necessary?  where does zeroing fit in? */
	memset(dev->buf_compressed + size, 0, dev->chunksize - size);
	scatterlist_transfer(dev, sg, dev->buf_compressed, WRITE);
	return size;
}

/* Decompress one chunk */
/* XXX this should be converted to use scatterlists rather than a vmalloc
   buffer */
static int decompress_zlib(struct convergent_dev *dev, struct scatterlist *sg,
			unsigned compressed_len)
{
	z_stream strm;
	int ret;
	int ret2;
	
	BUG_ON(!spin_is_locked(&dev->lock));
	/* XXX don't need to transfer whole scatterlist */
	scatterlist_transfer(dev, sg, dev->buf_compressed, READ);
	strm.workspace=dev->zlib_inflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_inflateInit(&strm);
	if (ret != Z_OK)
		return -ENOMEM; /* XXX */
	strm.next_in=dev->buf_compressed;
	strm.avail_in=compressed_len;
	strm.next_out=dev->buf_uncompressed;
	strm.avail_out=dev->chunksize;
	ret=zlib_inflate(&strm, Z_FINISH);
	ret2=zlib_inflateEnd(&strm);
	if (ret == Z_MEM_ERROR)
		return -ENOMEM;
	else if (ret != Z_STREAM_END || ret2 != Z_OK)
		return -EIO;
	if (strm.total_out != dev->chunksize)
		return -EIO;
	scatterlist_transfer(dev, sg, dev->buf_uncompressed, WRITE);
	return 0;
}

/* XXX we need decent crypto padding */
int compress(struct convergent_dev *dev, struct scatterlist *sg)
{
	switch (dev->compression) {
	case ISR_COMPRESS_NONE:
		return dev->chunksize;
	case ISR_COMPRESS_ZLIB:
		return compress_zlib(dev, sg);
	default:
		BUG();
		return -EIO;
	}
}

int decompress(struct convergent_dev *dev, struct scatterlist *sg,
			int type, unsigned compressed_len)
{
	switch (type) {
	case ISR_COMPRESS_NONE:
		if (compressed_len != dev->chunksize)
			return -EIO;
		return 0;
	case ISR_COMPRESS_ZLIB:
		return decompress_zlib(dev, sg, compressed_len);
	default:
		BUG();
		return -EIO;
	}
}

int compression_alloc(struct convergent_dev *dev)
{
	/* XXX this is not ideal, but there's no good way to support
	   scatterlists in LZF without hacking the code. */
	dev->buf_compressed=vmalloc(dev->chunksize);
	dev->buf_uncompressed=vmalloc(dev->chunksize);
	/* The deflate workspace size is too large for kmalloc */
	dev->zlib_deflate=vmalloc(zlib_deflate_workspacesize());
	dev->zlib_inflate=kmalloc(zlib_inflate_workspacesize(), GFP_KERNEL);
	debug("deflatesize %u inflatesize %u", zlib_deflate_workspacesize(),
				zlib_inflate_workspacesize());
	debug("compressed %p uncompressed %p deflate %p inflate %p",
				dev->buf_compressed, dev->buf_uncompressed,
				dev->zlib_deflate, dev->zlib_inflate);
	if (dev->buf_compressed == NULL || dev->buf_uncompressed == NULL ||
				dev->zlib_deflate == NULL ||
				dev->zlib_inflate == NULL)
		return -ENOMEM;
	return 0;
}

void compression_free(struct convergent_dev *dev)
{
	if (dev->zlib_inflate)
		kfree(dev->zlib_inflate);
	if (dev->zlib_deflate)
		vfree(dev->zlib_deflate);
	if (dev->buf_uncompressed)
		vfree(dev->buf_uncompressed);
	if (dev->buf_compressed)
		vfree(dev->buf_compressed);
}
