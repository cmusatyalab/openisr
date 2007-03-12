/* transform.c - encryption, hashing, compression */

/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (TM)
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
		.cipher_spec = "cbc(blowfish)",
		.cipher_block = 8,
		.key_len = 20,
		.hash_name = "sha1",
		.hash_len = 20
	},
	{
		.user_name = "blowfish-sha1-compat",
		.cipher_name = "blowfish",
		.cipher_mode = CRYPTO_TFM_MODE_CBC,
		.cipher_spec = "cbc(blowfish)",
		.cipher_block = 8,
		.key_len = 16,
		.hash_name = "sha1",
		.hash_len = 20
	},
	{
		.user_name = "none-sha1",
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

/**
 * suite_info - returns &tfm_suite_info associated with @suite
 **/
const struct tfm_suite_info *suite_info(enum nexus_crypto suite)
{
	BUILD_BUG_ON((sizeof(suite_desc)/sizeof(suite_desc[0])) !=
				NEXUS_NR_CRYPTO);
	BUG_ON(suite < 0 || suite >= NEXUS_NR_CRYPTO);
	return &suite_desc[suite];
}

/**
 * compress_info - returns &tfm_compress_info associated with @alg
 **/
const struct tfm_compress_info *compress_info(enum nexus_compress alg)
{
	BUILD_BUG_ON((sizeof(compress_desc)/sizeof(compress_desc[0])) !=
				NEXUS_NR_COMPRESS);
	BUG_ON(alg < 0 || alg >= NEXUS_NR_COMPRESS);
	return &compress_desc[alg];
}

/**
 * scatterlist_transfer - copy scatterlist to/from vmalloc bounce buffer
 * @dir: %READ if copying to @buf, %WRITE if copying from @buf
 *
 * This imposes overhead, of course, and is intended only for compression
 * algorithms that can't handle scatterlists.  (All crypto and hash algorithms
 * should be able to do so via cryptoapi.)  If the algorithm can run
 * page-at-a-time without sacrificing compression (e.g., deflate), try to do
 * that instead.
 *
 * We use KM_USER0, so this should only be called from process context.
 **/
static void scatterlist_transfer(struct scatterlist *sg, void *buf,
			unsigned nbytes, int dir)
{
	void *page;
	unsigned count;
	unsigned total;
	
	/* We use KM_USER0 */
	BUG_ON(in_interrupt());
	for (total=0; total < nbytes; sg++) {
		count=min(sg->length, nbytes - total);
		page=kmap_atomic(sg->page, KM_USER0);
		if (dir == READ)
			memcpy(buf + total, page + sg->offset, count);
		else
			memcpy(page + sg->offset, buf + total, count);
		kunmap_atomic(page, KM_USER0);
		total += count;
	}
}

/**
 * scatterlist_zero - zero out part of a scatterlist
 * @start : starting offset in bytes
 * @nbytes: number of zero bytes to write
 *
 * We use KM_USER0, so this should only be called from process context.
 **/
static void scatterlist_zero(struct scatterlist *sg, unsigned start,
			unsigned nbytes)
{
	void *page;
	unsigned count;
	
	debug(DBG_TFM, "scatterlist_zero start %u count %u", start, nbytes);
	/* We use KM_USER0 */
	BUG_ON(in_interrupt());
	while (start >= sg->length) {
		start -= sg->length;
		sg++;
	}
	while (nbytes > 0) {
		page=kmap_atomic(sg->page, KM_USER0);
		count=min(nbytes, sg->length - start);
		memset(page + sg->offset + start, 0, count);
		kunmap_atomic(page, KM_USER0);
		nbytes -= count;
		start=0;
		sg++;
	}
}

/**
 * scatterlist_flip - swap page pointers between @s1 and @s2
 **/
static void scatterlist_flip(struct scatterlist *s1, struct scatterlist *s2,
			unsigned npages)
{
	struct page *tmp;
	
	for (; npages > 0; npages--, s1++, s2++) {
		tmp=s1->page;
		s1->page=s2->page;
		s2->page=tmp;
	}
}

/**
 * crypto_pad_len - return length of PKCS padding needed for @datalen bytes
 *
 * Returns the number of bytes of padding which need to be added to
 * data of length @datalen if padding is used.  Returns 0 if encryption has
 * been disabled for this suite.
 **/
static inline unsigned crypto_pad_len(struct nexus_dev *dev, unsigned datalen)
{
	unsigned cipher_block=suite_info(dev->suite)->cipher_block;
	if (cipher_block == 0)
		return 0;
	else
		return cipher_block - (datalen % cipher_block);
}

/**
 * crypto_pad - perform PKCS padding on a chunkdata scatterlist
 *
 * Returns the new length.  It is an error to call crypto_pad() if encryption
 * is disabled for the suite associated with @dev, or if the scatterlist
 * does not have room for the pad bytes.
 *
 * We use KM_USER0, so this should only be called from process context.
 **/
static unsigned crypto_pad(struct nexus_dev *dev, struct scatterlist *sg,
			unsigned datalen)
{
	unsigned padlen=crypto_pad_len(dev, datalen);
	unsigned offset=datalen;
	unsigned char *page;
	unsigned i;
	
	BUG_ON(padlen == 0);  /* crypto_unpad() will be confused on decrypt */
	BUG_ON(datalen + padlen > dev->chunksize);
	/* We use KM_USER0 */
	BUG_ON(in_interrupt());
	debug(DBG_TFM, "Pad %u", padlen);
	
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

/**
 * crypto_unpad - perform PKCS unpadding on a chunkdata scatterlist
 * @len: data length including padding
 *
 * Returns the new length, or -EINVAL if the padding is invalid.  It is an
 * error to call crypto_unpad() if encryption is disabled for the suite
 * associated with @dev.
 *
 * We use KM_USER0, so this should only be called from process context.
 **/
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
	debug(DBG_TFM, "Unpad %u", padlen);
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

/**
 * should_store_chunk_compressed - returns true if compression was worthwhile
 * @size: compressed size of the chunk in bytes
 *
 * Returns true if the compressed data, plus the PKCS padding, is at least
 * one byte smaller than the uncompressed data.  (We do padding iff we're
 * doing compression, so the uncompressed data is always chunksize bytes.)
 **/
static int should_store_chunk_compressed(struct nexus_dev *dev, unsigned size)
{
	if (size >= dev->chunksize)
		return 0;
	if (size + crypto_pad_len(dev, size) >= dev->chunksize) {
		/* Padding pushes us over the threshold */
		debug(DBG_TFM, "Refusing to compress: borderline case");
		return 0;
	}
	return 1;
}

/**
 * compress_chunk_zlib - compress a chunk using the zlib (deflate) algorithm
 * @ts: the per-CPU temporary state buffer
 *
 * Returns the compressed size, -EFBIG if the chunk isn't worth storing
 * compressed (because it didn't compress well), or -EIO on error.  Must
 * be called from process context.
 **/
static int compress_chunk_zlib(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg)
{
	z_stream strm;
	void *from;
	void *to;
	struct scatterlist *out_sg=ts->zlib_sg;
	unsigned out_offset=0;
	int ret;
	int ret2;
	int size;
	int flush;
	int i=0;
	
	strm.workspace=ts->zlib_deflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK) {
		debug(DBG_TFM, "zlib_deflateInit failed");
		return -EIO;
	}
	/* Compression is slow, so we call cond_resched() every input page to
	   try to keep scheduling latency down, even though this may cause
	   some unnecessary TLB misses for output pages. */
	do {
		from=kmap_atomic(sg[i].page, KM_USER0);
		strm.next_in=from + sg[i].offset;
		strm.avail_in=sg[i].length;
		flush = (i == chunk_pages(dev) - 1) ? Z_FINISH : 0;
		i++;
		do {
			to=kmap_atomic(out_sg->page, KM_USER1);
			strm.next_out=to + out_sg->offset + out_offset;
			strm.avail_out=out_sg->length - out_offset;
			ret=zlib_deflate(&strm, flush);
			/* Unconditionally unmap the destination page: we can't
			   hold a mapping across cond_resched() */
			kunmap_atomic(to, KM_USER1);
			if (strm.avail_out == 0) {
				out_offset=0;
				out_sg++;
			} else {
				out_offset=out_sg->length - strm.avail_out;
			}
		} while ((strm.avail_in > 0 || flush) && ret == Z_OK &&
					strm.total_out < dev->chunksize);
		kunmap_atomic(from, KM_USER0);
		cond_resched();
	} while (ret == Z_OK && strm.total_out < dev->chunksize);
	size=strm.total_out;
	ret2=zlib_deflateEnd(&strm);
	if (!should_store_chunk_compressed(dev, size)) {
		/* Compressed data is too big */
		return -EFBIG;
	} else if (ret != Z_STREAM_END || ret2 != Z_OK) {
		debug(DBG_TFM, "zlib compression failed");
		return -EIO;
	}
	
	/* We can't just swap the sg pointer with ts->zlib_sg because the
	   scatterlists may be of different lengths (zlib_sg must be able
	   to hold MAX_CHUNKSIZE bytes).  So we swap individual page
	   pointers. */
	scatterlist_flip(sg, ts->zlib_sg, (size + PAGE_SIZE - 1) / PAGE_SIZE);
	/* We write the whole chunk out to disk, so make sure we're not
	   leaking data. */
	scatterlist_zero(sg, size, dev->chunksize - size);
	return size;
}

/**
 * decompress_chunk_zlib - decompress a zlib-compressed chunk
 * @ts : the per-CPU temporary state buffer
 * @len: the length of the compressed data
 *
 * Returns 0 on success or -EIO on error.  Must be called from process context.
 **/
static int decompress_chunk_zlib(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg,
			unsigned len)
{
	z_stream strm;
	struct scatterlist *in_sg=sg;
	struct scatterlist *out_sg=ts->zlib_sg;
	unsigned out_offset=0;
	void *from;
	void *to=NULL;  /* silence compiler warning */
	int ret;
	int ret2;
	
	strm.workspace=ts->zlib_inflate;
	/* XXX keep persistent stream structures? */
	ret=zlib_inflateInit(&strm);
	if (ret != Z_OK) {
		debug(DBG_TFM, "zlib_inflateInit failed");
		return -EIO;
	}
	
	/* Decompression is relatively fast, so we cond_resched() only every
	   compressed (input) page.  If we called cond_resched() every output
	   page, we'd be repeatedly mapping and unmapping the same input
	   page, leading to lots of unnecessary TLB misses. */
	do {
		from=kmap_atomic(in_sg->page, KM_USER0);
		strm.next_in=from + in_sg->offset;
		strm.avail_in=min(len, in_sg->length);
		len -= strm.avail_in;
		in_sg++;
		do {
			if (strm.total_out < dev->chunksize) {
				to=kmap_atomic(out_sg->page, KM_USER1);
				strm.next_out=to + out_sg->offset + out_offset;
				strm.avail_out=out_sg->length - out_offset;
			} else {
				/* If total_out == chunksize but zlib_inflate()
				   returns Z_OK, we call into zlib_inflate()
				   one more time with a zero-byte output
				   buffer.  The reason is that the 4-byte
				   ADLER32 trailer may span an input page
				   boundary; in this case there is more work to
				   be done but no more output will be produced.
				   If there *is* more output to be produced
				   (because we've been given an invalid block),
				   zlib_inflate() will return Z_BUF_ERROR when
				   we do this.
				   
				   In the kernel's zlib, unlike in vanilla
				   zlib, it's permissible to set next_out to
				   NULL. */
				strm.next_out=NULL;
				strm.avail_out=0;
			}
			ret=zlib_inflate(&strm, Z_SYNC_FLUSH);
			if (strm.next_out == NULL)
				continue;
			/* Can't hold the mapping across cond_resched() */
			kunmap_atomic(to, KM_USER1);
			if (strm.avail_out > 0) {
				out_offset=out_sg->length - strm.avail_out;
			} else {
				out_offset=0;
				out_sg++;
			}
		} while (strm.avail_in > 0 && ret == Z_OK &&
					strm.total_out <= dev->chunksize);
		kunmap_atomic(from, KM_USER0);
		cond_resched();
	} while (ret == Z_OK && len > 0 && strm.total_out <= dev->chunksize);
	
	len=strm.total_out;
	ret2=zlib_inflateEnd(&strm);
	if (ret != Z_STREAM_END || ret2 != Z_OK) {
		debug(DBG_TFM, "reached end of decompression output buffer");
		return -EIO;
	}
	if (len != dev->chunksize) {
		debug(DBG_TFM, "chunk did not decompress to %d bytes",
					dev->chunksize);
		return -EIO;
	}
	scatterlist_flip(sg, ts->zlib_sg, chunk_pages(dev));
	return 0;
}

/**
 * compress_chunk_lzf - compress a chunk using the LZF algorithm
 * @ts: the per-CPU temporary state buffer
 *
 * Returns the compressed size or -EFBIG if the chunk isn't worth storing
 * compressed (because it didn't compress well).  Must be called from process
 * context.
 **/
static int compress_chunk_lzf(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg)
{
	int size;
	
	scatterlist_transfer(sg, ts->lzf_buf_uncompressed, dev->chunksize,
				READ);
	size=lzf_compress(ts->lzf_buf_uncompressed, dev->chunksize,
				ts->lzf_buf_compressed, dev->chunksize,
				ts->lzf_compress);
	if (size == 0 || !should_store_chunk_compressed(dev, size)) {
		/* Compressed data is too big */
		return -EFBIG;
	}
	/* We write the whole chunk out to disk, so make sure we're not
	   leaking data. */
	memset(ts->lzf_buf_compressed + size, 0, dev->chunksize - size);
	scatterlist_transfer(sg, ts->lzf_buf_compressed, dev->chunksize, WRITE);
	return size;
}

/**
 * decompress_chunk_lzf - decompress an LZF-compressed chunk
 * @ts : the per-CPU temporary state buffer
 * @len: the length of the compressed data
 *
 * Returns 0 on success or -EIO on error.  Must be called from process context.
 **/
static int decompress_chunk_lzf(struct nexus_dev *dev,
			struct nexus_tfm_state *ts, struct scatterlist *sg,
			unsigned len)
{
	scatterlist_transfer(sg, ts->lzf_buf_compressed, len, READ);
	len=lzf_decompress(ts->lzf_buf_compressed, len,
				ts->lzf_buf_uncompressed, dev->chunksize);
	if (len != dev->chunksize)
		return -EIO;
	scatterlist_transfer(sg, ts->lzf_buf_uncompressed, dev->chunksize,
				WRITE);
	return 0;
}

/**
 * compress_chunk - compress a chunk with the specified algorithm
 * @ts: the per-CPU temporary state buffer
 *
 * Returns the compressed size, -EFBIG if the chunk isn't worth storing
 * compressed (because it didn't compress well), or -EIO on error.  Must
 * be called from process context.  @sg is updated in place.
 **/
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

/**
 * decompress_chunk - decompress a chunk with the specified algorithm
 * @ts: the per-CPU temporary state buffer
 * @len: the length of the compressed data
 *
 * Returns 0 on success or -EIO on error.  Must be called from process context.
 * @sg is updated in place.
 **/
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

/**
 * crypto_hash - generate the cryptographic hash of some data
 * @ts    : the per-CPU temporary state buffer
 * @nbytes: the number of input bytes in @sg
 * @out   : where to write the hash value
 *
 * We use whichever hash algorithm is associated with the crypto suite
 * associated with @dev.  @out must be able to hold the appropriate number
 * of bytes.
 **/
int crypto_hash(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, unsigned nbytes, u8 *out)
{
	return cryptoapi_hash(ts->hash[dev->suite], sg, nbytes, out);
}

/**
 * crypto_cipher - encrypt or decrypt some data
 * @ts   : the per-CPU temporary state buffer
 * @len  : the number of input bytes in @sg
 * @dir  : %READ to decrypt, %WRITE to encrypt
 * @doPad: whether to do PKCS padding
 *
 * @key must have a length equal to the key length parameter for the cipher
 * suite associated with @dev.  @sg is updated in place.  @doPad must be
 * true if @len is not a multiple of the cipher block size.
 *
 * Returns the length of the encrypted data, or an error code.  If @doPad is
 * false, the encrypted length will always be equal to @len.
 **/
int crypto_cipher(struct nexus_dev *dev, struct nexus_tfm_state *ts,
			struct scatterlist *sg, char key[], unsigned len,
			int dir, int doPad)
{
	struct crypto_blkcipher *tfm=ts->cipher[dev->suite];
	char iv[8]={0}; /* XXX */
	int ret;
	unsigned key_len=suite_info(dev->suite)->key_len;
	
	crypto_blkcipher_set_iv(tfm, iv, sizeof(iv));
	BUG_ON(key_len > suite_info(dev->suite)->hash_len);  /* XXX */
	ret=crypto_blkcipher_setkey(tfm, key, key_len);
	if (ret)
		return ret;
	
	if (dir == READ) {
		ret=cryptoapi_decrypt(tfm, sg, sg, len);
		if (ret)
			return ret;
		if (doPad)
			return crypto_unpad(dev, sg, len);
		else
			return len;
	} else {
		if (doPad)
			len=crypto_pad(dev, sg, len);
		ret=cryptoapi_encrypt(tfm, sg, sg, len);
		if (ret)
			return ret;
		return len;
	}
}

/**
 * compression_type_ok - returns true if @compress is valid for @dev
 **/
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

/**
 * suite_add - allocate transforms in @ts for @suite
 *
 * Returns 0 or error code.  @suite must not already be allocated in @ts.
 * If @suite uses the SHA-1 hash, and cryptoapi selects an unoptimized SHA-1
 * implementation on architectures where an optimized one is available,
 * and we have not complained about this yet, a warning is printed to the
 * system log.
 **/
int suite_add(struct nexus_tfm_state *ts, enum nexus_crypto suite)
{
	const struct tfm_suite_info *info;
	struct crypto_blkcipher *cipher;
	struct crypto_hash *hash;
	static int have_warned;
	
	BUG_ON(ts->cipher[suite] != NULL);
	
	info=suite_info(suite);
	hash=cryptoapi_alloc_hash(info);
	if (IS_ERR(hash))
		return PTR_ERR(hash);
	if (info->cipher_name != NULL) {
		cipher=cryptoapi_alloc_cipher(info);
		if (IS_ERR(cipher)) {
			crypto_free_hash(hash);
			return PTR_ERR(cipher);
		}
	} else {
		cipher=NULL;
	}
	ts->cipher[suite]=cipher;
	ts->hash[suite]=hash;
	
	if (!have_warned && !strcmp("sha1", info->hash_name) &&
				sha1_impl_is_suboptimal(hash)) {
		/* Actually, the presence of the SHA1 accelerator only matters
		   when the tfm is first allocated.  Does anyone have better
		   wording for this? */
		log(KERN_NOTICE, "Using unoptimized SHA1; load sha1-"
					SHA1_ACCEL_ARCH ".ko to improve "
					"performance");
		have_warned=1;
	}
	return 0;
}

/**
 * suite_remove - free transforms in @ts for @suite
 *
 * @suite must already be allocated in @ts.
 **/
void suite_remove(struct nexus_tfm_state *ts, enum nexus_crypto suite)
{
	BUG_ON(ts->hash[suite] == NULL);
	crypto_free_hash(ts->hash[suite]);
	ts->hash[suite]=NULL;
	if (ts->cipher[suite] != NULL) {
		crypto_free_blkcipher(ts->cipher[suite]);
		ts->cipher[suite]=NULL;
	}
}

/**
 * compress_add - allocate buffers in @ts for @alg
 *
 * Returns 0 or error code.  @alg must not already be allocated in @ts.
 *
 * XXX We always allocate temporary buffers of size %MAX_CHUNKSIZE, which is
 * defined for this purpose.  (There's no other reason the chunksize couldn't
 * be larger.)  We should dynamically resize the buffers to fit the largest
 * chunksize we actually need at the moment, rather than using an arbitrary
 * constant.
 **/
int compress_add(struct nexus_tfm_state *ts, enum nexus_compress alg)
{
	switch (alg) {
	case NEXUS_COMPRESS_NONE:
		break;
	case NEXUS_COMPRESS_ZLIB:
		ts->zlib_sg=alloc_scatterlist(MAX_CHUNKSIZE);
		if (ts->zlib_sg == NULL)
			return -ENOMEM;
		/* The deflate workspace size is too large for kmalloc */
		ts->zlib_deflate=vmalloc(zlib_deflate_workspacesize());
		if (ts->zlib_deflate == NULL) {
			free_scatterlist(ts->zlib_sg, MAX_CHUNKSIZE);
			ts->zlib_sg=NULL;
			return -ENOMEM;
		}
		ts->zlib_inflate=kmalloc(zlib_inflate_workspacesize(),
					GFP_KERNEL);
		if (ts->zlib_inflate == NULL) {
			vfree(ts->zlib_deflate);
			ts->zlib_deflate=NULL;
			free_scatterlist(ts->zlib_sg, MAX_CHUNKSIZE);
			ts->zlib_sg=NULL;
			return -ENOMEM;
		}
		break;
	case NEXUS_COMPRESS_LZF:
		ts->lzf_buf_compressed=vmalloc(MAX_CHUNKSIZE);
		if (ts->lzf_buf_compressed == NULL)
			return -ENOMEM;
		ts->lzf_buf_uncompressed=vmalloc(MAX_CHUNKSIZE);
		if (ts->lzf_buf_uncompressed == NULL) {
			vfree(ts->lzf_buf_compressed);
			ts->lzf_buf_compressed=NULL;
			return -ENOMEM;
		}
		ts->lzf_compress=kmalloc(sizeof(LZF_STATE), GFP_KERNEL);
		if (ts->lzf_compress == NULL) {
			vfree(ts->lzf_buf_uncompressed);
			ts->lzf_buf_uncompressed=NULL;
			vfree(ts->lzf_buf_compressed);
			ts->lzf_buf_compressed=NULL;
			return -ENOMEM;
		}
		break;
	case NEXUS_NR_COMPRESS:
		BUG();
	}
	return 0;
}

/**
 * compress_remove - free buffers in @ts for @alg
 *
 * @alg must already be allocated in @ts.
 **/
void compress_remove(struct nexus_tfm_state *ts, enum nexus_compress alg)
{
	switch (alg) {
	case NEXUS_COMPRESS_NONE:
		break;
	case NEXUS_COMPRESS_ZLIB:
		BUG_ON(ts->zlib_inflate == NULL);
		kfree(ts->zlib_inflate);
		ts->zlib_inflate=NULL;
		vfree(ts->zlib_deflate);
		ts->zlib_deflate=NULL;
		free_scatterlist(ts->zlib_sg, MAX_CHUNKSIZE);
		ts->zlib_sg=NULL;
		break;
	case NEXUS_COMPRESS_LZF:
		BUG_ON(ts->lzf_compress == NULL);
		kfree(ts->lzf_compress);
		ts->lzf_compress=NULL;
		vfree(ts->lzf_buf_uncompressed);
		ts->lzf_buf_uncompressed=NULL;
		vfree(ts->lzf_buf_compressed);
		ts->lzf_buf_compressed=NULL;
		break;
	case NEXUS_NR_COMPRESS:
		BUG();
	}
}

/**
 * transform_validate - perform sanity-checks on transforms specified in @dev
 *
 * Tests suite and compress fields in @dev to verify that userspace requested
 * reasonable transforms.  Returns 0 if all tests pass.  If a test fails,
 * returns -EINVAL and prints a message to the system log.
 **/
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
