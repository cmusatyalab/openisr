/*
 * blobtool - encode/decode file data
 *
 * Copyright (C) 2007-2009 Carnegie Mellon University
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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ftw.h>
#include <glib.h>
#include <zlib.h>
#include <archive.h>
#include <archive_entry.h>
#include "isrcrypto.h"

/* For libarchive 1.2 */
#ifndef ARCHIVE_EXTRACT_SECURE_SYMLINKS
#define ARCHIVE_EXTRACT_SECURE_SYMLINKS 0
#endif
#ifndef ARCHIVE_EXTRACT_SECURE_NODOTDOT
#define ARCHIVE_EXTRACT_SECURE_NODOTDOT 0
#endif

#define BUFSZ 32768
#define RNDFILE "/dev/urandom"
#define SALT_MAGIC "Salted__"
#define SALT_LEN 8
#define ENC_HEADER_LEN (strlen(SALT_MAGIC) + SALT_LEN)
#define FTW_FDS 16
#define ARCHIVE_EXTRACT_FLAGS  (ARCHIVE_EXTRACT_TIME |\
				ARCHIVE_EXTRACT_UNLINK |\
				ARCHIVE_EXTRACT_SECURE_SYMLINKS |\
				ARCHIVE_EXTRACT_SECURE_NODOTDOT)

/* Crypto parameters */
static enum isrcry_cipher cipher = ISRCRY_CIPHER_AES;
static unsigned cipher_block = 16;
static unsigned keylen = 16;
static enum isrcry_mode mode = ISRCRY_MODE_CBC;
static enum isrcry_padding padding = ISRCRY_PADDING_PKCS5;
static enum isrcry_hash hash = ISRCRY_HASH_SHA1;
static unsigned hashlen = 20;

/* Command-line parameters */
static int keyroot_fd;
static const char *keyroot;
static const char *infile;
static const char *outfile;
static const char *parent_dir;
static gboolean encode = TRUE;
static gboolean want_encrypt;
static gboolean want_hash;
static gboolean want_zlib;
static gboolean want_chunk_crypto;
static gboolean want_tar;
static int compress_level = Z_BEST_COMPRESSION;

/** Utility ******************************************************************/

struct iodata {
	FILE *infp;
	FILE *outfp;
	GString *in;
	GString *out;
};

#define warn(str, args...) g_printerr("blobtool: " str "\n", ## args)

#define die(str, args...) do { \
		g_printerr("blobtool: " str "\n", ## args); \
		exit(1); \
	} while (0)

static void *expand_string(GString *str, unsigned len)
{
	unsigned offset = str->len;

	g_string_set_size(str, offset + len);
	return str->str + offset;
}

static void swap_strings(struct iodata *iod)
{
	GString *tmp;

	tmp = iod->in;
	iod->in = iod->out;
	iod->out = tmp;
	g_string_truncate(iod->out, 0);
}

/** Cipher *******************************************************************/

static void get_keyroot(void)
{
	GString *str;
	char buf[32];
	ssize_t ret;

	str = g_string_new("");
	while ((ret = read(keyroot_fd, buf, sizeof(buf))) > 0)
		g_string_append_len(str, buf, ret);
	if (ret == -1)
		die("Failed to read keyroot fd %d", keyroot_fd);
	keyroot = g_strchomp(g_string_free(str, FALSE));
}

static void hex2bin(const char *hex, char *bin, int bin_len)
{
	unsigned char *uhex=(unsigned char *)hex;
	int i;

	for (i=0; i<bin_len; i++)
		bin[i] = (g_ascii_xdigit_value(uhex[2*i]) << 4) +
					g_ascii_xdigit_value(uhex[2*i+1]);
}

/* enc(1)-compatible key derivation */
static void set_cipher_key(struct isrcry_cipher_ctx *ctx, const char *salt)
{
	struct isrcry_hash_ctx *hash;
	unsigned hashlen = isrcry_hash_len(ISRCRY_HASH_MD5);
	char buf[keylen + cipher_block + hashlen];  /* key + IV + overflow */
	char *key = buf;
	char *iv = buf + keylen;
	char *cur = buf;
	int remaining;
	unsigned krlen = strlen(keyroot);
	enum isrcry_result ret;

	hash = isrcry_hash_alloc(ISRCRY_HASH_MD5);
	if (hash == NULL)
		die("Couldn't allocate MD5 hash");
	for (remaining = keylen + cipher_block; remaining > 0;
				remaining -= hashlen, cur += hashlen) {
		if (cur > buf)
			isrcry_hash_update(hash, cur - hashlen, hashlen);
		isrcry_hash_update(hash, keyroot, krlen);
		isrcry_hash_update(hash, salt, SALT_LEN);
		isrcry_hash_final(hash, cur);
	}
	isrcry_hash_free(hash);
	ret = isrcry_cipher_init(ctx, encode ? ISRCRY_ENCRYPT : ISRCRY_DECRYPT,
				key, keylen, iv);
	if (ret)
		die("Couldn't initialize cipher: %s", isrcry_strerror(ret));
}

static void set_cipher_key_direct(struct isrcry_cipher_ctx *ctx)
{
	unsigned krlen = strlen(keyroot);
	char key[krlen / 2];
	enum isrcry_result ret;

	if (krlen == 0 || krlen % 2)
		die("Provided key is not a valid hex string");
	hex2bin(keyroot, key, sizeof(key));
	ret = isrcry_cipher_init(ctx, encode ? ISRCRY_ENCRYPT : ISRCRY_DECRYPT,
				key, sizeof(key), NULL);
	if (ret)
		die("Couldn't initialize cipher: %s", isrcry_strerror(ret));
}

static void init_cipher(struct isrcry_cipher_ctx *ctx, const char **in,
			unsigned *inlen, GString *out)
{
	FILE *fp;
	char salt[SALT_LEN];

	get_keyroot();
	if (want_chunk_crypto) {
		set_cipher_key_direct(ctx);
		return;
	}
	if (encode) {
		g_string_append(out, SALT_MAGIC);
		fp = fopen(RNDFILE, "r");
		if (fp == NULL)
			die("Couldn't open " RNDFILE);
		while (fread(salt, 1, sizeof(salt), fp) < sizeof(salt));
		fclose(fp);
		g_string_append_len(out, salt, sizeof(salt));
		set_cipher_key(ctx, salt);
	} else {
		if (*inlen < ENC_HEADER_LEN)
			die("Couldn't read header of encrypted data");
		if (memcmp(*in, SALT_MAGIC, strlen(SALT_MAGIC)))
			die("Invalid magic string in encrypted data");
		*in += strlen(SALT_MAGIC);
		set_cipher_key(ctx, *in);
		*in += SALT_LEN;
		*inlen -= ENC_HEADER_LEN;
	}
}

static void run_cipher(const char *in, unsigned inlen, GString *out,
			gboolean final)
{
	static struct isrcry_cipher_ctx *ctx;
	static void *partial;
	static unsigned offset;
	char finalbuf[2 * cipher_block];
	unsigned count;
	unsigned long outlen;
	enum isrcry_result ret;

	if (ctx == NULL) {
		ctx = isrcry_cipher_alloc(cipher, mode);
		if (ctx == NULL)
			die("Couldn't allocate cipher");
		partial = g_malloc(cipher_block);
		init_cipher(ctx, &in, &inlen, out);
	}
	/* We always hold a block in reserve for isrcry_cipher_final().  This
	   means that we never run a block through isrcry_cipher_process()
	   unless at least one more byte is pending. */
	if (offset) {
		count = MIN(cipher_block - offset, inlen);
		memcpy(partial + offset, in, count);
		offset += count;
		in += count;
		inlen -= count;
		if (offset == cipher_block && inlen > 0) {
			isrcry_cipher_process(ctx, partial, cipher_block,
					expand_string(out, cipher_block));
			offset = 0;
		}
	}
	if (inlen / cipher_block) {
		count = (inlen / cipher_block) * cipher_block;
		if (!(inlen % cipher_block))
			count -= cipher_block;
		isrcry_cipher_process(ctx, in, count,
					expand_string(out, count));
		in += count;
		inlen -= count;
	}
	g_assert(inlen <= cipher_block);
	memcpy(partial, in, inlen);
	offset += inlen;
	if (final) {
		outlen = sizeof(finalbuf);
		ret = isrcry_cipher_final(ctx, padding, partial, offset,
					finalbuf, &outlen);
		if (ret)
			die("Couldn't finalize cipher: %s",
						isrcry_strerror(ret));
		g_string_append_len(out, finalbuf, outlen);
	}
}

/** Hash *********************************************************************/

static void run_hash(const char *in, unsigned inlen, GString *out,
			gboolean final)
{
	static struct isrcry_hash_ctx *ctx;
	unsigned char result[hashlen];
	unsigned n;

	if (ctx == NULL) {
		ctx = isrcry_hash_alloc(hash);
		if (ctx == NULL)
			die("Couldn't allocate hash");
	}
	isrcry_hash_update(ctx, in, inlen);
	if (final) {
		isrcry_hash_final(ctx, result);
		for (n = 0; n < hashlen; n++)
			g_string_append_printf(out, "%.2x", result[n]);
		g_string_append_c(out, '\n');
	}
}

/** Zlib compression *********************************************************/

static void run_zlib_compress(const char *in, unsigned inlen, GString *out,
			gboolean final)
{
	static z_stream strm;
	char buf[BUFSZ];
	int ret;

	if (strm.state == NULL) {
		if (deflateInit(&strm, compress_level) != Z_OK)
			die("zlib init failed: %s", strm.msg);
	}
	strm.next_in = (void *) in;
	strm.avail_in = inlen;
	while (strm.avail_in > 0) {
		strm.next_out = (void *) buf;
		strm.avail_out = sizeof(buf);
		if (deflate(&strm, 0) != Z_OK)
			die("zlib deflate failed: %s", strm.msg);
		g_string_append_len(out, buf, sizeof(buf) - strm.avail_out);
	}
	if (final) {
		do {
			strm.next_out = (void *) buf;
			strm.avail_out = sizeof(buf);
			ret = deflate(&strm, Z_FINISH);
			if (ret != Z_STREAM_END && ret != Z_OK)
				die("zlib deflate failed: %s", strm.msg);
			g_string_append_len(out, buf, sizeof(buf) -
						strm.avail_out);
		} while (ret != Z_STREAM_END);
		if (deflateEnd(&strm) != Z_OK)
			die("zlib deflate failed: %s", strm.msg);
	}
}

static void run_zlib_decompress(const char *in, unsigned inlen, GString *out,
			gboolean final)
{
	static z_stream strm;
	static gboolean done;
	static gboolean warned;
	char buf[BUFSZ];
	int ret;

	if (strm.state == NULL) {
		if (inflateInit(&strm) != Z_OK)
			die("zlib init failed: %s", strm.msg);
	}
	strm.next_in = (void *) in;
	strm.avail_in = inlen;
	while (strm.avail_in > 0 && !done) {
		strm.next_out = (void *) buf;
		strm.avail_out = sizeof(buf);
		ret = inflate(&strm, Z_SYNC_FLUSH);
		if (ret != Z_STREAM_END && ret != Z_OK)
			die("zlib inflate failed: %s", strm.msg);
		g_string_append_len(out, buf, sizeof(buf) - strm.avail_out);
		/* If zlib says we're done decoding, then we are, even
		   if there's input left over */
		if (ret == Z_STREAM_END)
			done = TRUE;
	}
	if (done && strm.avail_in > 0 && !warned) {
		warned = TRUE;
		warn("ignoring trailing garbage in zlib stream");
	}
	if (final) {
		if (!done)
			die("zlib stream ended prematurely");
		if (inflateEnd(&strm) != Z_OK)
			die("zlib inflate failed: %s", strm.msg);
	}
}

/** Generic control **********************************************************/

#define action(name) do { \
		if (ops++) \
			swap_strings(iod); \
		run_ ## name(iod->in->str, iod->in->len, iod->out, final); \
	} while (0)
static void run_buffer(struct iodata *iod, gboolean final)
{
	int ops = 0;

	if (encode) {
		if (want_zlib)
			action(zlib_compress);
		if (want_encrypt)
			action(cipher);
	} else {
		if (want_encrypt)
			action(cipher);
		if (want_zlib)
			action(zlib_decompress);
	}
	if (want_hash)
		action(hash);
	/* If we haven't been asked to do anything, copy in to out */
	if (ops == 0)
		g_string_append_len(iod->out, iod->in->str, iod->in->len);
}
#undef action

static void run_stream(struct iodata *iod)
{
	size_t len;

	do {
		g_string_set_size(iod->in, BUFSZ);
		g_string_truncate(iod->out, 0);
		len = fread(iod->in->str, 1, iod->in->len, iod->infp);
		if (ferror(iod->infp))
			die("Error reading input");
		g_string_set_size(iod->in, len);
		run_buffer(iod, feof(iod->infp));
		fwrite(iod->out->str, 1, iod->out->len, iod->outfp);
		if (ferror(iod->outfp))
			die("Error writing output");
	} while (!feof(iod->infp));
}

/** Tar control **************************************************************/

/* tar I/O uses a different main loop than non-tar I/O, since we're not just
   processing one FD into another. */

static ssize_t archive_read(struct archive *arch, void *data,
			const void **buffer)
{
	struct iodata *iod = data;
	size_t len;

	/* At EOF, run_buffer() may or may not produce some output.  If not,
	   we return 0 immediately.  But if it does, we won't return 0 until
	   the next time we're called.  If we're not at EOF, we must not
	   return 0. */
	if (feof(iod->infp))
		return 0;
	do {
		g_string_set_size(iod->in, BUFSZ);
		g_string_truncate(iod->out, 0);
		len = fread(iod->in->str, 1, iod->in->len, iod->infp);
		if (ferror(iod->infp)) {
			archive_set_error(arch, EIO, "Error reading input");
			return ARCHIVE_FATAL;
		}
		g_string_set_size(iod->in, len);
		run_buffer(iod, feof(iod->infp));
	} while (iod->out->len == 0 && !feof(iod->infp));
	*buffer = iod->out->str;
	return iod->out->len;
}

static ssize_t archive_write(struct archive *arch, void *data, void *buffer,
			size_t length)
{
	struct iodata *iod = data;

	g_string_truncate(iod->in, 0);
	g_string_truncate(iod->out, 0);
	g_string_append_len(iod->in, buffer, length);
	run_buffer(iod, FALSE);
	if (fwrite(iod->out->str, 1, iod->out->len, iod->outfp) <
				iod->out->len) {
		archive_set_error(arch, EIO, "Error writing output");
		return ARCHIVE_FATAL;
	}
	return length;
}

static int archive_finish_write(struct archive *arch, void *data)
{
	struct iodata *iod = data;

	g_string_truncate(iod->in, 0);
	g_string_truncate(iod->out, 0);
	run_buffer(iod, TRUE);
	if (fwrite(iod->out->str, 1, iod->out->len, iod->outfp) <
				iod->out->len) {
		archive_set_error(arch, EIO, "Error writing final output");
		return ARCHIVE_FATAL;
	}
	return ARCHIVE_OK;
}

static void read_archive(struct iodata *iod)
{
	struct archive *arch;
	struct archive_entry *ent;
	int ret;

	arch = archive_read_new();
	if (arch == NULL)
		die("Couldn't read archive read object");
	if (archive_read_support_format_tar(arch))
		die("Enabling tar format: %s", archive_error_string(arch));
	if (archive_read_support_compression_gzip(arch))
		die("Enabling gzip format: %s", archive_error_string(arch));
	if (archive_read_open(arch, iod, NULL, archive_read, NULL))
		die("Opening archive: %s", archive_error_string(arch));
	while (!(ret = archive_read_next_header(arch, &ent)))
		if (archive_read_extract(arch, ent, ARCHIVE_EXTRACT_FLAGS))
			die("Extracting %s: %s", archive_entry_pathname(ent),
						archive_error_string(arch));
	if (ret != ARCHIVE_EOF)
		die("Reading archive: %s", archive_error_string(arch));
	if (archive_read_close(arch))
		die("Closing archive: %s", archive_error_string(arch));
	archive_read_finish(arch);
}

/* ftw() provides no means to pass a data pointer to the called function, so
   we have to use a global.  (fts() has a nicer interface but doesn't work
   for _FILE_OFFSET_BITS = 64.)  This is only for write_entry(); pretend it
   doesn't exist otherwise. */
static struct archive *write_entry_archive;

static int write_entry(const char *path, const struct stat *st, int type,
			struct FTW *ignored)
{
	struct archive *arch = write_entry_archive;
	struct archive_entry *ent;
	FILE *fp = NULL;
	char buf[BUFSZ];
	ssize_t len;

	(void)ignored;

	switch (type) {
	case FTW_D:
		break;
	case FTW_F:
		/* Make sure we can read the file. */
		fp = fopen(path, "r");
		if (fp == NULL) {
			warn("Couldn't read %s: %s", path, strerror(errno));
			return 0;
		}
		break;
	case FTW_SL:
		/* Get the symlink target. */
		len = readlink(path, buf, sizeof(buf) - 1);
		if (len == -1) {
			warn("Couldn't read link %s: %s", path,
						strerror(errno));
			return 0;
		}
		buf[len] = 0;
		break;
	case FTW_DNR:
		warn("Couldn't read directory: %s", path);
		return 0;
	case FTW_NS:
		warn("Couldn't stat: %s", path);
		return 0;
	default:
		die("write_entry: Unknown type code %d: %s", type, path);
	}

	ent = archive_entry_new();
	if (ent == NULL)
		die("Couldn't allocate archive entry");
	archive_entry_copy_stat(ent, st);
	archive_entry_set_pathname(ent, path);
	if (S_ISLNK(st->st_mode))
		archive_entry_set_symlink(ent, buf);
	if (archive_write_header(arch, ent))
		die("Couldn't write archive header for %s: %s", path,
					archive_error_string(arch));
	archive_entry_free(ent);

	if (fp != NULL) {
		while (!feof(fp)) {
			len = fread(buf, 1, sizeof(buf), fp);
			if (ferror(fp))
				die("Error reading %s", path);
			/* libarchive < 2.4.8 will fail zero-byte writes
			   when using gzip/bzip2 */
			if (len > 0 && archive_write_data(arch, buf, len)
						!= len)
				die("Couldn't write archive data for %s: %s",
						path,
						archive_error_string(arch));
		}
		fclose(fp);
	}
	return 0;
}

static void write_archive(struct iodata *iod, char * const *paths)
{
	struct archive *arch;

	arch = archive_write_new();
	if (arch == NULL)
		die("Couldn't read archive write object");
	if (archive_write_set_format_pax_restricted(arch))
		die("Setting tar format: %s", archive_error_string(arch));
	if (archive_write_set_compression_gzip(arch))
		die("Setting compression format: %s",
					archive_error_string(arch));
	if (archive_write_open(arch, iod, NULL, archive_write,
				archive_finish_write))
		die("Opening archive: %s", archive_error_string(arch));
	write_entry_archive = arch;  /* sigh */
	for (; *paths != NULL; paths++)
		if (nftw(*paths, write_entry, FTW_FDS, FTW_PHYS))
			die("Error traversing path: %s", *paths);
	if (archive_write_close(arch))
		die("Closing archive: %s", archive_error_string(arch));
	archive_write_finish(arch);
}

/** Top level ****************************************************************/

static GOptionEntry options[] = {
	{"in", 'i', 0, G_OPTION_ARG_FILENAME, &infile, "Input file", "path"},
	{"out", 'o', 0, G_OPTION_ARG_FILENAME, &outfile, "Output file", "path"},
	{"keyroot-fd", 'k', 0, G_OPTION_ARG_INT, &keyroot_fd, "File descriptor from which to read the keyroot", "fd"},
	{"decode", 'd', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &encode, "Decode encoded input", NULL},
	{"encrypt", 'e', 0, G_OPTION_ARG_NONE, &want_encrypt, "Encrypt data", NULL},
	{"chunk", 'c', 0, G_OPTION_ARG_NONE, &want_chunk_crypto, "Encrypt with no salt, zero IV, and provided hex key", NULL},
	{"hash", 'h', 0, G_OPTION_ARG_NONE, &want_hash, "Hash data", NULL},
	{"zlib", 'Z', 0, G_OPTION_ARG_NONE, &want_zlib, "Compress data with zlib", NULL},
	{"level", 'l', 0, G_OPTION_ARG_INT, &compress_level, "Compression level (1-9)", NULL},
	{"tar", 't', 0, G_OPTION_ARG_NONE, &want_tar, "Generate or extract a gzipped tar archive", NULL},
	{"directory", 'C', 0, G_OPTION_ARG_FILENAME, &parent_dir, "Change to directory before tarring/untarring files", "dir"},
	{NULL}
};

int main(int argc, char **argv)
{
	GOptionContext *octx;
	GError *err = NULL;
	struct iodata iod = {
		.infp = stdin,
		.outfp = stdout,
		.in = g_string_sized_new(BUFSZ),
		.out = g_string_sized_new(BUFSZ)
	};

	octx = g_option_context_new("[paths] - encode/decode files");
	g_option_context_add_main_entries(octx, options, NULL);
	if (!g_option_context_parse(octx, &argc, &argv, &err))
		die("%s", err->message);
	g_option_context_free(octx);
	if (want_tar && want_hash)
		die("--tar is incompatible with --hash");
	if (want_tar && encode && infile != NULL)
		die("--in invalid with --tar in encode mode");
	if (want_tar && !encode && outfile != NULL)
		die("--out invalid with --tar --decode");
	if (want_tar && encode && g_strv_length(argv) < 2)
		die("No input files or directories specified");
	if (!(want_tar && encode) && g_strv_length(argv) > 1)
		die("Extraneous arguments on command line");
	if (infile != NULL) {
		iod.infp = fopen(infile, "r");
		if (iod.infp == NULL)
			die("Couldn't open %s for reading", infile);
	}
	if (outfile != NULL) {
		iod.outfp = fopen(outfile, "w");
		if (iod.outfp == NULL)
			die("Couldn't open %s for writing", outfile);
	}
	if (parent_dir != NULL)
		if (chdir(parent_dir))
			die("Couldn't change to directory %s", parent_dir);

	if (want_tar) {
		if (encode)
			write_archive(&iod, argv + 1);
		else
			read_archive(&iod);
	} else {
		run_stream(&iod);
	}
	fclose(iod.infp);
	fclose(iod.outfp);
	return 0;
}
