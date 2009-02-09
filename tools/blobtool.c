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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <zlib.h>
#include "isrcrypto.h"

#define BUFSZ 32768
#define RNDFILE "/dev/urandom"
#define SALT_MAGIC "Salted__"
#define SALT_LEN 8
#define ENC_HEADER_LEN (strlen(SALT_MAGIC) + SALT_LEN)

static enum isrcry_cipher cipher = ISRCRY_CIPHER_AES;
static unsigned cipher_block = 16;
static unsigned keylen = 16;
static enum isrcry_mode mode = ISRCRY_MODE_CBC;
static enum isrcry_padding padding = ISRCRY_PADDING_PKCS5;
static enum isrcry_hash hash = ISRCRY_HASH_SHA1;
static unsigned hashlen = 20;

static int keyroot_fd;
static const char *keyroot;
static gboolean encode = TRUE;
static gboolean want_encrypt;
static gboolean want_hash;
static gboolean want_zlib;
static gboolean want_chunk_crypto;
static int compress_level = Z_BEST_COMPRESSION;

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

static void swap_strings(GString **in, GString **out)
{
	GString *tmp;

	tmp = *in;
	*in = *out;
	*out = tmp;
	g_string_truncate(*out, 0);
}

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
		g_printerr("blobtool: ignoring trailing garbage in zlib "
					"stream\n");
	}
	if (final) {
		if (!done)
			die("zlib stream ended prematurely");
		if (inflateEnd(&strm) != Z_OK)
			die("zlib inflate failed: %s", strm.msg);
	}
}

#define action(name) do { \
		if (ops++) \
			swap_strings(in, out); \
		run_ ## name((*in)->str, (*in)->len, *out, final); \
	} while (0)
static void run_buffer(GString **in, GString **out, gboolean final)
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
		g_string_append_len(*out, (*in)->str, (*in)->len);
}
#undef action

static GOptionEntry options[] = {
	{"keyroot-fd", 'k', 0, G_OPTION_ARG_INT, &keyroot_fd, "File descriptor from which to read the keyroot", "fd"},
	{"decode", 'd', G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, &encode, "Decode encoded input", NULL},
	{"encrypt", 'e', 0, G_OPTION_ARG_NONE, &want_encrypt, "Encrypt data", NULL},
	{"chunk", 'c', 0, G_OPTION_ARG_NONE, &want_chunk_crypto, "Encrypt with no salt, zero IV, and provided hex key", NULL},
	{"hash", 'h', 0, G_OPTION_ARG_NONE, &want_hash, "Hash data", NULL},
	{"zlib", 'Z', 0, G_OPTION_ARG_NONE, &want_zlib, "Compress data with zlib", NULL},
	{"level", 'l', 0, G_OPTION_ARG_INT, &compress_level, "Compression level (1-9)", NULL},
	{NULL}
};

int main(int argc, char **argv)
{
	GOptionContext *octx;
	GError *err = NULL;
	GString *in;
	GString *out;
	size_t len;

	octx = g_option_context_new("- encode/decode files");
	g_option_context_add_main_entries(octx, options, NULL);
	if (!g_option_context_parse(octx, &argc, &argv, &err))
		die("%s", err->message);
	g_option_context_free(octx);

	in = g_string_sized_new(BUFSZ);
	out = g_string_sized_new(BUFSZ);
	do {
		g_string_set_size(in, BUFSZ);
		g_string_truncate(out, 0);
		len = fread(in->str, 1, in->len, stdin);
		if (ferror(stdin))
			die("Error reading input");
		g_string_set_size(in, len);
		run_buffer(&in, &out, len == 0);
		fwrite(out->str, 1, out->len, stdout);
	} while (len > 0);
	return 0;
}
