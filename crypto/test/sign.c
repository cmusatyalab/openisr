/*
 * libisrcrypto - cryptographic library for the OpenISR (R) system
 *
 * Copyright (C) 2008-2009 Carnegie Mellon University
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.  A copy of the GNU Lesser General
 * Public License should have been distributed along with this library in the
 * file LICENSE.LGPL.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <glib.h>
#include "isrcrypto.h"

#define ALG	ISRCRY_SIGN_RSA_PSS_SHA1
#define KEYFMT	ISRCRY_KEY_FORMAT_RAW

void die(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

void *read_file(const char *path, unsigned *length)
{
	GError *err = NULL;
	gchar *data;
	gsize len;

	if (!g_file_get_contents(path, &data, &len, &err))
		die("Couldn't read %s: %s", path, err->message);
	if (length != NULL)
		*length = len;
	return data;
}

void write_file(const char *path, void *data, unsigned length)
{
	GError *err = NULL;

	if (!g_file_set_contents(path, data, length, &err))
		die("Couldn't write %s: %s", path, err->message);
}

void usage(const char *argv0)
{
	const char *prog = g_path_get_basename(argv0);

	fprintf(stderr, "Usage:\t%s genkey <bits> <pubkey@> <privkey@>\n",
				prog);
	fprintf(stderr, "\t%s sign <privkey> <data> <sig@>\n", prog);
	fprintf(stderr, "\t%s verify <pubkey> <data> <sig>\n", prog);
	fprintf(stderr, "Parameters marked with @ are outputs\n");
	exit(1);
}

int main(int argc, char **argv)
{
	struct isrcry_random_ctx *rctx;
	struct isrcry_sign_ctx *sctx;
	enum isrcry_result ret;
	char buf[8192];
	unsigned buflen;
	void *data;
	unsigned datalen;

	if (argc < 2)
		usage(argv[0]);

	rctx = isrcry_random_alloc();
	if (rctx == NULL)
		die("Couldn't allocate random ctx");
	sctx = isrcry_sign_alloc(ALG, rctx);
	if (sctx == NULL)
		die("Couldn't allocate sign ctx");

	if (!strcmp(argv[1], "genkey")) {
		if (argc != 5)
			usage(argv[0]);
		ret = isrcry_sign_make_keys(sctx, atoi(argv[2]) / 8);
		if (ret)
			die("make_keys returned %d", ret);
		buflen = sizeof(buf);
		ret = isrcry_sign_get_key(sctx, ISRCRY_KEY_PUBLIC, KEYFMT,
					buf, &buflen);
		if (ret)
			die("get_key(public) returned %d", ret);
		write_file(argv[3], buf, buflen);
		buflen = sizeof(buf);
		ret = isrcry_sign_get_key(sctx, ISRCRY_KEY_PRIVATE, KEYFMT,
					buf, &buflen);
		if (ret)
			die("get_key(private) returned %d", ret);
		write_file(argv[4], buf, buflen);
	} else if (!strcmp(argv[1], "sign")) {
		if (argc != 5)
			usage(argv[0]);
		data = read_file(argv[2], &datalen);
		ret = isrcry_sign_set_key(sctx, ISRCRY_KEY_PRIVATE, KEYFMT,
					data, datalen);
		if (ret)
			die("set_key returned %d", ret);
		g_free(data);
		data = read_file(argv[3], &datalen);
		isrcry_sign_update(sctx, data, datalen);
		g_free(data);
		buflen = sizeof(buf);
		ret = isrcry_sign_sign(sctx, buf, &buflen);
		if (ret)
			die("sign returned %d", ret);
		write_file(argv[4], buf, buflen);
	} else if (!strcmp(argv[1], "verify")) {
		if (argc != 5)
			usage(argv[0]);
		data = read_file(argv[2], &datalen);
		ret = isrcry_sign_set_key(sctx, ISRCRY_KEY_PUBLIC, KEYFMT,
					data, datalen);
		if (ret)
			die("set_key returned %d", ret);
		g_free(data);
		data = read_file(argv[3], &datalen);
		isrcry_sign_update(sctx, data, datalen);
		g_free(data);
		data = read_file(argv[4], &datalen);
		ret = isrcry_sign_verify(sctx, data, datalen);
		if (ret != ISRCRY_OK && ret != ISRCRY_BAD_SIGNATURE)
			die("verify returned %d", ret);
		else if (ret)
			printf("fail\n");
		else
			printf("pass\n");
		g_free(data);
	} else {
		usage(argv[0]);
	}
	isrcry_sign_free(sctx);
	isrcry_random_free(rctx);
	return 0;
}
