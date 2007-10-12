/*
 * zlib - encode or decode a deflate stream from stdin to stdout
 *
 * Copyright (C) 2007 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <zlib.h>

#define BUFSZ 8192

static const char *opts="cdh123456789";

void usage(char *argv0)
{
	fprintf(stderr, "Usage: %s [-%s]\n", argv0, opts);
	exit(2);
}

void die(char *msg)
{
	fprintf(stderr, "Error: %s\n", msg);
	exit(1);
}

void zdie(int err)
{
	char *msg;

	switch (err) {
	case Z_OK:
		msg="Z_OK";
		break;
	case Z_STREAM_END:
		msg="Z_STREAM_END";
		break;
	case Z_NEED_DICT:
		msg="Z_NEED_DICT";
		break;
	case Z_ERRNO:
		msg="Z_ERRNO";
		break;
	case Z_STREAM_ERROR:
		msg="Z_STREAM_ERROR";
		break;
	case Z_DATA_ERROR:
		msg="Z_DATA_ERROR";
		break;
	case Z_MEM_ERROR:
		msg="Z_MEM_ERROR";
		break;
	case Z_BUF_ERROR:
		msg="Z_BUF_ERROR";
		break;
	case Z_VERSION_ERROR:
		msg="Z_VERSION_ERROR";
		break;
	default:
		msg="Unknown error";
		break;
	}

	fprintf(stderr, "Error: zlib returns %s\n", msg);
	exit(1);
}

void comp(int level)
{
	z_stream strm;
	unsigned char ibuf[BUFSZ];
	unsigned char obuf[BUFSZ];
	ssize_t len;
	int ret;

	memset(&strm, 0, sizeof(strm));
	ret=deflateInit(&strm, level);
	if (ret != Z_OK)
		zdie(ret);
	while ((len=read(0, ibuf, BUFSZ)) > 0) {
		strm.next_in=ibuf;
		strm.avail_in=len;
		while (strm.avail_in > 0) {
			strm.next_out=obuf;
			strm.avail_out=BUFSZ;
			ret=deflate(&strm, 0);
			if (ret != Z_OK)
				zdie(ret);
			if (write(1, obuf, BUFSZ - strm.avail_out) <
						(int)(BUFSZ - strm.avail_out))
				die(strerror(errno));
		}
	}
	if (len == -1)
		die(strerror(errno));

	while (1) {
		strm.next_out=obuf;
		strm.avail_out=BUFSZ;
		ret=deflate(&strm, Z_FINISH);
		if (ret != Z_STREAM_END && ret != Z_OK)
			zdie(ret);
		if (write(1, obuf, BUFSZ - strm.avail_out) <
					(int)(BUFSZ - strm.avail_out))
			die(strerror(errno));
		if (ret == Z_STREAM_END)
			break;
	}
	ret=deflateEnd(&strm);
	if (ret != Z_OK)
		zdie(ret);
}

void decomp(void)
{
	z_stream strm;
	unsigned char ibuf[BUFSZ];
	unsigned char obuf[BUFSZ];
	ssize_t len;
	int ret;

	memset(&strm, 0, sizeof(strm));
	ret=inflateInit(&strm);
	if (ret != Z_OK)
		zdie(ret);
	while ((len=read(0, ibuf, BUFSZ)) > 0) {
		strm.next_in=ibuf;
		strm.avail_in=len;
		while (strm.avail_in > 0) {
			strm.next_out=obuf;
			strm.avail_out=BUFSZ;
			ret=inflate(&strm, Z_SYNC_FLUSH);
			if (ret != Z_STREAM_END && ret != Z_OK)
				zdie(ret);
			if (write(1, obuf, BUFSZ - strm.avail_out) <
						(int)(BUFSZ - strm.avail_out))
				die(strerror(errno));
			/* If zlib says we're done decoding, then we are, even
			   if there's input left over */
			if (ret == Z_STREAM_END)
				goto done;
		}
	}
	if (len == -1)
		die(strerror(errno));

done:
	/* This will return an error if the stream ended prematurely */
	ret=inflateEnd(&strm);
	if (ret != Z_OK)
		zdie(ret);
}

int main(int argc, char **argv)
{
	int opt;
	int decompress=0;
	int level=Z_DEFAULT_COMPRESSION;

	while ((opt=getopt(argc, argv, opts)) != -1) {
		switch (opt) {
		case 'c':
			/* Ignored for compatibility with other compression
			   programs */
			break;
		case 'd':
			decompress=1;
			break;
		case 'h':
		case '?':
			usage(argv[0]);
			break;
		default:
			level=opt - '0';
			break;
		}
	}
	if (optind != argc)
		usage(argv[0]);

	if (decompress)
		decomp();
	else
		comp(level);

	return 0;
}
