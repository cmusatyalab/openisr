/*
 * Parcelkeeper - support daemon for the OpenISR (R) system virtual disk
 *
 * Copyright (C) 2006-2009 Carnegie Mellon University
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

#include <stdlib.h>
#include <string.h>
#include "defs.h"

#define DATAVER 3

#define OPTSTRS \
	optstr(VERSION), \
	optstr(CHUNKSIZE), \
	optstr(NUMCHUNKS), \
	optstr(CHUNKSPERDIR), \
	optstr(CRYPTO), \
	optstr(COMPRESS), \
	optstr(UUID), \
	optstr(SERVER), \
	optstr(USER), \
	optstr(PARCEL), \
	optstr(RPATH)

#define optstr(str) PC_ ## str
enum pc_ident {
	OPTSTRS,
	PC_DUPLICATE,
	PC_IGNORE
};
#undef optstr

#define optstr(str) {#str, PC_ ## str}
static const struct pc_option {
	char *key;
	enum pc_ident ident;
} pc_options[] = {
	OPTSTRS,
	{NULL}
};
#undef optstr

struct pc_parse_ctx {
	gchar *rpath;
	gboolean seen[sizeof(pc_options) / sizeof(pc_options[0]) - 1];
};

static enum pc_ident pc_find_option(struct pc_parse_ctx *ctx, const char *key,
			int line)
{
	const struct pc_option *opt;

	for (opt=pc_options; opt->key != NULL; opt++) {
		if (strcmp(key, opt->key))
			continue;
		if (ctx->seen[opt->ident]) {
			pk_log(LOG_ERROR, "Duplicate key %s at line %d",
						key, line);
			return PC_DUPLICATE;
		}
		ctx->seen[opt->ident]=TRUE;
		return opt->ident;
	}
	return PC_IGNORE;
}

static gboolean pc_have_options(struct pc_parse_ctx *ctx)
{
	const struct pc_option *opt;
	gboolean ret=TRUE;

	for (opt=pc_options; opt->key != NULL; opt++) {
		if (!ctx->seen[opt->ident]) {
			pk_log(LOG_ERROR, "Missing key %s in parcel.cfg",
						opt->key);
			ret=FALSE;
		}
	}
	return ret;
}

static pk_err_t pc_handle_option(struct pc_parse_ctx *ctx, enum pc_ident ident,
			char *value)
{
	gchar **strs;
	unsigned u;
	enum compresstype compress;

	switch (ident) {
	case PC_VERSION:
		if (parseuint(&u, value, 10)) {
			pk_log(LOG_ERROR, "Error parsing parcel data version"
						" %s", value);
			return PK_INVALID;
		}
		if (u != DATAVER) {
			pk_log(LOG_ERROR, "Unknown parcel data version: "
						"expected %d, found %u",
						DATAVER, u);
			return PK_INVALID;
		}
		break;
	case PC_CHUNKSIZE:
		if (parseuint(&parcel.chunksize, value, 10)) {
			pk_log(LOG_ERROR, "Invalid chunksize %s", value);
			return PK_INVALID;
		}
		break;
	case PC_NUMCHUNKS:
		if (parseuint(&parcel.chunks, value, 10)) {
			pk_log(LOG_ERROR, "Invalid chunk count %s", value);
			return PK_INVALID;
		}
		break;
	case PC_CHUNKSPERDIR:
		if (parseuint(&parcel.chunks_per_dir, value, 10)) {
			pk_log(LOG_ERROR, "Invalid CHUNKSPERDIR value %s",
						value);
			return PK_INVALID;
		}
		break;
	case PC_CRYPTO:
		parcel.crypto=parse_crypto(value);
		if (parcel.crypto == CRY_UNKNOWN) {
			pk_log(LOG_ERROR, "Unknown crypto suite %s", value);
			return PK_INVALID;
		}
		parcel.hashlen=crypto_hashlen(parcel.crypto);
		break;
	case PC_COMPRESS:
		parcel.required_compress=(1 << COMP_NONE);
		strs=g_strsplit(value, ",", 0);
		for (u=0; strs[u] != NULL; u++) {
			compress=parse_compress(strs[u]);
			if (compress == COMP_UNKNOWN) {
				pk_log(LOG_ERROR, "Unknown compression type"
							" %s", strs[u]);
				g_strfreev(strs);
				return PK_INVALID;
			}
			parcel.required_compress |= (1 << compress);
		}
		g_strfreev(strs);
		if (!compress_is_valid(config.compress)) {
			pk_log(LOG_ERROR, "This parcel does not support the "
						"requested compression type");
			return PK_INVALID;
		}
		break;
	case PC_UUID:
		if (canonicalize_uuid(value, &parcel.uuid))
			return PK_INVALID;
		break;
	case PC_SERVER:
		parcel.server=g_strdup(value);
		break;
	case PC_USER:
		parcel.user=g_strdup(value);
		break;
	case PC_PARCEL:
		parcel.parcel=g_strdup(value);
		break;
	case PC_RPATH:
		ctx->rpath=g_strdup(value);
		break;
	case PC_DUPLICATE:
		return PK_INVALID;
	case PC_IGNORE:
		break;
	}
	return PK_SUCCESS;
}

pk_err_t parse_parcel_cfg(void)
{
	struct pc_parse_ctx ctx = {};
	gchar *data;
	gchar **lines;
	gchar **parts;
	pk_err_t ret;
	int i;

	ret=read_file(config.parcel_cfg, &data, NULL);
	if (ret) {
		pk_log(LOG_ERROR, "Couldn't read parcel.cfg: %s",
					pk_strerror(ret));
		return ret;
	}
	lines=g_strsplit(data, "\n", 0);
	g_free(data);
	for (i=0; lines[i] != NULL; i++) {
		g_strstrip(lines[i]);
		if (lines[i][0] == '#' || lines[i][0] == 0)
			continue;
		parts=g_strsplit(lines[i], "=", 2);  /* key, value */
		if (g_strv_length(parts) != 2) {
			pk_log(LOG_ERROR, "Error parsing parcel.cfg at line %d",
						i + 1);
			goto bad;
		}
		g_strstrip(parts[0]);
		g_strstrip(parts[1]);
		if (pc_handle_option(&ctx, pc_find_option(&ctx, parts[0], i+1),
					parts[1]))
			goto bad;
		g_strfreev(parts);
	}
	g_strfreev(lines);
	if (!pc_have_options(&ctx))
		return PK_IOERR;
	parcel.master = g_strdup_printf("%s/%s/%s/last/hdk", ctx.rpath,
					parcel.user, parcel.parcel);
	g_free(ctx.rpath);
	return PK_SUCCESS;

bad:
	g_strfreev(parts);
	g_strfreev(lines);
	g_free(ctx.rpath);
	return PK_IOERR;
}
