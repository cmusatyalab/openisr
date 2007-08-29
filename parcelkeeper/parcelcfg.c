/*
 * Parcelkeeper - support daemon for the OpenISR (TM) system virtual disk
 *
 * Copyright (C) 2006-2007 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <string.h>
#include <uuid.h>
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
	PC_DUPLICATE,
	PC_IGNORE,
	OPTSTRS
};
#undef optstr

#define optstr(str) {#str, PC_ ## str}
static struct pc_option {
	char *key;
	enum pc_ident ident;
	int seen;
} pc_options[] = {
	OPTSTRS,
	{NULL}
};
#undef optstr

static char *raw_master;

static enum pc_ident pc_find_option(char *key, int line)
{
	struct pc_option *opt;

	for (opt=pc_options; opt->key != NULL; opt++) {
		if (strcmp(key, opt->key))
			continue;
		if (opt->seen) {
			pk_log(LOG_ERROR, "Duplicate key %s at line %d",
						key, line);
			return PC_DUPLICATE;
		}
		opt->seen=1;
		return opt->ident;
	}
	return PC_IGNORE;
}

static int pc_have_options(void)
{
	struct pc_option *opt;
	int ret=1;

	for (opt=pc_options; opt->key != NULL; opt++) {
		if (!opt->seen) {
			pk_log(LOG_ERROR, "Missing key %s in parcel.cfg",
						opt->key);
			ret=0;
		}
	}
	return ret;
}

static pk_err_t pc_handle_option(enum pc_ident ident, char *value)
{
	unsigned u;
	char *tok;
	char *saveptr;
	enum compresstype compress;
	uuid_t *uuid;
	uuid_rc_t uurc;

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
		while ((tok=strtok_r(value, ",", &saveptr)) != NULL) {
			value=NULL;
			compress=parse_compress(tok);
			if (compress == COMP_UNKNOWN) {
				pk_log(LOG_ERROR, "Unknown compression type"
							" %s", tok);
				return PK_INVALID;
			}
			parcel.required_compress |= (1 << compress);
		}
		if (!compress_is_valid(config.compress)) {
			pk_log(LOG_ERROR, "This parcel does not support the "
						"requested compression type");
			return PK_INVALID;
		}
		break;
	case PC_UUID:
		uurc=uuid_create(&uuid);
		if (uurc) {
			pk_log(LOG_ERROR, "Can't create UUID object: %s",
						uuid_error(uurc));
			return PK_INVALID;
		}
		if (uuid_import(uuid, UUID_FMT_STR, value, strlen(value) + 1)) {
			pk_log(LOG_ERROR, "Invalid UUID");
			return PK_INVALID;
		}
		uurc=uuid_export(uuid, UUID_FMT_STR, (void *)&parcel.uuid,
					NULL);
		if (uurc) {
			pk_log(LOG_ERROR, "Can't format UUID: %s",
						uuid_error(uurc));
			return PK_INVALID;
		}
		uuid_destroy(uuid);
		break;
	case PC_SERVER:
		parcel.server=strdup(value);
		break;
	case PC_USER:
		parcel.user=strdup(value);
		break;
	case PC_PARCEL:
		parcel.parcel=strdup(value);
		break;
	case PC_RPATH:
		raw_master=strdup(value);
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
	FILE *fp;
	char buf[128];
	char *key;
	char *value;
	char *state;
	int line;

	fp=fopen(config.parcel_cfg, "r");
	if (fp == NULL) {
		pk_log(LOG_ERROR, "Couldn't open parcel.cfg");
		return PK_IOERR;
	}
	for (line=1; fgets(buf, sizeof(buf), fp) != NULL; line++) {
		if (buf[0] == '#' || !strcmp("\n", buf))
			continue;
		/* XXX bug: value cannot contain [ \t=] */
		key=strtok_r(buf, " \t=\n", &state);
		if (key != NULL)
			value=strtok_r(NULL, " \t=\n", &state);
		if (key == NULL || value == NULL) {
			pk_log(LOG_ERROR, "Error parsing parcel.cfg at line %d",
						line);
			goto bad;
		}
		if (pc_handle_option(pc_find_option(key, line), value))
			goto bad;
	}
	fclose(fp);
	if (!pc_have_options())
		return PK_IOERR;
	if (asprintf(&parcel.master, "%s/%s/%s/last/hdk", raw_master,
					parcel.user, parcel.parcel) == -1) {
		pk_log(LOG_ERROR, "malloc failure");
		return PK_NOMEM;
	}
	free(raw_master);
	return PK_SUCCESS;

bad:
	fclose(fp);
	return PK_IOERR;
}
