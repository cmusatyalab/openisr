/*
 * Parcelkeeper - support daemon for the OpenISR (R) system virtual disk
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include "defs.h"

#define TRANSPORT_TRIES 5
#define TRANSPORT_RETRY_DELAY 5

struct pk_connection {
	CURL *curl;
	char errbuf[CURL_ERROR_SIZE];
	char *buf;
	size_t offset;
};

static size_t curl_callback(void *data, size_t size, size_t nmemb,
			void *private)
{
	struct pk_connection *conn=private;
	size_t count = min(size * nmemb, parcel.chunksize - conn->offset);

	memcpy(conn->buf + conn->offset, data, count);
	conn->offset += count;
	return count;
}

static void transport_cleanup_conn(struct pk_connection *conn)
{
	if (conn->curl)
		curl_easy_cleanup(conn->curl);
	free(conn);
}

static pk_err_t transport_init_conn(struct pk_connection **result)
{
	struct pk_connection *conn;

	conn=malloc(sizeof(*conn));
	if (conn == NULL) {
		pk_log(LOG_ERROR, "malloc failure allocating connection");
		goto bad;
	}
	memset(conn, 0, sizeof(*conn));
	conn->curl=curl_easy_init();
	if (conn->curl == NULL) {
		pk_log(LOG_ERROR, "Couldn't initialize CURL handle");
		goto bad;
	}
	if (curl_easy_setopt(conn->curl, CURLOPT_NOPROGRESS, 1)) {
		pk_log(LOG_ERROR, "Couldn't disable curl progress meter");
		goto bad;
	}
	if (curl_easy_setopt(conn->curl, CURLOPT_NOSIGNAL, 1)) {
		pk_log(LOG_ERROR, "Couldn't disable signals");
		goto bad;
	}
	if (curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION,
				curl_callback)) {
		pk_log(LOG_ERROR, "Couldn't set write callback");
		goto bad;
	}
	if (curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, conn)) {
		pk_log(LOG_ERROR, "Couldn't set write callback data");
		goto bad;
	}
	if (curl_easy_setopt(conn->curl, CURLOPT_ERRORBUFFER, conn->errbuf)) {
		pk_log(LOG_ERROR, "Couldn't set error buffer");
		goto bad;
	}
	if (curl_easy_setopt(conn->curl, CURLOPT_FAILONERROR, 1)) {
		pk_log(LOG_ERROR, "Couldn't set fail-on-error flag");
		goto bad;
	}
	if (curl_easy_setopt(conn->curl, CURLOPT_MAXFILESIZE,
				parcel.chunksize)) {
		pk_log(LOG_ERROR, "Couldn't set maximum transfer size");
		goto bad;
	}
	*result=conn;
	return PK_SUCCESS;

bad:
	if (conn)
		transport_cleanup_conn(conn);
	return PK_CALLFAIL;
}

pk_err_t transport_init(void)
{
	if (curl_global_init(CURL_GLOBAL_ALL)) {
		pk_log(LOG_ERROR, "Couldn't initialize curl library");
		return PK_CALLFAIL;
	}
	return transport_init_conn(&state.conn);
}

void transport_shutdown(void)
{
	transport_cleanup_conn(state.conn);
}

static pk_err_t transport_get(void *buf, unsigned chunk, size_t *len)
{
	struct pk_connection *conn=state.conn;
	char *url;
	pk_err_t ret;
	CURLcode err;

	url=form_chunk_path(parcel.master, chunk);
	if (url == NULL) {
		pk_log(LOG_ERROR, "malloc failure");
		return PK_NOMEM;
	}
	pk_log(LOG_TRANSPORT, "Fetching %s", url);
	if (curl_easy_setopt(conn->curl, CURLOPT_URL, url)) {
		pk_log(LOG_ERROR, "Couldn't set connection URL");
		free(url);
		return PK_CALLFAIL;
	}
	conn->buf=buf;
	conn->offset=0;
	err=curl_easy_perform(conn->curl);
	if (err)
		pk_log(LOG_ERROR, "Fetching %s: %s", url, conn->errbuf);
	switch (err) {
	case CURLE_OK:
		*len=conn->offset;
		ret=PK_SUCCESS;
		break;
	case CURLE_COULDNT_RESOLVE_PROXY:
	case CURLE_COULDNT_RESOLVE_HOST:
	case CURLE_COULDNT_CONNECT:
	case CURLE_HTTP_RETURNED_ERROR:
	case CURLE_OPERATION_TIMEOUTED:
	case CURLE_GOT_NOTHING:
	case CURLE_SEND_ERROR:
	case CURLE_RECV_ERROR:
	case CURLE_BAD_CONTENT_ENCODING:
		ret=PK_NETFAIL;
		break;
	default:
		ret=PK_IOERR;
		break;
	}
	free(url);
	return ret;
}

pk_err_t transport_fetch_chunk(void *buf, unsigned chunk, const void *tag,
			unsigned *length)
{
	char calctag[parcel.hashlen];
	size_t len;
	int i;
	pk_err_t ret;

	for (i=0; i<TRANSPORT_TRIES; i++) {
		ret=transport_get(buf, chunk, &len);
		if (ret != PK_NETFAIL)
			break;
		pk_log(LOG_ERROR, "Fetching chunk %u failed; retrying in %d "
					"seconds", chunk,
					TRANSPORT_RETRY_DELAY);
		sleep(TRANSPORT_RETRY_DELAY);
	}
	if (ret != PK_SUCCESS) {
		pk_log(LOG_ERROR, "Couldn't fetch chunk %u", chunk);
		return ret;
	}
	ret=digest(parcel.crypto, calctag, buf, len);
	if (ret) {
		pk_log(LOG_ERROR, "Couldn't calculate chunk hash");
		return ret;
	}
	if (memcmp(tag, calctag, parcel.hashlen)) {
		pk_log(LOG_ERROR, "Invalid tag for retrieved chunk %u", chunk);
		log_tag_mismatch(tag, calctag, parcel.hashlen);
		return PK_TAGFAIL;
	}
	hoard_put_chunk(tag, buf, len);
	*length=len;
	return PK_SUCCESS;
}
