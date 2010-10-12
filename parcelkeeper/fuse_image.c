/*
 * Parcelkeeper - support daemon for the OpenISR (R) system virtual disk
 *
 * Copyright (C) 2006-2010 Carnegie Mellon University
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
#include <inttypes.h>
#include <errno.h>
#include "defs.h"
#include "fuse_defs.h"

struct io_cursor {
	/* Public fields; do not modify */
	unsigned chunk;
	unsigned offset;
	unsigned length;
	unsigned buf_offset;

	/* Private fields */
	struct pk_state *state;
	off_t start;
	size_t count;
};

/* The cursor is assumed to be allocated on the stack; this just fills
   it in. */
static void io_start(struct pk_state *state, struct io_cursor *cur,
			off_t start, size_t count)
{
	memset(cur, 0, sizeof(*cur));
	cur->state = state;
	cur->start = start;
	cur->count = count;
}

/* Populate the public fields of the cursor with information on the next
   chunk in the I/O, starting from the first.  Returns TRUE if we produced
   a valid chunk, FALSE if done with this I/O. */
static gboolean io_chunk(struct io_cursor *cur)
{
	cur->buf_offset += cur->length;
	if (cur->buf_offset >= cur->count)
		return FALSE;  /* Done */
	cur->chunk = (cur->start + cur->buf_offset) /
				cur->state->parcel->chunksize;
	if (cur->chunk >= cur->state->parcel->chunks)
		return FALSE;  /* End of disk */
	cur->offset = cur->start + cur->buf_offset -
				(cur->chunk * cur->state->parcel->chunksize);
	cur->length = MIN(cur->state->parcel->chunksize - cur->offset,
				cur->count - cur->buf_offset);
	return TRUE;
}

int image_read(struct pk_state *state, char *buf, off_t start, size_t count)
{
	struct io_cursor cur;
	char data[state->parcel->chunksize];

	pk_log(LOG_FUSE, "Read %"PRIu64" at %"PRIu64, (uint64_t) count,
				(uint64_t) start);
	for (io_start(state, &cur, start, count); io_chunk(&cur); ) {
		if (cache_get(state, cur.chunk, data)) {
			stats_increment(state, chunk_errors, 1);
			state->fuse->leave_dirty = TRUE;
			return (int) cur.buf_offset ?: -EIO;
		}
		memcpy(buf + cur.buf_offset, data + cur.offset, cur.length);
		stats_increment(state, bytes_read, cur.length);
	}
	return cur.buf_offset;
}

int image_write(struct pk_state *state, const char *buf, off_t start,
			size_t count)
{
	struct io_cursor cur;
	char data[state->parcel->chunksize];

	pk_log(LOG_FUSE, "Write %"PRIu64" at %"PRIu64, (uint64_t) count,
				(uint64_t) start);
	for (io_start(state, &cur, start, count); io_chunk(&cur); ) {
		if (cur.length < state->parcel->chunksize) {
			/* Read-modify-write */
			if (cache_get(state, cur.chunk, data))
				goto bad;
		} else {
			stats_increment(state, whole_chunk_updates, 1);
		}
		memcpy(data + cur.offset, buf + cur.buf_offset, cur.length);
		if (cache_update(state, cur.chunk, data))
			goto bad;
		stats_increment(state, bytes_written, cur.length);
	}
	return cur.buf_offset;

bad:
	stats_increment(state, chunk_errors, 1);
	state->fuse->leave_dirty = TRUE;
	return (int) cur.buf_offset ?: -EIO;
}
