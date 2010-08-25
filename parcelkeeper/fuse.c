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

#include <sys/utsname.h>
#include <string.h>
#include <inttypes.h>
#include <signal.h>
#include <errno.h>
#define FUSE_USE_VERSION 26
#include <fuse.h>
#include "defs.h"

struct pk_fuse {
	/* Fileystem handles */
	struct fuse *fuse;
	struct fuse_chan *chan;

	/* Open statistics files */
	GHashTable *stat_buffers;

	/* Leave the local cache file dirty flag set at shutdown to force
	   the cache to be checked */
	gboolean leave_dirty;
};

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

enum fuse_directory {
	DIR_ROOT,
	DIR_STATS,
};

static const int ignored_signals[]={SIGINT, SIGTERM, SIGUSR1, SIGUSR2,
			SIGTSTP, SIGTTOU, 0};
static const int caught_signals[]={SIGQUIT, SIGHUP, 0};

static void fuse_signal_handler(int sig)
{
	sigstate.signal = sig;
	if (sigstate.fuse != NULL)
		fuse_exit(sigstate.fuse->fuse);
}

typedef gboolean (stat_handler)(void *data, const char *name);

static gchar *_statistic(struct pk_state *state, stat_handler *handle,
			void *data)
{
	if (handle(data, "bytes_read"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.bytes_read);
	if (handle(data, "bytes_written"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.bytes_written);
	if (handle(data, "chunk_reads"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.chunk_reads);
	if (handle(data, "chunk_writes"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.chunk_writes);
	if (handle(data, "chunk_errors"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.chunk_errors);
	if (handle(data, "cache_hits"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.cache_hits);
	if (handle(data, "cache_misses"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.cache_misses);
	if (handle(data, "compression_ratio_pct")) {
		if (state->stats.chunk_writes == 0)
			return g_strdup("n/a\n");
		return g_strdup_printf("%.1f\n", 100.0 *
					state->stats.data_bytes_written /
					(state->stats.chunk_writes *
					state->parcel->chunksize));
	}
	if (handle(data, "whole_chunk_updates"))
		return g_strdup_printf("%"PRIu64"\n",
					state->stats.whole_chunk_updates);
	return NULL;
}

static gboolean _stat_enumerate(void *data, const char *name)
{
	g_ptr_array_add(data, g_strdup(name));
	return FALSE;
}

static gchar **list_stats(struct pk_state *state)
{
	GPtrArray *arr;

	arr = g_ptr_array_new();
	_statistic(state, _stat_enumerate, arr);
	g_ptr_array_add(arr, NULL);
	return (gchar **) g_ptr_array_free(arr, FALSE);
}

static gboolean _stat_compare(void *data, const char *name)
{
	return g_str_equal(data, name);
}

static gchar *get_stat(struct pk_state *state, const char *name)
{
	return _statistic(state, _stat_compare, (char *) name);
}

static int do_getattr(const char *path, struct stat *st)
{
	struct pk_state *state = fuse_get_context()->private_data;
	gchar *value;

	st->st_nlink = 1;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_size = 0;
	st->st_atime = st->st_mtime = st->st_ctime = time(NULL);

	if (g_str_equal(path, "/")) {
		st->st_nlink = 3;
		st->st_mode = S_IFDIR | 0500;
	} else if (g_str_equal(path, "/stats")) {
		st->st_nlink = 2;
		st->st_mode = S_IFDIR | 0500;
	} else if (g_str_equal(path, "/image")) {
		st->st_mode = S_IFREG | 0600;
		st->st_size = ((off_t) state->parcel->chunks) *
					state->parcel->chunksize;
	} else if (g_str_has_prefix(path, "/stats/")) {
		/* Statistics file */
		value = get_stat(state, path + strlen("/stats/"));
		if (value == NULL)
			return -ENOENT;
		st->st_mode = S_IFREG | 0400;
		st->st_size = strlen(value);
		g_free(value);
	} else {
		return -ENOENT;
	}
	st->st_blocks = (st->st_size + 511) / 512;
	return 0;
}

static int do_open(const char *path, struct fuse_file_info *fi)
{
	struct pk_state *state = fuse_get_context()->private_data;
	gchar *buf;

	if (g_str_has_prefix(path, "/stats/")) {
		/* Statistics file */
		buf = get_stat(state, path + strlen("/stats/"));
		if (buf == NULL)
			return -ENOENT;
		/* Find the next available file handle */
		for (fi->fh = 1; g_hash_table_lookup(
					state->fuse->stat_buffers,
					GINT_TO_POINTER(fi->fh)); fi->fh++);
		g_hash_table_insert(state->fuse->stat_buffers,
					GINT_TO_POINTER(fi->fh), buf);
	} else if (!g_str_equal(path, "/image")) {
		return -ENOENT;
	}
	return 0;
}

static int read_stat(struct pk_state *state, int fh, char *buf, off_t start,
			size_t count)
{
	gchar *src;
	int srclen;
	int len;

	src = g_hash_table_lookup(state->fuse->stat_buffers,
				GINT_TO_POINTER(fh));
	if (src == NULL)
		return -EBADF;
	srclen = strlen(src);
	len = MAX(0, MIN((int) count, srclen - start));
	memcpy(buf, src + start, len);
	return len;
}

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

static int read_image(struct pk_state *state, char *buf, off_t start,
			size_t count)
{
	struct io_cursor cur;
	char data[state->parcel->chunksize];

	pk_log(LOG_FUSE, "Read %"PRIu64" at %"PRIu64, count, start);
	for (io_start(state, &cur, start, count); io_chunk(&cur); ) {
		if (cache_get(state, cur.chunk, data)) {
			state->stats.chunk_errors++;
			state->fuse->leave_dirty = TRUE;
			return (int) cur.buf_offset ?: -EIO;
		}
		memcpy(buf + cur.buf_offset, data + cur.offset, cur.length);
		state->stats.bytes_read += cur.length;
	}
	return cur.buf_offset;
}

static int do_read(const char *path, char *buf, size_t count, off_t start,
			struct fuse_file_info *fi)
{
	struct pk_state *state = fuse_get_context()->private_data;

	if (fi->fh)
		return read_stat(state, fi->fh, buf, start, count);
	else
		return read_image(state, buf, start, count);
}

static int do_write(const char *path, const char *buf, size_t count,
			off_t start, struct fuse_file_info *fi)
{
	struct pk_state *state = fuse_get_context()->private_data;
	struct io_cursor cur;
	char data[state->parcel->chunksize];

	g_assert(fi->fh == 0);

	pk_log(LOG_FUSE, "Write %"PRIu64" at %"PRIu64, count, start);
	for (io_start(state, &cur, start, count); io_chunk(&cur); ) {
		if (cur.length < state->parcel->chunksize) {
			/* Read-modify-write */
			if (cache_get(state, cur.chunk, data))
				goto bad;
		} else {
			state->stats.whole_chunk_updates++;
		}
		memcpy(data + cur.offset, buf + cur.buf_offset, cur.length);
		if (cache_update(state, cur.chunk, data))
			goto bad;
		state->stats.bytes_written += cur.length;
	}
	return cur.buf_offset;

bad:
	state->stats.chunk_errors++;
	state->fuse->leave_dirty = TRUE;
	return (int) cur.buf_offset ?: -EIO;
}

static int do_statfs(const char *path, struct statvfs *st)
{
	struct pk_state *state = fuse_get_context()->private_data;

	st->f_bsize = state->parcel->chunksize;
	st->f_blocks = state->parcel->chunks;
	/* XXX number of unfetched chunks */
	st->f_bfree = st->f_bavail = 0;
	st->f_namemax = 256;
	return 0;
}

static int do_release(const char *path, struct fuse_file_info *fi)
{
	struct pk_state *state = fuse_get_context()->private_data;

	if (fi->fh)
		g_hash_table_remove(state->fuse->stat_buffers,
					GINT_TO_POINTER(fi->fh));
	return 0;
}

static int do_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	struct pk_state *state = fuse_get_context()->private_data;
	int ret;

	/* XXX flush dirty chunks */
	if (datasync)
		ret = fdatasync(state->cache_fd);
	else
		ret = fsync(state->cache_fd);
	if (ret)
		return -errno;
	return 0;
}

static int do_opendir(const char *path, struct fuse_file_info *fi)
{
	if (g_str_equal(path, "/"))
		fi->fh = DIR_ROOT;
	else if (g_str_equal(path, "/stats"))
		fi->fh = DIR_STATS;
	else
		return -ENOENT;
	return 0;
}

static int do_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t off, struct fuse_file_info *fi)
{
	struct pk_state *state = fuse_get_context()->private_data;
	gchar **stats;
	gchar **cur;

	switch (fi->fh) {
	case DIR_ROOT:
		filler(buf, "image", NULL, 0);
		filler(buf, "stats", NULL, 0);
		return 0;
	case DIR_STATS:
		for (cur = stats = list_stats(state); *cur != NULL; cur++)
			filler(buf, *cur, NULL, 0);
		g_strfreev(stats);
		return 0;
	default:
		return -EIO;
	}
}

static const struct fuse_operations pk_fuse_ops = {
	.getattr = do_getattr,
	.open = do_open,
	.read = do_read,
	.write = do_write,
	.statfs = do_statfs,
	.release = do_release,
	.fsync = do_fsync,
	.opendir = do_opendir,
	.readdir = do_readdir,
	.flag_nullpath_ok = 1,
};

pk_err_t fuse_init(struct pk_state *state)
{
	pk_err_t ret;
	struct utsname utsname;
	GPtrArray *argv;
	struct fuse_args args;

	/* Check for previous unclean shutdown of local cache */
	if (cache_test_flag(state, CA_F_DIRTY)) {
		pk_log(LOG_WARNING, "Local cache marked as dirty");
		pk_log(LOG_WARNING, "Will not run until the cache has been "
					"validated or discarded");
		return PK_BADFORMAT;
	}

	/* Log kernel version */
	if (uname(&utsname))
		pk_log(LOG_ERROR, "Can't get kernel version");
	else
		pk_log(LOG_INFO, "%s %s (%s) on %s", utsname.sysname,
					utsname.release, utsname.version,
					utsname.machine);

	/* Log FUSE version */
	pk_log(LOG_INFO, "FUSE version %d", fuse_version());

	/* Set up data structures */
	state->fuse = g_slice_new0(struct pk_fuse);
	state->fuse->stat_buffers = g_hash_table_new_full(g_direct_hash,
				g_direct_equal, NULL, g_free);

	/* Create mountpoint */
	if (!g_file_test(state->conf->mountpoint, G_FILE_TEST_IS_DIR)) {
		if (mkdir(state->conf->mountpoint, 0700)) {
			pk_log(LOG_ERROR, "Couldn't create %s directory",
						state->conf->mountpoint);
			ret = PK_CALLFAIL;
			goto bad_dealloc;
		}
	}

	/* Set the dirty flag on the local cache.  If the damaged flag is
	   already set, there's no point in forcing another check if we
	   crash. */
	if (!cache_test_flag(state, CA_F_DAMAGED)) {
		ret = cache_set_flag(state, CA_F_DIRTY);
		if (ret)
			goto bad_rmdir;
	}

	/* Build FUSE command line */
	argv = g_ptr_array_new();
	g_ptr_array_add(argv, g_strdup("-odefault_permissions"));
	g_ptr_array_add(argv, g_strdup("-obig_writes"));
	g_ptr_array_add(argv, g_strdup_printf("-ofsname=openisr#%s",
				state->parcel->uuid));
	g_ptr_array_add(argv, g_strdup("-osubtype=openisr"));
	if (state->conf->flags & WANT_ALLOW_ROOT) {
		/* This option is needed for certain VMMs which run their
		   monitor process as root.  The "user_allow_other" option
		   must be specified in /etc/fuse.conf or fuse_mount()
		   will fail. */
		g_ptr_array_add(argv, g_strdup("-oallow_root"));
	}
	g_ptr_array_add(argv, NULL);
	args.argv = (gchar **) g_ptr_array_free(argv, FALSE);
	args.argc = g_strv_length(args.argv);
	args.allocated = 0;

	/* Initialize FUSE */
	state->fuse->chan = fuse_mount(state->conf->mountpoint, &args);
	if (state->fuse->chan == NULL) {
		pk_log(LOG_ERROR, "Couldn't mount FUSE filesystem");
		g_strfreev(args.argv);
		ret = PK_IOERR;
		goto bad_unflag;
	}
	state->fuse->fuse = fuse_new(state->fuse->chan, &args, &pk_fuse_ops,
				sizeof(pk_fuse_ops), state);
	g_strfreev(args.argv);
	if (state->fuse->fuse == NULL) {
		pk_log(LOG_ERROR, "Couldn't create FUSE filesystem");
		ret = PK_CALLFAIL;
		goto bad_unmount;
	}

	/* Register FUSE-specific signal handler */
	sigstate.fuse = state->fuse;
	ret = setup_signal_handlers(fuse_signal_handler, caught_signals,
				ignored_signals);
	if (ret)
		goto bad_destroy_fuse;
	/* If there's already a signal pending from the generic handlers,
	   make sure we respect it */
	if (pending_signal())
		fuse_exit(state->fuse->fuse);

	pk_log(LOG_INFO, "Initialized FUSE");
	return PK_SUCCESS;

bad_destroy_fuse:
	sigstate.fuse = NULL;
	fuse_destroy(state->fuse->fuse);
bad_unmount:
	fuse_unmount(state->conf->mountpoint, state->fuse->chan);
bad_unflag:
	cache_clear_flag(state, CA_F_DIRTY);
bad_rmdir:
	if (rmdir(state->conf->mountpoint))
		pk_log(LOG_ERROR, "Couldn't remove %s",
					state->conf->mountpoint);
bad_dealloc:
	g_hash_table_destroy(state->fuse->stat_buffers);
	g_slice_free(struct pk_fuse, state->fuse);
	return ret;
}

void fuse_run(struct pk_state *state)
{
	int sig;

	fuse_loop(state->fuse->fuse);
	sig = pending_signal();
	if (sig)
		pk_log(LOG_INFO, "Caught signal %d, shutting down FUSE "
					"immediately", sig);
	else
		pk_log(LOG_INFO, "Shutting down FUSE");
	/* Normally the filesystem will already have been unmounted.  Try
	   to make sure. */
	fuse_unmount(state->conf->mountpoint, state->fuse->chan);
	if (rmdir(state->conf->mountpoint)) {
		/* FUSE doesn't return an error code if umount fails, so
		   detect it here */
		pk_log(LOG_ERROR, "Couldn't unmount FUSE filesystem");
	}
}

void fuse_shutdown(struct pk_state *state)
{
	gchar **stats;
	gchar **cur;
	gchar *value;

	/* Log statistics */
	for (stats = cur = list_stats(state); *cur != NULL; cur++) {
		value = get_stat(state, *cur);
		g_strchomp(value);
		pk_log(LOG_STATS, "%s: %s", *cur, value);
		g_free(value);
	}
	g_strfreev(stats);

	if (!state->fuse->leave_dirty)
		cache_clear_flag(state, CA_F_DIRTY);
	fsync(state->cache_fd);

	sigstate.fuse = NULL;
	fuse_destroy(state->fuse->fuse);
	g_hash_table_destroy(state->fuse->stat_buffers);
	g_slice_free(struct pk_fuse, state->fuse);
}
