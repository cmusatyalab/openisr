/*
 * Parcelkeeper - support daemon for the OpenISR (R) system virtual disk
 *
 * Copyright (C) 2006-2008 Carnegie Mellon University
 *
 * This software is distributed under the terms of the Eclipse Public License,
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
 * ACCEPTANCE OF THIS AGREEMENT
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <linux/loop.h>
#include "nexus.h"
#include "defs.h"

static const int ignored_signals[]={SIGUSR1, SIGUSR2, SIGHUP, SIGTSTP, 0};
static const int caught_signals[]={SIGINT, SIGQUIT, SIGTERM, 0};

#define REQUESTS_PER_SYSCALL 64
#define MY_INTERFACE_VERSION 8
#define LOOP_UNREGISTER_TRIES 500
#if MY_INTERFACE_VERSION != NEXUS_INTERFACE_VERSION
#error This code uses a different interface version than the one defined in nexus.h
#endif

static void nexus_signal_handler(int sig)
{
	char c=sig;
	/* Race-free method of catching signals */
	write(state.signal_fds[1], &c, 1);
	/* The fd is set nonblocking, so if the pipe is full, the signal will
	   be lost */
}

static enum nexus_crypto crypto_to_nexus(enum cryptotype type)
{
	switch (type) {
	case CRY_AES_SHA1:
		return NEXUS_CRYPTO_AES_SHA1;
	case CRY_BLOWFISH_SHA1:
		return NEXUS_CRYPTO_BLOWFISH_SHA1;
	default:
		return NEXUS_NR_CRYPTO;
	}
}

static enum nexus_compress compress_to_nexus(enum compresstype type)
{
	switch (type) {
	case COMP_NONE:
		return NEXUS_COMPRESS_NONE;
	case COMP_ZLIB:
		return NEXUS_COMPRESS_ZLIB;
	case COMP_LZF:
		return NEXUS_COMPRESS_LZF;
	default:
		return NEXUS_NR_COMPRESS;
	}
}

static enum compresstype nexus_to_compress(enum nexus_compress type)
{
	switch (type) {
	case NEXUS_COMPRESS_NONE:
		return COMP_NONE;
	case NEXUS_COMPRESS_ZLIB:
		return COMP_ZLIB;
	case NEXUS_COMPRESS_LZF:
		return COMP_LZF;
	default:
		return COMP_UNKNOWN;
	}
}

static pk_err_t loop_bind(void) {
	struct loop_info64 info;
	int i;
	int fd;

	for (i=0 ;; i++) {
		if (asprintf(&state.loopdev_name, "/dev/loop%d", i) == -1) {
			pk_log(LOG_ERROR, "malloc failure opening loop device");
			continue;
		}
		fd=open(state.loopdev_name, O_RDWR|O_SYNC);
		if (fd == -1) {
			pk_log(LOG_ERROR, "Couldn't open loop device");
			return PK_IOERR;
		}
		if (ioctl(fd, LOOP_GET_STATUS64, &info) && errno == ENXIO) {
			/* XXX race condition */
			if (ioctl(fd, LOOP_SET_FD, state.cache_fd)) {
				pk_log(LOG_ERROR, "Couldn't bind to loop "
							"device");
				return PK_IOERR;
			}
			/* This is required in order to properly configure the
			   (null) transfer function, even though it
			   shouldn't be */
			if (ioctl(fd, LOOP_GET_STATUS64, &info)) {
				pk_log(LOG_ERROR, "Couldn't get status of "
							"loop device");
				ioctl(fd, LOOP_CLR_FD, 0);
				return PK_IOERR;
			}
			snprintf((char*)info.lo_file_name, LO_NAME_SIZE, "%s",
						config.cache_file);
			if (ioctl(fd, LOOP_SET_STATUS64, &info)) {
				pk_log(LOG_ERROR, "Couldn't configure "
							"loop device");
				ioctl(fd, LOOP_CLR_FD, 0);
				return PK_IOERR;
			}
			break;
		}
		close(fd);
		free(state.loopdev_name);
	}
	state.loopdev_fd=fd;
	pk_log(LOG_INFO, "Bound to loop device %s", state.loopdev_name);
	return PK_SUCCESS;
}

pk_err_t nexus_init(void)
{
	struct nexus_setup setup;
	pk_err_t ret;
	unsigned u;
	char revision[64];
	char protocol[8];
	unsigned protocol_i;
	struct utsname utsname;

	/* Check for previous unclean shutdown of local cache */
	if (cache_test_flag(CA_F_DIRTY)) {
		pk_log(LOG_WARNING, "Local cache marked as dirty");
		pk_log(LOG_WARNING, "Will not run until the cache has been "
					"validated or discarded");
		return PK_BADFORMAT;
	}

	/* Check Nexus version */
	if (!is_dir("/sys/class/openisr")) {
		pk_log(LOG_ERROR, "kernel module not loaded");
		return PK_NOTFOUND;
	}
	if (read_sysfs_file("/sys/class/openisr/version", protocol,
				sizeof(protocol))) {
		pk_log(LOG_ERROR, "can't get Nexus protocol version");
		return PK_PROTOFAIL;
	}
	if (sscanf(protocol, "%u", &protocol_i) != 1) {
		pk_log(LOG_ERROR, "can't parse protocol version");
		return PK_PROTOFAIL;
	}
	if (protocol_i != MY_INTERFACE_VERSION) {
		pk_log(LOG_ERROR, "protocol mismatch: expected version "
					"%u, got version %u",
					MY_INTERFACE_VERSION, protocol_i);
		return PK_PROTOFAIL;
	}
	if (read_sysfs_file("/sys/class/openisr/revision", revision,
				sizeof(revision))) {
		pk_log(LOG_ERROR, "can't get Nexus revision");
		return PK_PROTOFAIL;
	}
	pk_log(LOG_INFO, "Driver protocol %u, revision %s", protocol_i,
				revision);

	/* Log kernel version */
	if (uname(&utsname))
		pk_log(LOG_ERROR, "Can't get kernel version");
	else
		pk_log(LOG_INFO, "%s %s (%s) on %s", utsname.sysname,
					utsname.release, utsname.version,
					utsname.machine);

	/* Create signal-passing pipe */
	if (pipe(state.signal_fds)) {
		pk_log(LOG_ERROR, "couldn't create pipe");
		return PK_CALLFAIL;
	}
	/* Set it nonblocking */
	if (fcntl(state.signal_fds[0], F_SETFL, O_NONBLOCK) ||
				fcntl(state.signal_fds[1], F_SETFL,
				O_NONBLOCK)) {
		pk_log(LOG_ERROR, "couldn't set pipe nonblocking");
		return PK_CALLFAIL;
	}
	/* Register pipe-based signal handler */
	ret=setup_signal_handlers(nexus_signal_handler, caught_signals,
				ignored_signals);
	if (ret)
		return ret;
	if (pending_signal()) {
		/* We already got a signal under the generic signal-handling
		   system.  Exit. */
		return PK_INTERRUPT;
	}

	/* Open the device.  O_NONBLOCK ensures we never block on a read(), but
	   write() may still block */
	state.chardev_fd = open("/dev/openisrctl", O_RDWR|O_NONBLOCK);
	if (state.chardev_fd < 0) {
		if (errno == ENOENT) {
			pk_log(LOG_ERROR, "/dev/openisrctl does not exist");
			return PK_NOTFOUND;
		} else {
			pk_log(LOG_ERROR, "unable to open /dev/openisrctl");
			return PK_IOERR;
		}
	}

	/* Set the dirty flag on the local cache.  If the damaged flag is
	   already set, there's no point in forcing another check if we
	   crash. */
	if (!cache_test_flag(CA_F_DAMAGED)) {
		ret=cache_set_flag(CA_F_DIRTY);
		if (ret)
			return ret;
	}

	/* Bind the image file to a loop device */
	ret=loop_bind();
	if (ret) {
		cache_clear_flag(CA_F_DIRTY);
		return ret;
	}

	/* Register ourselves with the device */
	memset(&setup, 0, sizeof(setup));
	snprintf((char*)setup.ident, NEXUS_MAX_DEVICE_LEN, "%s",
				parcel.uuid);
	snprintf((char*)setup.chunk_device, NEXUS_MAX_DEVICE_LEN, "%s",
				state.loopdev_name);
	setup.offset=state.offset >> 9;
	setup.chunksize=parcel.chunksize;
	/* Always use a 16 MB cache */
	setup.cachesize=(16 << 20) / parcel.chunksize;
	setup.crypto=crypto_to_nexus(parcel.crypto);
	setup.compress_default=compress_to_nexus(config.compress);
	for (u=0; u<8*sizeof(parcel.required_compress); u++)
		if (parcel.required_compress & (1 << u))
			setup.compress_required |= 1 << compress_to_nexus(u);
	if (setup.crypto == NEXUS_NR_CRYPTO ||
				setup.compress_default == NEXUS_NR_COMPRESS ||
				(setup.compress_required &
				(1 << NEXUS_NR_COMPRESS))) {
		/* Shouldn't happen, so we don't need a very good error
		   message */
		pk_log(LOG_ERROR, "unknown crypto or compression algorithm");
		ioctl(state.loopdev_fd, LOOP_CLR_FD, 0);
		cache_clear_flag(CA_F_DIRTY);
		return PK_IOERR;
	}

	if (ioctl(state.chardev_fd, NEXUS_IOC_REGISTER, &setup)) {
		pk_log(LOG_ERROR, "unable to register with Nexus: %s",
					strerror(errno));
		ioctl(state.loopdev_fd, LOOP_CLR_FD, 0);
		cache_clear_flag(CA_F_DIRTY);
		return PK_IOERR;
	}
	state.bdev_index=setup.index;
	pk_log(LOG_INFO, "Registered with Nexus");
	return PK_SUCCESS;
}

static void log_sysfs_value(const char *attr)
{
	char *fname;
	char buf[32];

	if (asprintf(&fname, "/sys/class/openisr/openisr%c/%s",
				'a' + state.bdev_index, attr) == -1) {
		pk_log(LOG_ERROR, "malloc failure");
		return;
	}
	if (read_sysfs_file(fname, buf, sizeof(buf))) {
		pk_log(LOG_STATS, "%s: unknown", attr);
	} else {
		pk_log(LOG_STATS, "%s: %s", attr, buf);
	}
	free(fname);
}

void nexus_shutdown(void)
{
	int i;

	log_sysfs_value("cache_hits");
	log_sysfs_value("cache_misses");
	log_sysfs_value("cache_alloc_failures");
	log_sysfs_value("chunk_reads");
	log_sysfs_value("chunk_writes");
	log_sysfs_value("chunk_errors");
	log_sysfs_value("chunk_encrypted_discards");
	log_sysfs_value("whole_chunk_updates");
	log_sysfs_value("sectors_read");
	log_sysfs_value("sectors_written");
	log_sysfs_value("compression_ratio_pct");
	pk_log(LOG_STATS, "messages_received: %u", state.request_count);

	close(state.chardev_fd);

	/* XXX Sometimes the loop device doesn't unregister the first time.
	   For now, we retry (a lot) to try to ensure that the user isn't left
	   with a stale binding.  However, we still print the warning as a
	   debug aid. */
	for (i=0; i<LOOP_UNREGISTER_TRIES; i++) {
		if (!ioctl(state.loopdev_fd, LOOP_CLR_FD, 0)) {
			if (i > 0)
				pk_log(LOG_ERROR, "Had to try %d times to "
							"unbind loop device",
							i + 1);
			break;
		}
		usleep(10000);
	}
	if (i == LOOP_UNREGISTER_TRIES)
		pk_log(LOG_ERROR, "Couldn't unbind loop device");

	close(state.loopdev_fd);
	/* We don't trust the loop driver */
	sync();
	sync();
	sync();
	if (!state.leave_dirty)
		cache_clear_flag(CA_F_DIRTY);
}

static int request_is_valid(const struct nexus_message *req)
{
	if (req->chunk >= parcel.chunks) {
		pk_log(LOG_ERROR, "Invalid chunk number %llu received "
					"from Nexus", req->chunk);
		return 0;
	}

	switch (req->type) {
	case NEXUS_MSGTYPE_GET_META:
	case NEXUS_MSGTYPE_CHUNK_ERR:
		break;
	case NEXUS_MSGTYPE_UPDATE_META:
		if (req->length > parcel.chunksize) {
			pk_log(LOG_ERROR, "Invalid length %u received from "
						"Nexus for chunk %llu",
						req->length, req->chunk);
			return 0;
		}
		break;
	default:
		pk_log(LOG_ERROR, "Invalid msgtype %u received from Nexus",
					req->type);
		return 0;
	}
	return 1;
}

static void chunk_error(const struct nexus_message *req)
{
	char *expected;
	char *found;
	const char *rw;
	enum nexus_chunk_err err;

	rw = (req->err & NEXUS_ERR_IS_WRITE) ? "writing" : "reading";
	err = req->err & ~NEXUS_ERR_IS_WRITE;
	switch (err) {
	case NEXUS_ERR_IO:
		pk_log(LOG_WARNING, "Nexus: I/O error %s chunk %llu", rw,
					req->chunk);
		break;
	case NEXUS_ERR_TAG:
		expected=format_tag(req->expected, parcel.hashlen);
		found=format_tag(req->found, parcel.hashlen);
		pk_log(LOG_WARNING, "Nexus: Tag check error %s chunk %llu: "
					"expected %s, found %s", rw,
					req->chunk, expected, found);
		free(expected);
		free(found);
		break;
	case NEXUS_ERR_KEY:
		/* Don't log keys to the session log! */
		pk_log(LOG_WARNING, "Nexus: Key check error %s chunk %llu",
					rw, req->chunk);
		break;
	case NEXUS_ERR_HASH:
		pk_log(LOG_WARNING, "Nexus: Hashing failure %s chunk %llu",
					rw, req->chunk);
		break;
	case NEXUS_ERR_CRYPT:
		pk_log(LOG_WARNING, "Nexus: Crypto failure %s chunk %llu",
					rw, req->chunk);
		break;
	case NEXUS_ERR_COMPRESS:
		pk_log(LOG_WARNING, "Nexus: Compression failure %s chunk %llu",
					rw, req->chunk);
		break;
	default:
		pk_log(LOG_ERROR, "Unknown Nexus error (%u) %s chunk %llu",
					err, rw, req->chunk);
		break;
	}
	/* Leave the dirty bit set at shutdown, to force the local cache to
	   be checked */
	state.leave_dirty=1;
}

/* Returns true if @reply is valid */
static int process_message(const struct nexus_message *request,
			struct nexus_message *reply)
{
	pk_err_t err;
	enum compresstype compress;

	if (!request_is_valid(request)) {
		if (request->type == NEXUS_MSGTYPE_GET_META) {
			reply->type=NEXUS_MSGTYPE_META_HARDERR;
			reply->chunk=request->chunk;
			return 1;
		}
		return 0;
	}

	switch (request->type) {
	case NEXUS_MSGTYPE_GET_META:
		reply->chunk=request->chunk;
		err=cache_get(request->chunk, reply->tag, reply->key,
					&compress, &reply->length);
		reply->compression=compress_to_nexus(compress);
		if (err || reply->compression == NEXUS_NR_COMPRESS)
			reply->type=NEXUS_MSGTYPE_META_HARDERR;
		else
			reply->type=NEXUS_MSGTYPE_SET_META;
		return 1;
	case NEXUS_MSGTYPE_UPDATE_META:
		/* XXX ignores errors */
		cache_update(request->chunk, request->tag, request->key,
					nexus_to_compress(request->compression),
					request->length);
		break;
	case NEXUS_MSGTYPE_CHUNK_ERR:
		chunk_error(request);
		break;
	}
	return 0;
}

static void process_batch(void)
{
	struct nexus_message requests[REQUESTS_PER_SYSCALL];
	struct nexus_message replies[REQUESTS_PER_SYSCALL];
	int i;
	int in_count;
	int out_count=0;

	in_count=read(state.chardev_fd, &requests, sizeof(requests));
	if (in_count % sizeof(requests[0]))
		pk_log(LOG_ERROR, "Short read from Nexus: %d", in_count);
	in_count /= sizeof(requests[0]);

	for (i=0; i<in_count; i++) {
		if (process_message(&requests[i], &replies[out_count]))
			out_count++;
		state.request_count++;
	}

	if (out_count == 0)
		return;
	out_count *= sizeof(replies[0]);
	if (write(state.chardev_fd, replies, out_count) != out_count) {
		/* XXX */
		pk_log(LOG_ERROR, "Short write to Nexus");
	}
}

void nexus_run(void)
{
	fd_set readfds;
	fd_set exceptfds;
	int fdcount=max(state.signal_fds[0], state.chardev_fd) + 1;
	int shutdown_pending=0;
	char signal;

	/* Enter processing loop */
	FD_ZERO(&readfds);
	FD_ZERO(&exceptfds);
	for (;;) {
		FD_SET(state.chardev_fd, &readfds);
		FD_SET(state.signal_fds[0], &readfds);
		if (shutdown_pending)
			FD_SET(state.chardev_fd, &exceptfds);
		if (select(fdcount, &readfds, NULL, &exceptfds, NULL) == -1) {
			/* select(2) reports that the fdsets are now
			   undefined, so we start over */
			FD_ZERO(&readfds);
			FD_ZERO(&exceptfds);
			if (errno == EINTR) {
				/* Got a signal.  The next time through the
				   loop the pipe will be readable and we can
				   find out what signal it was */
				continue;
			} else {
				pk_log(LOG_ERROR, "select() failed: %s",
							strerror(errno));
				/* XXX now what? */
			}
		}

		/* Process pending signals */
		if (FD_ISSET(state.signal_fds[0], &readfds)) {
			while (read(state.signal_fds[0], &signal,
						sizeof(signal)) > 0) {
				switch (signal) {
				case SIGQUIT:
					pk_log(LOG_INFO, "Caught SIGQUIT;"
						" shutting down immediately");
					pk_log(LOG_INFO, "Loop "
						"unregistration may fail");
					return;
				default:
					pk_log(LOG_INFO, "Caught signal; "
						"shutdown pending");
					shutdown_pending=1;
				}
			}
		}

		/* If we need to shut down and we think the block device has
		   no users, try to unregister */
		if (shutdown_pending && FD_ISSET(state.chardev_fd,
					&exceptfds)) {
			if (!ioctl(state.chardev_fd, NEXUS_IOC_UNREGISTER))
				return;
		}

		/* Process pending requests */
		if (FD_ISSET(state.chardev_fd, &readfds))
			process_batch();
	}
}
