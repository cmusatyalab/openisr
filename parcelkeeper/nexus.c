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

static const int ignored_signals[]={SIGUSR1, SIGUSR2, SIGHUP, SIGTSTP, 0};
static const int caught_signals[]={SIGINT, SIGQUIT, SIGTERM, 0};

#define REQUESTS_PER_SYSCALL 64
#define MY_INTERFACE_VERSION 5
#if MY_INTERFACE_VERSION != NEXUS_INTERFACE_VERSION
#error This code uses a different interface version than the one defined in nexus.h
#endif

static void signal_handler(int sig)
{
	char c=sig;
	/* Race-free method of catching signals */
	write(state.signal_fds[1], &c, 1);
	/* The fd is set nonblocking, so if the pipe is full, the signal will
	   be lost */
}

static pk_err_t loop_bind(void) {
	struct loop_info64 info;
	int i;
	int fd;

	for (i=0 ;; i++) {
		snprintf(state.loopdev_name, sizeof(state.loopdev_name),
					"/dev/loop%d", i);
		fd=open(state.loopdev_name, O_RDWR|O_SYNC);
		if (fd == -1) {
			pk_log(LOG_ERRORS, "Couldn't open loop device");
			return PK_IOERR;
		}
		if (ioctl(fd, LOOP_GET_STATUS64, &info) && errno == ENXIO) {
			/* XXX race condition */
			if (ioctl(fd, LOOP_SET_FD, state.cachefile_fd)) {
				pk_log(LOG_ERRORS, "Couldn't bind to loop "
							"device");
				return PK_IOERR;
			}
			/* This is required in order to properly configure the
			   (null) transfer function, even though it
			   shouldn't be */
			if (ioctl(fd, LOOP_GET_STATUS64, &info)) {
				pk_log(LOG_ERRORS, "Couldn't get status of "
							"loop device");
				ioctl(fd, LOOP_CLR_FD, 0);
				return PK_IOERR;
			}
			snprintf((char*)info.lo_file_name, LO_NAME_SIZE, "%s",
						state.image_name);
			if (ioctl(fd, LOOP_SET_STATUS64, &info)) {
				pk_log(LOG_ERRORS, "Couldn't configure "
							"loop device");
				ioctl(fd, LOOP_CLR_FD, 0);
				return PK_IOERR;
			}
			break;
		}
		close(fd);
	}
	state.loopdev_fd=fd;
	pk_log(LOG_BASIC, "Bound to loop device %s", state.loopdev_name);
	return PK_SUCCESS;
}

pk_err_t nexus_init(void)
{
	struct nexus_setup setup;
	pk_err_t ret;
	int i;
	char revision[64];
	char protocol[8];
	unsigned protocol_i;
	struct utsname utsname;
	FILE *fp;

	/* Check Nexus version */
	if (!is_dir("/sys/class/openisr")) {
		pk_log(LOG_ERRORS, "kernel module not loaded");
		return PK_NOTFOUND;
	}
	if (read_sysfs_file("/sys/class/openisr/version", protocol,
				sizeof(protocol))) {
		pk_log(LOG_ERRORS, "can't get Nexus protocol version");
		return PK_PROTOFAIL;
	}
	if (sscanf(protocol, "%u", &protocol_i) != 1) {
		pk_log(LOG_ERRORS, "can't parse protocol version");
		return PK_PROTOFAIL;
	}
	if (protocol_i != MY_INTERFACE_VERSION) {
		pk_log(LOG_ERRORS, "protocol mismatch: expected version "
					"%u, got version %u",
					MY_INTERFACE_VERSION, protocol_i);
		return PK_PROTOFAIL;
	}
	if (read_sysfs_file("/sys/class/openisr/revision", revision,
				sizeof(revision))) {
		pk_log(LOG_ERRORS, "can't get Nexus revision");
		return PK_PROTOFAIL;
	}
	pk_log(LOG_BASIC,"Driver protocol %u, revision %s", protocol_i,
				revision);

	/* Log kernel version */
	if (uname(&utsname))
		pk_log(LOG_ERRORS, "Can't get kernel version");
	else
		pk_log(LOG_BASIC, "%s %s (%s) on %s", utsname.sysname,
					utsname.release, utsname.version,
					utsname.machine);

	/* Create signal-passing pipe */
	if (pipe(state.signal_fds)) {
		pk_log(LOG_ERRORS, "couldn't create pipe");
		return PK_CALLFAIL;
	}
	/* Set it nonblocking */
	if (fcntl(state.signal_fds[0], F_SETFL, O_NONBLOCK) ||
				fcntl(state.signal_fds[1], F_SETFL,
				O_NONBLOCK)) {
		pk_log(LOG_ERRORS, "couldn't set pipe nonblocking");
		return PK_CALLFAIL;
	}
	/* Register signal handler */
	for (i=0; caught_signals[i] != 0; i++) {
		if (set_signal_handler(caught_signals[i], signal_handler)) {
			pk_log(LOG_ERRORS, "unable to register default "
						"signal handler for signal %d",
						caught_signals[i]);
			return PK_CALLFAIL;
		}
	}
	/* Ignore signals that don't make sense for us */
	for (i=0; ignored_signals[i] != 0; i++) {
		if (set_signal_handler(ignored_signals[i], SIG_IGN)) {
			pk_log(LOG_ERRORS, "unable to ignore signal %d",
						ignored_signals[i]);
			return PK_CALLFAIL;
		}
	}

	/* Open the device.  O_NONBLOCK ensures we never block on a read(), but
	   write() may still block */
	state.chardev_fd = open("/dev/openisrctl", O_RDWR|O_NONBLOCK);
	if (state.chardev_fd < 0) {
		if (errno == ENOENT) {
			pk_log(LOG_ERRORS, "/dev/openisrctl does not exist");
			return PK_NOTFOUND;
		} else {
			pk_log(LOG_ERRORS, "unable to open /dev/openisrctl");
			return PK_IOERR;
		}
	}

	/* Open the regular file that will contain the name of the device node
	   we receive */
	fp=fopen(config.devfile, "w");
	if (fp == NULL) {
		pk_log(LOG_ERRORS, "couldn't open %s for writing",
					config.devfile);
		return PK_IOERR;
	}

	/* Bind the image file to a loop device */
	ret=loop_bind();
	if (ret) {
		fclose(fp);
		unlink(state.devfile_name);
		return ret;
	}

	/* Register ourselves with the device */
	memset(&setup, 0, sizeof(setup));
	snprintf((char*)setup.chunk_device, NEXUS_MAX_DEVICE_LEN, "%s",
				state.loopdev_name);
	setup.offset=state.offset_bytes / SECTOR_SIZE;
	setup.chunksize=state.chunksize_bytes;
	setup.cachesize=128;
	setup.crypto=NEXUS_CRYPTO_BLOWFISH_SHA1_COMPAT;
	setup.compress_default=NEXUS_COMPRESS_ZLIB;
	setup.compress_required=(1<<NEXUS_COMPRESS_NONE)|
				(1<<NEXUS_COMPRESS_ZLIB);

	if (ioctl(state.chardev_fd, NEXUS_IOC_REGISTER, &setup)) {
		pk_log(LOG_ERRORS, "unable to register with Nexus: %s",
					strerror(errno));
		ioctl(state.loopdev_fd, LOOP_CLR_FD, 0);
		fclose(fp);
		unlink(state.devfile_name);
		return PK_IOERR;
	}
	fprintf(fp, "/dev/openisr%c\n", 'a' + setup.index);
	fclose(fp);
	state.bdev_index=setup.index;
	pk_log(LOG_BASIC, "Registered with Nexus");
	return PK_SUCCESS;
}

static void log_sysfs_value(char *attr)
{
	char fname[MAX_PATH_LENGTH];
	char buf[32];

	snprintf(fname, sizeof(fname), "/sys/class/openisr/openisr%c/%s",
				'a' + state.bdev_index, attr);
	if (read_sysfs_file(fname, buf, sizeof(buf))) {
		pk_log(LOG_STATS, "%s:unknown", attr);
	} else {
		pk_log(LOG_STATS, "%s:%s", attr, buf);
	}
}

void nexus_shutdown(void)
{
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

	close(state.chardev_fd);
	unlink(config.devfile);
	if (ioctl(state.loopdev_fd, LOOP_CLR_FD, 0))
		pk_log(LOG_ERRORS, "Couldn't unbind loop device");
	close(state.loopdev_fd);
	/* We don't trust the loop driver */
	sync();
	sync();
	sync();
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
		pk_log(LOG_ERRORS, "Short read from Nexus: %d", in_count);
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
		pk_log(LOG_ERRORS, "Short write to Nexus");
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
				pk_log(LOG_ERRORS, "select() failed: %s",
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
					pk_log(LOG_BASIC, "Caught SIGQUIT;"
						" shutting down immediately");
					pk_log(LOG_BASIC, "Loop "
						"unregistration may fail");
					return;
				default:
					pk_log(LOG_BASIC, "Caught signal; "
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
