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

#include <stdio.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include "defs.h"

static void curtime(char *buf, unsigned buflen)
{
	struct timeval tv;
	struct tm tm;
	char fmt[22];

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	snprintf(fmt, sizeof(fmt), "%%b %%d %%Y %%H:%%M:%%S.%.3u",
				(unsigned)(tv.tv_usec / 1000));
	buf[0]=0;
	strftime(buf, buflen, fmt, &tm);
}

void _pk_log(enum pk_log_type type, char *fmt, const char *func, ...)
{
	va_list ap;
	char buf[50];

	if (state.log_fp != NULL && ((1 << type) & config.log_file_mask)) {
		curtime(buf, sizeof(buf));
		/* Ignore errors; it's better to write the log entry unlocked
		   than to drop it on the floor */
		get_file_lock(fileno(state.log_fp),
					FILE_LOCK_WRITE | FILE_LOCK_WAIT);
		fseek(state.log_fp, 0, SEEK_END);
		va_start(ap, func);
		fprintf(state.log_fp, "%s %d ", buf, state.pk_pid);
		if (type == LOG_ERROR)
			fprintf(state.log_fp, "%s(): ", func);
		vfprintf(state.log_fp, fmt, ap);
		fprintf(state.log_fp, "\n");
		va_end(ap);
		fflush(state.log_fp);
		put_file_lock(fileno(state.log_fp));
	}

	if ((1 << type) & config.log_stderr_mask) {
		va_start(ap, func);
		if (type == LOG_ERROR)
			fprintf(stderr, "%s(): ", func);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		va_end(ap);
	}
}

void log_start(void)
{
	state.pk_pid=getpid();
	/* stderr is unbuffered by default */
	setlinebuf(stderr);
	if (config.log_file != NULL && config.log_file_mask) {
		state.log_fp=fopen(config.log_file, "a");
		if (state.log_fp == NULL)
			pk_log(LOG_ERROR, "Couldn't open log file %s",
						config.log_file);
	}
	pk_log(LOG_INFO, "Parcelkeeper starting in %s mode", config.modename);
}

void log_shutdown(void)
{
	pk_log(LOG_INFO, "Parcelkeeper shutting down");
	if (state.log_fp != NULL) {
		fclose(state.log_fp);
		state.log_fp=NULL;
	}
}
