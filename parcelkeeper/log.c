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
	char fmt[25];

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	snprintf(fmt, sizeof(fmt), "%%a %%b %%d %%H:%%M:%%S.%.3u %%Y",
				(unsigned)(tv.tv_usec / 1000));
	buf[0]=0;
	strftime(buf, buflen, fmt, &tm);
}

void pk_log(enum pk_log_type type, char *fmt, ...)
{
	va_list ap;
	char buf[50];

	curtime(buf, sizeof(buf));
	if (state.log_fp != NULL && ((1 << type) & config.log_file_mask)) {
		va_start(ap, fmt);
		fprintf(state.log_fp, "%s %s", buf, config.log_info_str);
		vfprintf(state.log_fp, fmt, ap);
		fprintf(state.log_fp, "\n");
		va_end(ap);
	}

	if ((1 << type) & config.log_stderr_mask) {
		va_start(ap, fmt);
		fprintf(stderr, "%s %s", buf, config.log_info_str);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		va_end(ap);
	}
}

void log_start(void)
{
	/* stderr is unbuffered by default */
	setlinebuf(stderr);
	if (config.log_file != NULL && config.log_file_mask) {
		state.log_fp=fopen(config.log_file, "a");
		if (state.log_fp != NULL)
			setlinebuf(state.log_fp);
		else
			pk_log(LOG_ERROR, "Couldn't open log file %s",
						config.log_file);
	}
}

void log_shutdown(void)
{
	if (state.log_fp != NULL) {
		fclose(state.log_fp);
		state.log_fp=NULL;
	}
}
