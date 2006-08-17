/*
                               Fauxide

		      A virtual disk drive tool
 
               Copyright (c) 2002-2004, Intel Corporation
                          All Rights Reserved

This software is distributed under the terms of the Eclipse Public License, 
Version 1.0 which can be found in the file named LICENSE.  ANY USE, 
REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
ACCEPTANCE OF THIS AGREEMENT

*/

/* $Id: tf.c,v 1.7 2004/11/01 16:18:52 makozuch Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include "fauxide.h"

#define FAUXIDE_FILE_NAME    "/dev/hdk"

void usage(const char *progname)
{
    printf
	("usage: %s [openclose] [test_signal] [seek <n>] [read <n>] [rescue] [kick]\n",
	 progname);
}

int main(int argc, char *argv[])
{
    int i = 0;
    int d = -1;

    int tf_openclose = 0;
    int tf_test_signal = 0;
    int tf_seek = 0;
    int tf_read = 0;
    int tf_rescue = 0;
    int tf_kick = 0;

    long tf_seek_arg = 0;
    long tf_read_arg = 0;


    /* parse command line */
    if (argc < 2) {
		usage(argv[0]);
    }
    for (i = 1; i < argc; i++) {
	if (strcmp("openclose", argv[i]) == 0) {
	    tf_openclose = 1;
	} else if (strcmp("test_signal", argv[i]) == 0) {
	    tf_openclose = 1;
	    tf_test_signal = 1;
	} else if (strcmp("read", argv[i]) == 0) {
	    tf_openclose = 1;
	    tf_read = 1;
	    if (i + 1 >= argc) {
			usage(argv[0]);
	    }
	    tf_read_arg = atol(argv[++i]);
	} else if (strcmp("seek", argv[i]) == 0) {
	    tf_openclose = 1;
	    tf_seek = 1;
	    if (i + 1 >= argc) {
			usage(argv[0]);
	    }
	    tf_seek_arg = atol(argv[++i]);
	} else if (strcmp("rescue", argv[i]) == 0) {
	    tf_openclose = 1;
	    tf_rescue = 1;
	    /*
	       } else if(strcmp("kick", argv[i]) == 0) {
	       tf_openclose = 1;
	       tf_kick = 1;
	     */
	} else {
	    usage(argv[0]);
	}
    }

    if (tf_openclose) {
	d = open(FAUXIDE_FILE_NAME, O_RDWR);
	if (d < 0) {
	    printf("ERROR: unable to open %s.\n", FAUXIDE_FILE_NAME);
	    exit(0);
	}
    }

    if (tf_test_signal)
	ioctl(d, FAUXIDE_IOCTL_TEST_SIGNAL);

    if (tf_seek) {
	off_t result;
	result = lseek(d, (off_t) tf_seek_arg, SEEK_SET);

	if (result != tf_seek_arg) {
	    printf("WARNING! seek(): requested %li returned %li\n",
		   (long) tf_seek_arg, (long) result);
	}
    }

    if (tf_read) {
	char *buf;
	ssize_t bytes_returned;

	buf = malloc(tf_read_arg);
	if (buf) {
	    bytes_returned = read(d, buf, (size_t) tf_read_arg);
	    if (bytes_returned != tf_read_arg) {
		printf("WARNING! read(): requested %li returned %li\n",
		       (long) tf_read_arg, (long) bytes_returned);
		free(buf);
	    }
	} else {
	    printf("WARNING! malloc() failure. read aborted.\n");
	}
    }

    if (tf_rescue)
	ioctl(d, FAUXIDE_IOCTL_RESCUE);
    /*
       if(tf_kick)
       ioctl(d, FAUXIDE_IOCTL_KICK_REGISTRAR);
     */

    if (tf_openclose)
	close(d);

    return 0;
}
