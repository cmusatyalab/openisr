/*
 * isr_shell - Fake shell which only allows running ISR server commands
 *
 * Copyright (C) 2009 Carnegie Mellon University
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

static void die(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

int main(int argc, char **argv)
{
	int sub_argc;
	char **sub_argv;

	if (argc != 3 || strcmp(argv[1], "-c"))
		die("This is not an interactive shell.");

	if (!g_shell_parse_argv(argv[2], &sub_argc, &sub_argv, NULL) ||
				sub_argc == 0)
		die("Couldn't parse command.");

	if (!strcmp(sub_argv[0], "passwd") ||
				!strcmp(sub_argv[0], "ssh-add")) {
		if (sub_argc != 1)
			die("You may not pass extra arguments to this "
						"command.");
	} else if (strcmp(sub_argv[0], "isr_runserv")) {
		die("You may not run arbitrary commands on this system.");
	}

	execvp(sub_argv[0], sub_argv);
	die("Couldn't run command.");
	return 0;
}
