/*
 * readstats - Format and display Nexus state statistics
 *
 * Copyright (C) 2006-2008 Carnegie Mellon University
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
#include "nexus.h"

#define NEXUS_STATE(x) #x,
char *states[]={
	NEXUS_STATES
	NULL
};
#undef NEXUS_STATE

int main(int argc, char **argv)
{
	char **state=states;
	FILE *fp;
	unsigned val;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		return 1;
	}
	fp=fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Couldn't open file\n");
		return 1;
	}
	while (*state != NULL) {
		if (fscanf(fp, "%u", &val) != 1) {
			fprintf(stderr, "Not enough values in file\n");
			return 1;
		}
		printf("%18s %8u\n", *state, val);
		state++;
	}
	if (fscanf(fp, "%u", &val) != EOF) {
		fprintf(stderr, "Too many values in file\n");
		return 1;
	}
	return 0;
}
