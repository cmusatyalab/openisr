/* 
 * Nexus - convergently encrypting virtual disk driver for the OpenISR (R)
 *         system
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MASKFILE "/sys/class/openisr/debug_mask"

char *bits[]={
	"init",
	"ctr",
	"refcount",
	"thread",
	"tfm",
	"request",
	"chardev",
	"cd",
	"io",
	"err",
	NULL
};

int usage(char *argv0) {
	printf("Usage: %s {-q | -l | [-s] flag [flag [flag [...]]]}\n", argv0);
	return 1;
}

int query(void) {
	FILE *fp;
	unsigned flags=0;
	int i;
	
	fp=fopen(MASKFILE, "r");
	if (fp == NULL) {
		printf("Nexus not loaded or debugging not enabled\n");
		return 1;
	}
	if (fscanf(fp, "%x\n", &flags) != 1) {
		printf("Unable to parse debug flags\n");
		return 1;
	}
	fclose(fp);
	if (flags == 0) {
		printf("<none>\n");
	} else {
		for (i=0; bits[i] != NULL; i++)
			if (flags & (1 << i))
				printf("%s ", bits[i]);
		printf("\n");
	}
	return 0;
}

int list(void) {
	int i;
	
	for (i=0; bits[i] != NULL; i++)
		printf("%s ", bits[i]);
	printf("\n");
	return 0;
}

int set(int argc, char **argv)
{
	int i;
	int j;
	unsigned flags=0;
	int write=0;
	FILE *fp=stdout;
	
	for (i=1; i<argc; i++) {
		if (!strcmp("-s", argv[i])) {
			write=1;
			continue;
		}
		for (j=0; bits[j] != NULL; j++) {
			if (!strcasecmp(argv[i], bits[j])) {
				flags |= 1 << j;
				break;
			}
		}
		if (bits[j] == NULL) {
			printf("Unknown debug flag %s\n", argv[i]);
			return 1;
		}
	}
	if (write) {
		fp=fopen(MASKFILE, "w");
		if (fp == NULL) {
			printf("Couldn't open sysfs attribute for writing\n");
			return 1;
		}
	}
	fprintf(fp, "0x%x\n", flags);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 1)
		return usage(argv[0]);
	
	if (argc == 2 && !strcmp(argv[1], "-q"))
		return query();
	
	if (argc == 2 && !strcmp(argv[1], "-l"))
		return list();
	
	return set(argc, argv);
}
