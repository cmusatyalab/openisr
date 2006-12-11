#include <stdio.h>

char *states[]={
	"INVALID",
	"LOAD_META",
	"META",
	"LOAD_DATA",
	"ENCRYPTED",
	"CLEAN",
	"DIRTY",
	"STORE_DATA",
	"DIRTY_META",
	"STORE_META",
	"ERROR",
	NULL
};

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
		printf("%15s %8u\n", *state, val);
		state++;
	}
	if (fscanf(fp, "%u", &val) != EOF) {
		fprintf(stderr, "Too many values in file\n");
		return 1;
	}
	return 0;
}
