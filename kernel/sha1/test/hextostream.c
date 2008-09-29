#include <stdio.h>

int main(int argc, char **argv)
{
	char nextbyte[3];
	int ret;
	unsigned i;
	
	if (argc != 1) {
		fprintf(stderr, "Usage: %s < input-hex > output-binary\n",
					argv[0]);
		return 1;
	}
	
	for (;;) {
		ret=read(0, nextbyte, 2);
		if (ret < 0) {
			perror("Reading stdin");
			return 1;
		}
		if (ret == 0 || nextbyte[0] == '\n')
			break;
		if (nextbyte[1] == '\n') {
			fprintf(stderr, "Odd number of characters in input\n");
			if (nextbyte[0] == '\r')
				fprintf(stderr, "Remove DOS-style "
							"line endings\n");
			return 1;
		}
		if (ret == 1) {
			fprintf(stderr, "Garbage at end of input\n");
			return 1;
		}
		nextbyte[2]=0;
		sscanf(nextbyte, "%x", &i);
		printf("%c", i);
	}
	return 0;
}
