#include <stdio.h>

extern const char *rcs_revision;

int main(int argc, char **argv)
{
	printf("%s\n", rcs_revision);
	return 0;
}
