#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

int main(int argc, char *argv[])
{
  double d;
  long long ll;
  size_t len;
  char *p;

  if(argc != 2)
    exit(-1);

  len = strlen(argv[1]);

  d = strtod(argv[1], &p);

  if(p == (argv[1] + len)) {
    /* nothing -- no 'K' 'M' or 'G' */
  } else if(p == (argv[1] + len - 1)) {
    switch(*p) {
    case 'k': case 'K':
      d *= 1024;
      break;
    case 'm': case 'M':
      d *= 1024*1024;
      break;
    case 'g': case 'G':
      d *= 1024*1024*1024;
      break;
    default:
      exit(-1);
    }
  } else {
    exit(-1);
  }

  ll = (long long) ceil(d);

  printf("%lld", ll);

  return 0;
}
