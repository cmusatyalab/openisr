#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include "vulpes.h"

int is_dir(const char *name)
{
  struct stat s;
  int result = 0;
  
  if (stat(name, &s) == 0) {
    result = S_ISDIR(s.st_mode);
  }
  
  return result;
}

int is_file(const char *name)
{
  struct stat s;
  int result = 0;
  
  if (stat(name, &s) == 0) {
    result = S_ISREG(s.st_mode);
  }
  
  return result;
}

off_t get_filesize(int fd)
{
    struct stat s;
    
    /* Get file statistics */
    if (fstat(fd, &s)) {
      return (off_t) 0;
    }

    return s.st_size;
}

/* XXX does not ensure we're at the beginning of the file */
vulpes_err_t read_file(int fd, char *buf, int *bufsize)
{
  int count=read(fd, buf, *bufsize);
  if (count == -1)
    return VULPES_IOERR;
  if (count == *bufsize) {
    /* Make sure we're at EOF */
    if (lseek(fd, 0, SEEK_END) != count)
      return VULPES_OVERFLOW;
  }
  *bufsize=count;
  return 0;
}

char *vulpes_strerror(vulpes_err_t err)
{
  switch (err) {
  case VULPES_SUCCESS:
    return "Success";
  case VULPES_OVERFLOW:
    return "Buffer too small for data";
  case VULPES_IOERR:
    return "I/O error";
  case VULPES_NOTFOUND:
    return "Object not found";
  case VULPES_INVALID:
    return "Invalid parameter";
  case VULPES_NOMEM:
    return "Out of memory";
  case VULPES_NOKEY:
    return "No such key in keyring";
  case VULPES_TAGFAIL:
    return "Tag did not match data";
  }
  return "(Unknown)";
}

inline void charToHex(unsigned char* bin, unsigned char hex[2])
{
	int i;
	unsigned char tmp;

	tmp = *bin;
	i = ((int)tmp)/16;
	if (i<10)
		hex[0] = '0' + i;
	else
		hex[0] = 'A' + (i-10);
	i = ((int)tmp)%16;
	if (i<10)
		hex[1] = '0' + i;
	else
		hex[1] = 'A' + (i-10);
}

/* This function has to be really fast! */
inline unsigned char hexToChar(unsigned char* hex)
{
	int i,j;

	if ((hex[0]>='0')&&(hex[0]<='9'))
		i = hex[0]-'0';
	else
		if ((hex[0]>='A')&&(hex[0]<='F'))
			i = 10 + hex[0]-'A';
		else
		{
			printf("Keyring invalid: %c \n",hex[0]);
			exit(1);
		};
	if ((hex[1]>='0')&&(hex[1]<='9'))
		j = hex[1]-'0';
	else
		if ((hex[1]>='A')&&(hex[1]<='F'))
			j = 10 + hex[1]-'A';
		else
		{
			printf("Keyring invalid: %c \n",hex[1]);
			exit(1);
		};
	return ((unsigned char)(16*i + j));
}

/* @hex should be 2*binBytes+1 bytes long */
void binToHex(unsigned char *bin, unsigned char *hex, int binBytes)
{
  int i;
  
  for (i=0; i<binBytes; i++, bin++, hex += 2)
    charToHex(bin, hex);
  *hex=0;
}

void hexToBin(unsigned char *hex, unsigned char *bin, int binBytes)
{
  int i;
  
  for (i=0; i<binBytes; i++, bin++, hex += 2)
    *bin=hexToChar(hex);
}
