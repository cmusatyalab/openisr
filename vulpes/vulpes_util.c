#include <sys/types.h>
#include <sys/stat.h>
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
  }
  return "(Unknown)";
}
