#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

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
