#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "vulpes_log.h"

int local_get(char *buf, int *bufsize, const char *file)
{
  int fd;
  int count;
  
  fd = open(file, O_RDONLY);
  if (fd == -1) {
    vulpes_log(LOG_ERRORS,"LOCAL_GET","unable to open input %s",file);
    return -1;
  }
  count=read(fd, buf, *bufsize);
  if (count == -1) {
    vulpes_log(LOG_ERRORS,"LOCAL_GET","unable to read input %s",file);
    return -1;
  }
  if (count == *bufsize) {
    /* Make sure we're at EOF */
    if (lseek(fd, 0, SEEK_END) != count) {
      vulpes_log(LOG_ERRORS,"LOCAL_GET","file larger than buffer: %s",file);
      return -1;
    }
  }
  close(fd);
  *bufsize=count;
  
  return 0;
}
