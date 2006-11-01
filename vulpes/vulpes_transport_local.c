#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "vulpes.h"
#include "vulpes_log.h"
#include "vulpes_util.h"

vulpes_err_t local_get(char *buf, int *bufsize, const char *file)
{
  int fd;
  vulpes_err_t err;
  
  fd = open(file, O_RDONLY);
  if (fd == -1) {
    vulpes_log(LOG_ERRORS,"unable to open input %s",file);
    return VULPES_IOERR;
  }
  err=read_file(fd, buf, bufsize);
  if (err) {
    vulpes_log(LOG_ERRORS,"unable to read input %s: %s",file,vulpes_strerror(err));
    return err;
  }
  close(fd);
  return VULPES_SUCCESS;
}
