#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "vulpes.h"
#include "vulpes_log.h"
#include "vulpes_util.h"

vulpes_err_t local_get(char *buf, int *bufsize, const char *file)
{
  vulpes_err_t err;
  
  err=read_file(file, buf, bufsize);
  if (err)
    vulpes_log(LOG_ERRORS,"unable to read input %s: %s",file,vulpes_strerror(err));
  return err;
}
