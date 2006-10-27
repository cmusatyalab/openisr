#ifndef VULPES_UTIL_H_
#define VULPES_UTIL_H_

int is_dir(const char *name);
int is_file(const char *name);
off_t get_filesize(int fd);

#endif
