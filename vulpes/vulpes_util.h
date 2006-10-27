#ifndef VULPES_UTIL_H_
#define VULPES_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int is_dir(const char *name);
int is_file(const char *name);
off_t get_filesize(int fd);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
