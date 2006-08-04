#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <scsi/scsi.h>

static int (*real_open)(const char *pathname, int flags, ...);
static int (*real_ioctl)(int fd, int request, ...);

static void __attribute__((constructor)) libvdisk_init(void)
{
	fprintf(stderr, "Initializing libvdisk\n");
	real_open=dlsym(RTLD_NEXT, "open");
	real_ioctl=dlsym(RTLD_NEXT, "ioctl");
	if (real_open == NULL || real_ioctl == NULL)
		/* XXX */;
}

static int open_wrapper(const char *pathname, int flags, mode_t mode)
{
	int ret, err;
	ret=real_open(pathname, flags, mode);
	err=errno;
	fprintf(stderr, "Opening %s => %d\n", pathname, ret);
	errno=err;
	return ret;
}

static int fill_driveid(struct hd_driveid *id, uint64_t blocks)
{
	if (id == NULL)
		return -1;
	memset(id, 0, sizeof(*id));
	return 0;
}

#define get_last_arg(last_named_arg, arg_type, dest) do { \
	va_list ap; \
	va_start(ap, last_named_arg); \
	dest=va_arg(ap, arg_type); \
	va_end(ap); \
	} while (0)

/**** Wrapped functions ****/

int open(const char *pathname, int flags, ...)
{
	mode_t mode=0;
	
	if (flags & O_CREAT)
		get_last_arg(flags, mode_t, mode);
	return open_wrapper(pathname, flags, mode);
}

int open64(const char *pathname, int flags, ...)
{
	mode_t mode=0;
	
	if (flags & O_CREAT)
		get_last_arg(flags, mode_t, mode);
	return open_wrapper(pathname, flags|O_LARGEFILE, mode);
}

int ioctl(int fd, unsigned long request, ...)
{
	void *arg;
	int ret, err=0;
	char *name;
	char buf[12];
	uint64_t blocks;
	
	get_last_arg(request, void *, arg);
	switch (request) {
	case BLKGETSIZE64:
		name="BLKGETSIZE64";
		ret=real_ioctl(fd, request, arg);
		/* We need to save and restore errno across library calls */
		err=errno;
		break;
	case HDIO_GETGEO:
		name="HDIO_GETGEO";
		ret=real_ioctl(fd, request, arg);
		err=errno;
		break;
	case HDIO_GET_IDENTITY:
		name="HDIO_GET_IDENTITY";
		ret=real_ioctl(fd, BLKGETSIZE64, &blocks);
		if (ret) {
			err=errno;
			break;
		}
		if (fill_driveid((struct hd_driveid*)arg, blocks)) {
			/* XXX null pointer check */
			ret=-1;
			err=EFAULT;
			break;
		}
		ret=0;
		break;
	case SCSI_IOCTL_GET_IDLUN:
		name="SCSI_IOCTL_GET_IDLUN";
		ret=-1;
		err=ENOTTY;
		break;
	default:
		snprintf(buf, sizeof(buf), "0x%lx", request);
		name=buf;
	}
	if (request != FIONREAD)
		fprintf(stderr, "ioctl %s on %d => %d\n", name, fd, ret);
	errno=err;
	return ret;
}
