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
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <scsi/scsi.h>
#include <pthread.h>

#define DEBUG
/* XXX */
#define MAXPATHLEN 256

static int (*open_real)(const char *pathname, int flags, ...);
static int (*ioctl_real)(int fd, int request, ...);
static int (*close_real)(int fd);
static int (*dup_real)(int oldfd);
static int (*dup2_real)(int oldfd, int newfd);
static int (*fcntl_real)(int fd, int cmd, ...);
static int (*__xstat_real)(int ver, const char *filename, struct stat *buf);
static int (*__xstat64_real)(int ver, const char *filename, struct stat *buf);
static int (*__lxstat_real)(int ver, const char *filename, struct stat *buf);
static int (*__lxstat64_real)(int ver, const char *filename, struct stat *buf);

static struct {
	unsigned *map;
	unsigned words;
	pthread_mutex_t lock;
} fdmap={NULL, 0, PTHREAD_MUTEX_INITIALIZER};
static char *realdev=NULL;

/**** Debug and message stuff ****/
/* XXX convert to function? */
#define warn(s, args...) do { \
	fprintf(stderr, "libvdisk (%d): ", getpid()); \
	fprintf(stderr, s , ## args); \
	fprintf(stderr, "\n"); \
	} while (0)
#define ndebug(s, args...) /***/

#ifdef DEBUG
#define debug(s, args...) warn(s , ## args)
#else
#define debug(s, args...) /***/
#endif

static void _get_symbol(void **dest, char *name)
{
	*dest=dlsym(RTLD_NEXT, name);
	if (*dest == NULL) {
		warn("Failed to get symbol: %s", name);
		/* Cut our losses, since we're just going to fail horribly
		   later on */
		exit(-1);
	}
}
#define GET_SYMBOL(foo) _get_symbol((void**)&foo ## _real, #foo)

static void __attribute__((constructor)) libvdisk_init(void)
{
	char *path;

	debug("Initializing libvdisk");
	GET_SYMBOL(open);
	GET_SYMBOL(ioctl);
	GET_SYMBOL(close);
	GET_SYMBOL(dup);
	GET_SYMBOL(dup2);
	GET_SYMBOL(fcntl);
	GET_SYMBOL(__xstat);
	GET_SYMBOL(__xstat64);
	GET_SYMBOL(__lxstat);
	GET_SYMBOL(__lxstat64);

	path=getenv("VDISK_DEVICE");
	if (path != NULL) {
		realdev=strndup(path, MAXPATHLEN);
		if (realdev == NULL) {
			warn("Failed to read VDISK_DEVICE; no remapping will be done");
		}
	} else {
		warn("VDISK_DEVICE not set; no remapping will be done");
	}
}

/**** FD tracking ****/

#define BYTES_PER_WORD (sizeof(*fdmap.map))
#define BITS_PER_WORD (8*BYTES_PER_WORD)
#define wordof(fd) (fd/BITS_PER_WORD)
#define bitof(fd) (fd%BITS_PER_WORD)

/* Must be called with fdmap lock held */
static void _fdmap_make_space(int fd)
{
	unsigned newsize;
	unsigned *newmap;
	
	if (fd < fdmap.words*BITS_PER_WORD)
		return;

	newsize=2*fdmap.words;
	if (newsize == 0) newsize=1;
	if (fd >= newsize*BITS_PER_WORD)
		newsize=(fd/BITS_PER_WORD)+1;
	debug("Resizing fdmap from %d to %d", fdmap.words, newsize);
	newmap=malloc(newsize*BYTES_PER_WORD);
	if (newmap == NULL) {
		/* XXX */
		warn("Aiee, map allocation failed!");
		return;
	}
	memset(newmap, 0, newsize*BYTES_PER_WORD);
	if (fdmap.map != NULL) {
		memcpy(newmap, fdmap.map, fdmap.words*BYTES_PER_WORD);
		free(fdmap.map);
	}
	fdmap.map=newmap;
	fdmap.words=newsize;
}

static int _fd_active(int fd)
{
	_fdmap_make_space(fd);
	return ((fdmap.map[wordof(fd)] & (1 << bitof(fd))) != 0);	
}

static int fd_active(int fd)
{
	int ret;
	pthread_mutex_lock(&fdmap.lock);
	ret=_fd_active(fd);
	pthread_mutex_unlock(&fdmap.lock);
	return ret;
}

static void add_fd(int fd)
{
	pthread_mutex_lock(&fdmap.lock);
	_fdmap_make_space(fd);
	debug("Adding %d to fdmap", fd);
	fdmap.map[wordof(fd)] |= (1 << bitof(fd));
	pthread_mutex_unlock(&fdmap.lock);
}

static void remove_fd(int fd)
{
	pthread_mutex_lock(&fdmap.lock);
	_fdmap_make_space(fd);
	if (_fd_active(fd)) {
		debug("Removing %d from fdmap", fd);
		fdmap.map[wordof(fd)] &= ~(1 << bitof(fd));
	}
	pthread_mutex_unlock(&fdmap.lock);
}

/**** Utilities ****/

static int remap(const char **pathname)
{
	if (realdev == NULL || strcmp(*pathname, "/dev/hdv") != 0)
		return 0;
	*pathname=realdev;
	return 1;
}

static int open_wrapper(const char *pathname, int flags, mode_t mode)
{
	int ret, err, remapped;
	remapped=remap(&pathname);
	ret=open_real(pathname, flags, mode);
	err=errno;
	debug("Opening %s => %d", pathname, ret);
	if (remapped && ret != -1)
		add_fd(ret);
	errno=err;
	return ret;
}

enum stat_type {
	STAT,
	STAT64,
	LSTAT,
	LSTAT64
};

static int stat_wrapper(int ver, const char *filename, void *buf,
			enum stat_type type)
{
	int ret, err;
	char *typename;
	remap(&filename);
	switch (type) {
	case STAT:
		typename="stat";
		ret=__xstat_real(ver, filename, buf);
		break;
	case STAT64:
		typename="stat64";
		ret=__xstat64_real(ver, filename, buf);
		break;
	case LSTAT:
		typename="lstat";
		ret=__lxstat_real(ver, filename, buf);
		break;
	case LSTAT64:
		typename="lstat64";
		ret=__lxstat64_real(ver, filename, buf);
		break;
	}
	err=errno;
	debug("%s %s => %d", typename, filename, ret);
	errno=err;
	return ret;
}

static int fill_driveid(struct hd_driveid *id, uint64_t blocks)
{
	if (id == NULL)
		return -1;
	memset(id, 0, sizeof(*id));
	/* XXX */
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

int close(int fd)
{
	int ret, err;
	ret=close_real(fd);
	err=errno;
	debug("Closing %d => %d", fd, ret);
	/* On Linux, close() always releases the fd even if it returns
	   EINTR. */
	remove_fd(fd);
	errno=err;
	return ret;
}

int dup(int oldfd)
{
	int ret, err;
	ret=dup_real(oldfd);
	err=errno;
	debug("dup %d => %d", oldfd, ret);
	if (ret != -1 && fd_active(oldfd))
		add_fd(ret);
	errno=err;
	return ret;
}

int dup2(int oldfd, int newfd)
{
	int ret, err;
	ret=dup2_real(oldfd, newfd);
	err=errno;
	debug("dup2 %d => %d", oldfd, ret);
	if (ret != -1 && fd_active(oldfd))
		add_fd(ret);
	errno=err;
	return ret;
}

int fcntl(int fd, int cmd, ...)
{
	unsigned arg;
	int ret, err;
	get_last_arg(cmd, unsigned, arg);
	ret=fcntl_real(fd, cmd, arg);
	err=errno;
	debug("fcntl %d on %d => %d", cmd, fd, ret);
	if (cmd == F_DUPFD && ret != -1 && fd_active(fd))
		add_fd(ret);
	errno=err;
	return ret;
}

/* stat() in user programs translates to an __xstat() call at the library
   interface.  See the block comment in /usr/include/sys/stat.h. */
int __xstat(int ver, const char *filename, struct stat *buf)
{
	return stat_wrapper(ver, filename, buf, STAT);
}

/* We wrap all four stat() variants for completeness, but VMWare 5.5
   seems to only care about stat64().  Perhaps we should wrap access()
   also, though it is obscure. */
int __xstat64(int ver, const char *filename, struct stat64 *buf)
{
	return stat_wrapper(ver, filename, buf, STAT64);
}

int __lxstat(int ver, const char *filename, struct stat *buf)
{
	return stat_wrapper(ver, filename, buf, LSTAT);
}

int __lxstat64(int ver, const char *filename, struct stat64 *buf)
{
	return stat_wrapper(ver, filename, buf, LSTAT64);
}

/* native CD-ROM driver fails without fd tracking */
int ioctl(int fd, unsigned long request, ...)
{
	void *arg;
	int ret, err=0;
	char *name;
	char buf[12];
	uint64_t blocks;
	
	get_last_arg(request, void *, arg);
	if (!fd_active(fd))
		return ioctl_real(fd, request, arg);
	switch (request) {
	case BLKGETSIZE64:
		name="BLKGETSIZE64";
		ret=ioctl_real(fd, request, arg);
		/* We need to save and restore errno across library calls */
		err=errno;
		break;
	case HDIO_GETGEO:
		name="HDIO_GETGEO";
		ret=ioctl_real(fd, request, arg);
		err=errno;
		break;
	case HDIO_GET_IDENTITY:
		name="HDIO_GET_IDENTITY";
		ret=ioctl_real(fd, request, arg);
		err=errno;
		break;
#if 0
		ret=ioctl_real(fd, BLKGETSIZE64, &blocks);
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
#endif
	case SCSI_IOCTL_GET_IDLUN:
		name="SCSI_IOCTL_GET_IDLUN";
		ret=-1;
		err=ENOTTY;
		break;
	default:
		snprintf(buf, sizeof(buf), "0x%lx", request);
		name=buf;
		ret=ioctl_real(fd, request, arg);
		err=errno;
	}
	if (request != FIONREAD)
		debug("ioctl %s on %d => %d", name, fd, ret);
	errno=err;
	return ret;
}

