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

static int (*real_open)(const char *pathname, int flags, ...);
static int (*real_ioctl)(int fd, int request, ...);
static int (*real_close)(int fd);
static int (*real_dup)(int oldfd);
static int (*real_dup2)(int oldfd, int newfd);
static int (*real_fcntl)(int fd, int cmd, ...);

static struct {
	unsigned *map;
	unsigned words;
	pthread_mutex_t lock;
} fdmap={NULL, 0, PTHREAD_MUTEX_INITIALIZER};

/**** Debug and message stuff ****/
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

static void __attribute__((constructor)) libvdisk_init(void)
{
	debug("Initializing libvdisk");
	real_open=dlsym(RTLD_NEXT, "open");
	real_ioctl=dlsym(RTLD_NEXT, "ioctl");
	real_close=dlsym(RTLD_NEXT, "close");
	real_dup=dlsym(RTLD_NEXT, "dup");
	real_dup2=dlsym(RTLD_NEXT, "dup2");
	real_fcntl=dlsym(RTLD_NEXT, "fcntl");
	if (real_open == NULL || real_ioctl == NULL || real_close == NULL ||
				real_dup == NULL || real_dup2 == NULL ||
				real_fcntl == NULL) {
		warn("Failed to get symbols");
		/* Cut our losses, since we're just going to fail horribly
		   later on */
		exit(-1);
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

static int open_wrapper(const char *pathname, int flags, mode_t mode)
{
	int ret, err;
	ret=real_open(pathname, flags, mode);
	err=errno;
	debug("Opening %s => %d", pathname, ret);
	/* XXX */
	if (ret != -1 && strncmp("/dev/hd", pathname, 7) == 0)
		add_fd(ret);
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
	ret=real_close(fd);
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
	ret=real_dup(oldfd);
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
	ret=real_dup2(oldfd, newfd);
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
	ret=real_fcntl(fd, cmd, arg);
	err=errno;
	debug("fcntl %d on %d => %d", cmd, fd, ret);
	if (cmd == F_DUPFD && ret != -1 && fd_active(fd))
		add_fd(ret);
	errno=err;
	return ret;
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
		return real_ioctl(fd, request, arg);
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
		ret=real_ioctl(fd, request, arg);
		err=errno;
		break;
#if 0
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
#endif
	case SCSI_IOCTL_GET_IDLUN:
		name="SCSI_IOCTL_GET_IDLUN";
		ret=-1;
		err=ENOTTY;
		break;
	default:
		snprintf(buf, sizeof(buf), "0x%lx", request);
		name=buf;
		ret=real_ioctl(fd, request, arg);
		err=errno;
	}
	if (request != FIONREAD)
		debug("ioctl %s on %d => %d", name, fd, ret);
	errno=err;
	return ret;
}

