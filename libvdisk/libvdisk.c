/*
 * libvdisk - LD_PRELOAD library for block device access from finicky VMMs
 * 
 * Copyright (C) 2006 Carnegie Mellon University
 * 
 * This software is distributed under the terms of the Eclipse Public License, 
 * Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE, 
 * REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
 * ACCEPTANCE OF THIS AGREEMENT
 */

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
#include "revision.h"

#undef DEBUG
#define MAXPATHLEN 512

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
static int verbose=0;

/**** Debug and message stuff ****/

#define warn(s, args...) \
	fprintf(stderr, "libvdisk (%d): " s "\n", getpid(), ## args)
#define ndebug(s, args...) do {} while (0)

#ifdef DEBUG
#define debug(s, args...) warn(s, ## args)
#else
#define debug(s, args...) do {} while (0)
#endif

/**** Initialization ****/

static void _get_symbol(void **dest, char *name)
{
	*dest=dlsym(RTLD_NEXT, name);
	if (*dest == NULL) {
		warn("Failed to get symbol: %s: %s", name, dlerror());
		/* Cut our losses, since we're just going to fail horribly
		   later on */
		exit(-1);
	}
}
#define GET_SYMBOL(foo) _get_symbol((void**)&foo ## _real, #foo)

static void __attribute__((constructor)) libvdisk_init(void)
{
	char *tmp;
	
	tmp=getenv("VDISK_VERBOSE");
	if (tmp != NULL)
		verbose=1;
	
	if (verbose)
		warn("Initializing, revision " RCS_REVISION);
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
	
	tmp=getenv("VDISK_DEVICE");
	if (tmp != NULL) {
		realdev=strndup(tmp, MAXPATHLEN);
		if (realdev == NULL) {
			warn("Failed to read VDISK_DEVICE; no remapping "
						"will be done");
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

/* Must be called with fdmap lock held.  Returns -1 and sets errno on error. */
static int _fdmap_make_space(int fd)
{
	unsigned newsize;
	unsigned *newmap;
	
	if (fd < 0) {
		errno=EINVAL;
		return -1;
	}
	if ((unsigned)fd < fdmap.words*BITS_PER_WORD)
		return 0;
	
	newsize=2*fdmap.words;
	if (newsize == 0) newsize=1;
	if ((unsigned)fd >= newsize*BITS_PER_WORD)
		newsize=(fd/BITS_PER_WORD)+1;
	debug("Resizing fdmap from %d to %d", fdmap.words, newsize);
	newmap=realloc(fdmap.map, newsize*BYTES_PER_WORD);
	if (newmap == NULL) {
		errno=ENOMEM;
		return -1;
	}
	memset(newmap+fdmap.words, 0, (newsize-fdmap.words)*BYTES_PER_WORD);
	fdmap.map=newmap;
	fdmap.words=newsize;
	return 0;
}

static int _fd_active(int fd)
{
	if (_fdmap_make_space(fd))
		return 0;
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
	if (_fdmap_make_space(fd)) {
		if (errno == ENOMEM)
			warn("Couldn't add fd to map: allocation failed");
		/* else errno == EINVAL, meaning fd < 0, so do nothing */
	} else {
		debug("Adding %d to fdmap", fd);
		fdmap.map[wordof(fd)] |= (1 << bitof(fd));
	}
	pthread_mutex_unlock(&fdmap.lock);
}

static void remove_fd(int fd)
{
	pthread_mutex_lock(&fdmap.lock);
	if (_fd_active(fd)) {
		debug("Removing %d from fdmap", fd);
		fdmap.map[wordof(fd)] &= ~(1 << bitof(fd));
	}
	pthread_mutex_unlock(&fdmap.lock);
}

/**** Utilities ****/

static int remap(const char **pathname)
{
	if (realdev == NULL)
		return 0;
	if (*pathname == NULL || strcmp(*pathname, "/dev/hdk") != 0)
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
	default:
		typename="<unknown>";
		ret=-1;
		errno=EACCES;
		warn("Bug in stat_wrapper(): unknown stat type");
		break;
	}
	err=errno;
	debug("%s %s => %d", typename, filename, ret);
	errno=err;
	return ret;
}

#define min(a,b) ((a) < (b) ? (a) : (b))

static void fill_geo(struct hd_geometry *geo, uint64_t sects)
{
	uint64_t cyls;
	memset(geo, 0, sizeof(*geo));
	geo->heads=255;
	geo->sectors=63;
	/* We must round down in case of a partial cylinder */
	cyls=sects / (geo->heads * geo->sectors);
	geo->cylinders=min(cyls, 65535);
}

/* Based on a very loose reading of ATA-7 draft 4a and ATA-4 draft 18
   (the last version that provided C/H/S values). */
static void fill_driveid(struct hd_driveid *id, uint64_t sects)
{
	uint64_t cyls;
	memset(id, 0, sizeof(*id));
	id->heads=id->cur_heads=16;
	id->sectors=id->cur_sectors=63;
	/* We must round down in case of a partial cylinder */
	cyls=sects / (id->heads * id->sectors);
	id->cyls=id->cur_cyls=min(cyls, 16383);
	/* The ATA standard pads these with spaces, but the kernel converts
	   the spaces to nulls, and in the "model" case ensures that the string
	   is null-terminated.  To be safe we make all of the strings
	   null-terminated. */
	snprintf((char*)id->model,     40, "libvdisk");
	snprintf((char*)id->fw_rev,     8, "0");
	snprintf((char*)id->serial_no, 20, "0");
	id->capability=0x2;        /* LBA */
	id->command_set_2=0x4400;  /* 48-bit LBA */
	id->lba_capacity=min(sects, 0x0fffffff);
	id->cur_capacity0=(unsigned short)(id->lba_capacity & 0xffff);
	id->cur_capacity1=(unsigned short)(id->lba_capacity >> 16);
	id->lba_capacity_2=sects;
}

#define get_last_arg(last_named_arg, arg_type, dest) do { \
	va_list ap; \
	va_start(ap, last_named_arg); \
	dest=va_arg(ap, arg_type); \
	va_end(ap); \
	} while (0)

/**** Wrapped functions ****/

/* NOTE: All of these functions must save and restore errno across
   library calls */

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
	uint64_t size;  /* bytes */
	
	get_last_arg(request, void *, arg);
	if (!fd_active(fd))
		return ioctl_real(fd, request, arg);
	
	switch (request) {
	case BLKGETSIZE64:
		name="BLKGETSIZE64";
		break;
	case HDIO_GETGEO:
		name="HDIO_GETGEO";
		break;
	case HDIO_GET_IDENTITY:
		name="HDIO_GET_IDENTITY";
		break;
	case SCSI_IOCTL_GET_IDLUN:
		name="SCSI_IOCTL_GET_IDLUN";
		break;
	default:
		snprintf(buf, sizeof(buf), "0x%lx", request);
		name=buf;
	}

	switch (request) {
	case HDIO_GETGEO:
	case HDIO_GET_IDENTITY:
		/* There's no good way to check whether arg is a valid pointer
		   in the same way the kernel would, so an invalid arg will
		   produce SIGSEGV rather than EFAULT.  We do the obvious
		   check, even though it's a bit silly. */
		if ((void*)arg == NULL) {
			ret=-1;
			err=EFAULT;
			break;
		}
		ret=ioctl_real(fd, BLKGETSIZE64, &size);
		if (ret) {
			err=errno;
			break;
		}
		if (request == HDIO_GETGEO)
			fill_geo((struct hd_geometry*)arg, size/512);
		else
			fill_driveid((struct hd_driveid*)arg, size/512);
		ret=0;
		break;
	case SCSI_IOCTL_GET_IDLUN:
		ret=-1;
		err=ENOTTY;
		break;
	default:
		ret=ioctl_real(fd, request, arg);
		err=errno;
	}
	if (request != FIONREAD)
		debug("ioctl %s on %d => %d", name, fd, ret);
	errno=err;
	return ret;
}
