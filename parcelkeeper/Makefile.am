# We need the 2.6 version of <linux/loop.h>, and some distros have the
# 2.4 version in /usr/include
AM_CPPFLAGS = -I$(top_srcdir)/nexus -I$(KERNELDIR)/include
AM_CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -Wall -Wstrict-prototypes $(APR_CFLAGS) $(OSSP_UUID_CFLAGS)
AM_LDFLAGS = -lcrypto -lcurl $(SQLITE_LIBS) $(APR_LIBS) $(OSSP_UUID_LIBS)

pkglib_PROGRAMS = parcelkeeper
parcelkeeper_SOURCES  = cmdline.c main.c log.c cache.c nexus.c util.c
parcelkeeper_SOURCES += parcelcfg.c transport.c sql.c defs.h
nodist_parcelkeeper_SOURCES = revision.c

REVISION_TYPE = object
include $(top_srcdir)/mkrevision.mk
