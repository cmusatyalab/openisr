# We need the 2.6 version of <linux/loop.h>, and some distros have the
# 2.4 version in /usr/include
AM_CPPFLAGS = -I$(top_srcdir)/nexus -I$(KERNELDIR)/include
AM_CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -Wall -Wstrict-prototypes
AM_LDFLAGS = -lcrypto -lcurl

pkglib_PROGRAMS = parcelkeeper
parcelkeeper_SOURCES = revision.c cmdline.c main.c log.c defs.h

REVISION_TYPE = object
REVISION_DIR = parcelkeeper
include $(top_srcdir)/mkrevision.mk
