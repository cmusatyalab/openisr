# We need the 2.6 version of <linux/loop.h>, and some distros have the
# 2.4 version in /usr/include
AM_CPPFLAGS = -I$(top_srcdir)/nexus -I$(KERNELDIR)/include
AM_CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -Wall -Wstrict-prototypes
AM_LDFLAGS = -lz -lssl -lcurl

pkglib_PROGRAMS = vulpes
vulpes_SOURCES = revision.c main.c driver.c transport.c cache.c crypto.c \
			log.c util.c lookaside.c crypto.h log.h lookaside.h \
			state.h util.h vulpes.h

REVISION_TYPE = object
REVISION_DIR = vulpes
include $(top_srcdir)/mkrevision.mk
