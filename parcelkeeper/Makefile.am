# We need the 2.6 version of <linux/loop.h>, and some distros have the
# 2.4 version in /usr/include
AM_CPPFLAGS = -I$(top_srcdir)/nexus -I$(top_srcdir)/sqlite
AM_CPPFLAGS += -I$(KERNELDIR)/include -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -W -Wall -Wstrict-prototypes -Wno-missing-field-initializers
AM_CFLAGS += $(APR_CFLAGS) $(OSSP_UUID_CFLAGS)
AM_LDFLAGS = -L$(top_srcdir)/sqlite -lcrypto -lcurl -lsqlite
AM_LDFLAGS += $(APR_LIBS) $(OSSP_UUID_LIBS)

pkglib_PROGRAMS = parcelkeeper
parcelkeeper_SOURCES  = cmdline.c main.c log.c cache.c hoard.c nexus.c util.c
parcelkeeper_SOURCES += parcelcfg.c transport.c sql.c defs.h
nodist_parcelkeeper_SOURCES = revision.c

include $(top_srcdir)/mkrevision.mk
