AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I$(top_srcdir)/sqlite
AM_CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -W -Wall -Wstrict-prototypes -Wno-missing-field-initializers
AM_CFLAGS += $(OSSP_UUID_CFLAGS)
AM_LDFLAGS = -L$(top_srcdir)/sqlite -lcrypto -lcurl -lsqlite -lrt
AM_LDFLAGS += $(OSSP_UUID_LIBS)

pkglib_PROGRAMS = parcelkeeper
parcelkeeper_SOURCES  = cmdline.c main.c log.c cache.c cache_modes.c
parcelkeeper_SOURCES += hoard.c hoard_modes.c nexus.c util.c parcelcfg.c
parcelkeeper_SOURCES += transport.c sql.c defs.h
nodist_parcelkeeper_SOURCES = revision.c

include $(top_srcdir)/mkrevision.mk
