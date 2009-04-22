AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I$(top_srcdir)/sqlite
AM_CPPFLAGS += -I$(top_srcdir)/crypto -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -W -Wall -Wstrict-prototypes $(NO_FIELD_INITIALIZER_WARNINGS)
AM_CFLAGS += $(libuuid_CFLAGS) $(glib_CFLAGS)
AM_LDFLAGS = -L$(top_builddir)/sqlite -L$(top_builddir)/crypto
AM_LDFLAGS += -lcurl -lsqlite -lrt -lisrcrypto $(libuuid_LIBS) $(glib_LIBS)

pkglib_PROGRAMS = parcelkeeper
parcelkeeper_SOURCES  = cmdline.c main.c log.c cache.c cache_modes.c
parcelkeeper_SOURCES += hoard.c hoard_modes.c nexus.c util.c parcelcfg.c
parcelkeeper_SOURCES += transport.c sql.c defs.h
nodist_parcelkeeper_SOURCES = revision.c
CLEANFILES = revision.c

include $(top_srcdir)/mkrevision.mk
