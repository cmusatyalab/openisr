AM_CFLAGS= -Wall -Wstrict-prototypes -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/nexus -I/lib/modules/`uname -r`/build/include
AM_LDFLAGS= -lz -lssl -lcurl

pkglib_PROGRAMS = vulpes
vulpes_SOURCES = revision.c main.c driver.c transport.c cache.c crypto.c \
			log.c util.c lookaside.c crypto.h log.h lookaside.h \
			state.h util.h vulpes.h

REVISION_TYPE = object
REVISION_DIR = vulpes
include $(top_srcdir)/mkrevision.mk
