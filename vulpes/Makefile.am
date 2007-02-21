AM_CFLAGS= -g -O2 -Wall -Wstrict-prototypes -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/nexus -I/lib/modules/`uname -r`/build/include
AM_LDFLAGS= -lz -lssl -lcurl

pkglib_PROGRAMS = vulpes
vulpes_SOURCES = revision.c main.c driver.c transport.c cache.c crypto.c \
			log.c util.c lookaside.c crypto.h log.h lookaside.h \
			state.h util.h vulpes.h

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.
.PHONY: revision.dummy
revision.dummy:
	@$(top_srcdir)/mkrevision.sh object vulpes
-include revision.dummy
