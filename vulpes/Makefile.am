AM_CFLAGS= -g -O2 -Wall -Wstrict-prototypes -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I../nexus -I/lib/modules/`uname -r`/build/include
AM_LFLAGS= -lz -lssl -lcurl

pkglib_PROGRAMS = vulpes
vulpes_SOURCES = revision.c main.c driver.c transport.c cache.c crypto.c log.c util.c lookaside.c

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh object vulpes
-include revision.dummy
