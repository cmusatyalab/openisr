AM_CFLAGS=-W -Wall -Wstrict-prototypes -O2 -fno-strict-aliasing

lib_LTLIBRARIES = libvdisk.la
libvdisk_la_SOURCES = libvdisk.c

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh header libvdisk
-include revision.dummy

