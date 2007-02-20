AM_CFLAGS=-W -Wall -Wstrict-prototypes -O2 -fno-strict-aliasing

lib_LTLIBRARIES = libvdisk.la
libvdisk_la_SOURCES = libvdisk.c

# If the user passed --enable-static to configure, it still doesn't make
# any sense to install a static version of the library, so make sure we
# kill it.  Also, no one should link a program against libvdisk, so get
# rid of libvdisk.la and the libvdisk.so symlink.  Finally, libvdisk
# needs to be setuid and not executable.  (Why is libtool setting
# libraries executable?)
install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/libvdisk.a \
				$(DESTDIR)$(libdir)/libvdisk.la \
				$(DESTDIR)$(libdir)/libvdisk.so
	chmod 4644 $(DESTDIR)$(libdir)/libvdisk.so.0.0.0

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh header libvdisk
-include revision.dummy
