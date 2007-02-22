AM_CFLAGS=-W -Wall -Wstrict-prototypes -O2 -fno-strict-aliasing

# libvdisk will not work if it's not in /lib or /usr/lib, since it needs
# to be LD_PRELOADed into a setuid root program
sysexeclibdir = /usr/lib

sysexeclib_LTLIBRARIES = libvdisk.la
libvdisk_la_SOURCES = libvdisk.c revision.h

# If the user passed --enable-static to configure, it still doesn't make
# any sense to install a static version of the library, so make sure we
# kill it.  Also, no one should link a program against libvdisk, so get
# rid of libvdisk.la and the libvdisk.so symlink.  Finally, libvdisk
# needs to be setuid and not executable.  (Why is libtool setting
# libraries executable?)
install-exec-hook:
	rm -f $(DESTDIR)$(sysexeclibdir)/libvdisk.a \
				$(DESTDIR)$(sysexeclibdir)/libvdisk.la \
				$(DESTDIR)$(sysexeclibdir)/libvdisk.so
	chmod 4644 $(DESTDIR)$(sysexeclibdir)/libvdisk.so.0.0.0

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.
.PHONY: revision.dummy
revision.dummy:
	@$(top_srcdir)/mkrevision.sh header libvdisk
-include revision.dummy
