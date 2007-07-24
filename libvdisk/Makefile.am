AM_CFLAGS=-W -Wall -Wstrict-prototypes -fno-strict-aliasing
AM_LDFLAGS= -ldl

SOURCEFILES = libvdisk.c revision.h

# libvdisk will not work if it's not in /lib or /usr/lib, since it needs
# to be LD_PRELOADed into a setuid root program
sysexeclibdir = /usr/lib
sysexeclib_LTLIBRARIES = libvdisk.la
libvdisk_la_SOURCES = $(SOURCEFILES)

if LIBVDISK_BUILD_32
sysexeclib32dir = /usr/lib32
sysexeclib32_LTLIBRARIES = 32/libvdisk.la
32_libvdisk_la_SOURCES = $(SOURCEFILES)
32_libvdisk_la_CFLAGS = -m32
endif

# If the user passed --enable-static to configure, it still doesn't make
# any sense to install a static version of the library, so make sure we
# kill it.  Also, no one should link a program against libvdisk, so get
# rid of libvdisk.la and the libvdisk.so symlink.  Finally, libvdisk
# needs to be setuid and not executable.  (Why is libtool setting
# libraries executable?)
do_install = rm -f $(1)/libvdisk.a $(1)/libvdisk.la $(1)/libvdisk.so && \
			chmod 4644 $(1)/libvdisk.so.0.0.0

# Automake handles "make uninstall" through libtool, but we never installed
# libvdisk.la, so libtool fails to complete the uninstall.
do_uninstall = rm -f $(1)/libvdisk.so.0 $(1)/libvdisk.so.0.0.0

if LIBVDISK_BUILD_32
install-exec-hook:
	$(call do_install,$(DESTDIR)$(sysexeclibdir))
	$(call do_install,$(DESTDIR)$(sysexeclib32dir))

uninstall-local:
	$(call do_uninstall,$(DESTDIR)$(sysexeclibdir))
	$(call do_uninstall,$(DESTDIR)$(sysexeclib32dir))
else
install-exec-hook:
	$(call do_install,$(DESTDIR)$(sysexeclibdir))

uninstall-local:
	$(call do_uninstall,$(DESTDIR)$(sysexeclibdir))
endif

REVISION_TYPE = header
REVISION_DIR = libvdisk
include $(top_srcdir)/mkrevision.mk
