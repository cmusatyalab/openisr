AM_CFLAGS=-W -Wall -Wstrict-prototypes -fno-strict-aliasing
AM_LDFLAGS= -ldl

include $(top_srcdir)/mkrevision.mk
BUILT_SOURCES = revision.h

# libvdisk will not work if it's not in /lib or /usr/lib, since it needs
# to be LD_PRELOADed into a setuid root program
sysexeclibdir = $(LIBVDISK_DIRPATH)
sysexeclib_LTLIBRARIES = libvdisk.la
libvdisk_la_SOURCES = libvdisk.c
nodist_libvdisk_la_SOURCES = revision.h

if LIBVDISK_BUILD_32
sysexeclib32dir = $(LIBVDISK_DIRPATH_32)
sysexeclib32_LTLIBRARIES = 32/libvdisk.la
32_libvdisk_la_SOURCES = libvdisk.c
nodist_32_libvdisk_la_SOURCES = revision.h
32_libvdisk_la_CFLAGS = $(AM_CFLAGS) -m32
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
