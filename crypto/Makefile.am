LIBTOOL_VERSION = 0:0:0

AM_CFLAGS=-W -Wall -Wstrict-prototypes -funroll-loops -fomit-frame-pointer
# autoconf puts a -O2 flag in CFLAGS which cannot be overridden by AM_CFLAGS
CFLAGS=@CFLAGS@ -O3

pkglib_LTLIBRARIES = libisrcrypto.la
libisrcrypto_la_SOURCES = aes.c blowfish.c cbc.c util.c wrapper.c
libisrcrypto_la_SOURCES += isrcrypto.h internal.h aes_tab.h blowfish_tab.h

# If the user passed --enable-static to configure, we still don't want to
# install a static version of the library, so make sure we kill it.
# Also, the library shouldn't be executable.  (Why is libtool setting
# libraries executable?)
install-exec-hook:
	rm -f $(DESTDIR)$(pkglibdir)/libisrcrypto.a
	chmod -x $(DESTDIR)$(pkglibdir)/libisrcrypto.so.*
