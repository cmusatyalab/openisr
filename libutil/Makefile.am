AM_CPPFLAGS = -I$(top_srcdir)/crypto
AM_CFLAGS   = -W -Wall -Wstrict-prototypes $(VISIBILITY_HIDDEN) $(glib_CFLAGS)
AM_LDFLAGS  = -L$(top_builddir)/crypto -lisrcrypto $(glib_LIBS)

pkglib_LTLIBRARIES = libisrutil.la
libisrutil_la_SOURCES  = chunk.c
libisrutil_la_SOURCES += isrutil.h internal.h
