LIBTOOL_VERSION = 0:0:0

AM_CFLAGS=-W -Wall -Wstrict-prototypes -funroll-loops -fomit-frame-pointer
# autoconf puts a -O2 flag in CFLAGS which cannot be overridden by AM_CFLAGS
CFLAGS=@CFLAGS@ -O3

if HAVE_VISIBILITY
AM_CFLAGS += -fvisibility=hidden
endif

pkglib_LTLIBRARIES = libisrcrypto.la
libisrcrypto_la_SOURCES = aes.c blowfish.c cbc.c util.c wrapper.c
libisrcrypto_la_SOURCES += isrcrypto.h internal.h aes_tab.h blowfish_tab.h
