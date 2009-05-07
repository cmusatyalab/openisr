LIBTOOL_VERSION = 0:0:0

AM_CFLAGS  = -W -Wall -Wstrict-prototypes -funroll-loops -fomit-frame-pointer
AM_CFLAGS += $(VISIBILITY_HIDDEN)
# autoconf puts a -O2 flag in CFLAGS which cannot be overridden by AM_CFLAGS
CFLAGS=@CFLAGS@ -O3
AM_LDFLAGS = -lgmp

pkglib_LTLIBRARIES = libisrcrypto.la
libisrcrypto_la_SOURCES = aes.c blowfish.c cbc.c cipher.c ecb.c hash.c hmac.c
libisrcrypto_la_SOURCES += mac.c md5.c md5-compress.c pad.c random.c sha1.c
libisrcrypto_la_SOURCES += util.c
libisrcrypto_la_SOURCES += isrcrypto.h internal.h
libisrcrypto_la_SOURCES += aes_tab.h blowfish_tab.h

if HAVE_X86_64
libisrcrypto_la_SOURCES += sha1-compress-amd64.S
else
if HAVE_X86_32
libisrcrypto_la_SOURCES += sha1-compress-ia32.S
else
libisrcrypto_la_SOURCES += sha1-compress.c
endif
endif

SUBDIRS = . test
