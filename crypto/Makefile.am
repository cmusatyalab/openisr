LIBTOOL_VERSION = 0:0:0

AM_CFLAGS  = -W -Wall -Wstrict-prototypes -funroll-loops -fomit-frame-pointer
AM_CFLAGS += $(VISIBILITY_HIDDEN) $(libtasn1_CFLAGS)
# autoconf puts a -O2 flag in CFLAGS which cannot be overridden by AM_CFLAGS
CFLAGS=@CFLAGS@ -O3
AM_LDFLAGS = -lgmp $(libtasn1_LIBS)

pkglib_LTLIBRARIES = libisrcrypto.la
libisrcrypto_la_SOURCES = aes.c blowfish.c cbc.c cipher.c ecb.c hash.c hmac.c
libisrcrypto_la_SOURCES += mac.c md5.c md5-compress.c pad.c random.c sha1.c
libisrcrypto_la_SOURCES += sign.c util.c gmp.c der.c rsa.c
libisrcrypto_la_SOURCES += isrcrypto.h internal.h
libisrcrypto_la_SOURCES += aes_tab.h blowfish_tab.h
nodist_libisrcrypto_la_SOURCES = rsa-key-tab.c
CLEANFILES = rsa-key-tab.c
EXTRA_DIST = rsa-key.asn1

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

%-tab.c: %.asn1
	$(ASN1PARSER) -n $(subst -,_,$(basename $(notdir $<)))_asn1_tab \
		-o $@.tmp $<
	sed -e "s/^extern //" $@.tmp > $@
	rm $@.tmp
