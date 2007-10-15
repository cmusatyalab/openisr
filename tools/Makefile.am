AM_CPPFLAGS = -I$(top_srcdir)/sqlite -D_GNU_SOURCE
AM_CFLAGS = -W -Wall -Wstrict-prototypes -I..
AM_LDFLAGS = -L$(top_srcdir)/sqlite -lsqlite

GEN = upgrade-0.9.pl

if WANT_SERVER
SERVER_PROGS = zlib convert-chunks convert-keyring
pkgdata_SCRIPTS = upgrade-0.9.pl
endif

pkglib_PROGRAMS = query $(SERVER_PROGS)
CLEANFILES = $(SERVER_PROGS) $(GEN)
EXTRA_DIST = $(GEN:=.in)

convert_chunks_LDFLAGS = $(AM_LDFLAGS) -lcrypto -lz
zlib_LDFLAGS = -lz

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
