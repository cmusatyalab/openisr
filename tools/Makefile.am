AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I$(top_srcdir)/sqlite -I..
AM_CPPFLAGS += -D_GNU_SOURCE
AM_CFLAGS = -W -Wall -Wstrict-prototypes
SQLITE_LIBFLAGS = -L$(top_srcdir)/sqlite -lsqlite

GEN = openisr-config openisr-config.8 upgrade-0.9.pl dirtometer

if WANT_SERVER
SERVERPROGS = zlib convert-chunks convert-keyring
SERVERSCRIPTS = upgrade-0.9.pl
endif

if WANT_CLIENT
CLIENTPROGS = readstats nexus_debug
CLIENTSCRIPTS = dirtometer
sbin_SCRIPTS = openisr-config
man_MANS = openisr-config.8
endif

pkglib_PROGRAMS = query $(SERVERPROGS) $(CLIENTPROGS)
pkgdata_SCRIPTS = $(SERVERSCRIPTS) $(CLIENTSCRIPTS)
EXTRA_PROGRAMS = nextest
CLEANFILES = $(GEN) nextest
EXTRA_DIST = $(GEN:=.in)

convert_chunks_LDFLAGS = $(SQLITE_LIBFLAGS) -lcrypto -lz
convert_keyring_LDFLAGS = $(SQLITE_LIBFLAGS)
query_LDFLAGS = $(SQLITE_LIBFLAGS)
nextest_LDFLAGS = -lcrypto
zlib_LDFLAGS = -lz

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
