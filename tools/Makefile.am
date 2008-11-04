AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I$(top_srcdir)/sqlite -I..
AM_CPPFLAGS += -D_GNU_SOURCE
AM_CFLAGS = -W -Wall -Wstrict-prototypes
SQLITE_LIBFLAGS = -L$(top_builddir)/sqlite -lsqlite

GEN = openisr-config openisr-config.8 upgrade-0.9.pl

if WANT_SERVER
SERVERPROGS = zlib convert-chunks convert-keyring
SERVERSCRIPTS = upgrade-0.9.pl
endif

if WANT_CLIENT
CLIENTPROGS = dirtometer readstats nexus_debug
dist_pkgdata_DATA = modbuild.pm
sbin_SCRIPTS = openisr-config
man_MANS = openisr-config.8
endif

pkglib_PROGRAMS = query $(SERVERPROGS) $(CLIENTPROGS)
pkgdata_SCRIPTS = $(SERVERSCRIPTS)
EXTRA_PROGRAMS = nextest
CLEANFILES = $(GEN) nextest
EXTRA_DIST = $(GEN:=.in)

convert_chunks_LDFLAGS = $(SQLITE_LIBFLAGS) -lcrypto -lz
convert_keyring_LDFLAGS = $(SQLITE_LIBFLAGS)
dirtometer_CFLAGS = $(AM_CFLAGS) $(gtk_CFLAGS) $(glib_CFLAGS)
dirtometer_CFLAGS += -Wno-unused-parameter
dirtometer_LDFLAGS = $(gtk_LIBS) $(glib_LIBS)
query_LDFLAGS = $(SQLITE_LIBFLAGS)
nextest_LDFLAGS = -lcrypto
zlib_LDFLAGS = -lz

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
