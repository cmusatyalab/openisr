AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I$(top_srcdir)/sqlite -I..
AM_CPPFLAGS += -D_GNU_SOURCE
AM_CFLAGS = -W -Wall -Wstrict-prototypes

GEN = openisr-config openisr-config.8

if WANT_SERVER
SERVERPROGS = zlib
endif

if WANT_CLIENT
CLIENTPROGS = dirtometer readstats nexus_debug
dist_pkgdata_DATA = modbuild.pm
sbin_SCRIPTS = openisr-config
man_MANS = openisr-config.8
endif

pkglib_PROGRAMS = query $(SERVERPROGS) $(CLIENTPROGS)
EXTRA_PROGRAMS = nextest
CLEANFILES = $(GEN) nextest
EXTRA_DIST = $(GEN:=.in)

dirtometer_CFLAGS = $(AM_CFLAGS) $(gtk_CFLAGS) $(glib_CFLAGS)
dirtometer_CFLAGS += -Wno-unused-parameter -Wno-missing-field-initializers
dirtometer_LDFLAGS = $(gtk_LIBS) $(glib_LIBS)
query_LDFLAGS = -L$(top_builddir)/sqlite -lsqlite
nextest_LDFLAGS = -lcrypto
zlib_LDFLAGS = -lz

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
