AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I$(top_srcdir)/sqlite -I..
AM_CPPFLAGS += -I$(top_srcdir)/crypto -D_GNU_SOURCE
AM_CFLAGS = -W -Wall -Wstrict-prototypes
CRYPTO_LIBS = -L$(top_builddir)/crypto -lisrcrypto

GEN = openisr-config openisr-config.8

if WANT_CLIENT
CLIENTPROGS = dirtometer readstats nexus_debug
dist_pkgdata_DATA = modbuild.pm
sbin_SCRIPTS = openisr-config
man_MANS = openisr-config.8
endif

pkglib_PROGRAMS = query blobtool $(CLIENTPROGS)
EXTRA_PROGRAMS = nextest
CLEANFILES = $(GEN) nextest
EXTRA_DIST = $(GEN:=.in)

blobtool_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS) -Wno-missing-field-initializers
blobtool_LDFLAGS = $(CRYPTO_LIBS) $(glib_LIBS) -lz
dirtometer_CFLAGS = $(AM_CFLAGS) $(gtk_CFLAGS) $(glib_CFLAGS)
dirtometer_CFLAGS += -Wno-unused-parameter -Wno-missing-field-initializers
dirtometer_LDFLAGS = $(gtk_LIBS) $(glib_LIBS)
query_LDFLAGS = -L$(top_builddir)/sqlite -lsqlite
nextest_LDFLAGS = $(CRYPTO_LIBS)

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
