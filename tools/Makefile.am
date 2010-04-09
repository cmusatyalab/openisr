AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I$(top_srcdir)/sqlite -I..
AM_CPPFLAGS += -I$(top_srcdir)/crypto -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -W -Wall -Wstrict-prototypes
SQL_LIBS = -L$(top_builddir)/sqlite -lisrsql
CRYPTO_LIBS = -L$(top_builddir)/crypto -lisrcrypto

GEN = openisr-config openisr-config.8 post set_device_owner viewer

if WANT_CLIENT
CLIENTPROGS = dirtometer readstats nexus_debug
dist_pkgdata_DATA = modbuild.pm
pkgdata_SCRIPTS = set_device_owner viewer
sbin_SCRIPTS = openisr-config
man_MANS = openisr-config.8
noinst_SCRIPTS = post
endif

if WANT_SERVER
SERVERPROGS = disktool
endif

pkglib_PROGRAMS = query blobtool $(CLIENTPROGS) $(SERVERPROGS)
EXTRA_PROGRAMS = nextest hoardtest
CLEANFILES = $(GEN) nextest hoardtest
EXTRA_DIST = $(GEN:=.in)

blobtool_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS) $(NO_FIELD_INITIALIZER_WARNINGS)
blobtool_LDFLAGS = $(CRYPTO_LIBS) $(glib_LIBS) -larchive
disktool_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS) $(NO_FIELD_INITIALIZER_WARNINGS)
disktool_LDFLAGS = $(CRYPTO_LIBS) $(glib_LIBS) $(SQL_LIBS)
dirtometer_CFLAGS = $(AM_CFLAGS) $(gtk_CFLAGS) $(glib_CFLAGS)
dirtometer_CFLAGS += -Wno-unused-parameter $(NO_FIELD_INITIALIZER_WARNINGS)
dirtometer_LDFLAGS = $(gtk_LIBS) $(glib_LIBS)
query_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS)
query_LDFLAGS = $(glib_LIBS) $(SQL_LIBS)
nextest_LDFLAGS = $(CRYPTO_LIBS)
hoardtest_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS)
hoardtest_LDFLAGS = $(glib_LIBS) $(CRYPTO_LIBS) $(SQL_LIBS)

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk

postinst: post
	@chmod +x $(builddir)/post
	$(builddir)/post
