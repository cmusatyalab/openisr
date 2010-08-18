AM_CPPFLAGS = -I$(top_srcdir)/kernel/nexus -I..
AM_CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -W -Wall -Wstrict-prototypes

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
blobtool_LDFLAGS = -lisrcrypto $(glib_LIBS) -larchive
disktool_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS) $(NO_FIELD_INITIALIZER_WARNINGS)
disktool_LDFLAGS = $(glib_LIBS) -lisrsql -lisrutil
dirtometer_CFLAGS = $(AM_CFLAGS) $(gtk_CFLAGS) $(glib_CFLAGS)
dirtometer_CFLAGS += -Wno-unused-parameter $(NO_FIELD_INITIALIZER_WARNINGS)
dirtometer_LDFLAGS = $(gtk_LIBS) $(glib_LIBS)
query_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS)
query_LDFLAGS = $(glib_LIBS) -lisrsql
nextest_LDFLAGS = -lisrcrypto
hoardtest_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS)
hoardtest_LDFLAGS = $(glib_LIBS) -lisrcrypto -lisrsql

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk

postinst: post
	@chmod +x $(builddir)/post
	$(builddir)/post
