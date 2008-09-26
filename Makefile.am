if WANT_CLIENT
CLIENTDIRS = client parcelkeeper conf
endif

if WANT_SERVER
SERVERDIRS = locksrv
endif

if WANT_LIBVDISK
VDISKDIR = libvdisk
endif

if WANT_COMMON
COMMONDIRS = sqlite tools
endif

# Unconditionally descend into kernel directories: even if we didn't, the
# GNUmakefiles there would still need to condition their calls into Kbuild
# on WANT_MODULES or else distclean would break for VPATH builds.  Also, Nexus
# has tools it may want to build even if !WANT_MODULES.
SUBDIRS = $(COMMONDIRS) $(CLIENTDIRS) $(SERVERDIRS) $(VDISKDIR) nexus sha1 vmm
dist_noinst_SCRIPTS = mkrevision.sh autogen.sh
EXTRA_DIST  = LICENSE.Eclipse LICENSE.GPL LICENSE.LGPL CHANGES kernel.mk
EXTRA_DIST += .gitrevision README.server

# dist-gzip appears to rebuild the tarball whenever it is run (though the
# generated Makefile seems to indicate that this shouldn't happen).  Thus
# we only generate the tarball when we're actually doing the install (and
# remove it afterward), rather than generating it during the build.
if WANT_MODULE_SOURCE
install-data-local: dist-gzip
	$(INSTALL_DATA) openisr-$(VERSION).tar.gz \
				$(DESTDIR)$(pkgdatadir)/openisr.tar.gz
	rm -f openisr-$(VERSION).tar.gz
endif

# This is marked PHONY so that it will run unconditionally during "make dist";
# otherwise, we might distribute an obsolete .gitrevision.
.PHONY: .gitrevision
.gitrevision:
	$(top_srcdir)/mkrevision.sh update
