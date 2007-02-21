if WANT_CLIENT
CLIENTDIRS = client vulpes conf
endif

if WANT_MODULES
SHADIR = sha1
endif

if WANT_LIBVDISK
VDISKDIR = libvdisk
endif

# Unconditionally descend into nexus to pick up the tools
SUBDIRS = $(CLIENTDIRS) $(VDISKDIR) nexus $(SHADIR)
dist_noinst_SCRIPTS = mkrevision.sh
EXTRA_DIST = LICENSE.Eclipse LICENSE.GPL LICENSE.LGPL debian

dist-hook:
	rm -rf $(distdir)/debian/.svn
