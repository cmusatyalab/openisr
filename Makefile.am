if WANT_CLIENT
CLIENTDIRS = client vulpes conf
endif

# NOTE: We cannot support VPATH builds when WANT_MODULES is enabled, because
# Kbuild does not support VPATH builds for external modules.
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
