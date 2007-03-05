if WANT_CLIENT
CLIENTDIRS = client vulpes conf
endif

if WANT_LIBVDISK
VDISKDIR = libvdisk
endif

# Unconditionally descend into kernel directories: even if we didn't, the
# GNUmakefiles there would still need to condition their calls into Kbuild
# on WANT_MODULES or else distclean would break for VPATH builds.  Also, Nexus
# has tools it may want to build even if !WANT_MODULES.
SUBDIRS = $(CLIENTDIRS) $(VDISKDIR) nexus sha1
dist_noinst_SCRIPTS = mkrevision.sh
EXTRA_DIST  = LICENSE.Eclipse LICENSE.GPL LICENSE.LGPL CHANGES
EXTRA_DIST += debian openisr.spec

dist-hook:
	rm -rf $(distdir)/debian/.svn
