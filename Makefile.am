if WANT_CLIENT
CLIENTDIRS = client parcelkeeper kernel conf
endif

if WANT_SERVER
SERVERDIRS = locksrv
endif

if WANT_COMMON
COMMONDIRS = sqlite tools
endif

SUBDIRS = $(COMMONDIRS) $(CLIENTDIRS) $(SERVERDIRS) vmm
dist_noinst_SCRIPTS = mkrevision.sh autogen.sh
EXTRA_DIST  = LICENSE.Eclipse LICENSE.GPL LICENSE.LGPL CHANGES README.server
EXTRA_DIST += .gitrevision

# This is marked PHONY so that it will run unconditionally during "make dist";
# otherwise, we might distribute an obsolete .gitrevision.
.PHONY: .gitrevision
.gitrevision:
	$(top_srcdir)/mkrevision.sh $(top_builddir) update
