GEN = shell vmware kvm virtualbox
vmmdir = $(pkgdatadir)/vmm
vmm_SCRIPTS = $(GEN)
dist_pkgdata_DATA = vmm.pm vmm.py
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in)

SUBDIRS = . xpcom

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
