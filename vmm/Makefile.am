GEN = shell vmware kvm
vmmdir = $(pkgdatadir)/vmm
vmm_SCRIPTS = $(GEN)
dist_pkgdata_DATA = vmm.pm
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in)

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
