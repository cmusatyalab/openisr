include $(top_srcdir)/vmm.mk

GEN = shell $(ALL_VMMS)
CLEANFILES = $(GEN) vmm.pyc
EXTRA_DIST = $(GEN:=.in)
vmmdir = $(pkgdatadir)/vmm

if WANT_CLIENT
VMM_SHELL = shell
dist_pkgdata_DATA = vmm.pm vmm.py
endif

if WANT_VBOX_XPCOM
XPCOM = xpcom
endif

vmm_SCRIPTS = $(VMM_SHELL) $(VMMS)
EXTRA_SCRIPTS = $(ALL_VMMS)

SUBDIRS = . $(XPCOM)

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
