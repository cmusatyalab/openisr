SRVCMDS = catlog checkparcel commit getconfig lock ls motd rollback stat
SRVSCRIPTS = $(patsubst %, isr_srv_%.pl, $(SRVCMDS))

bin_SCRIPTS = isr_runserv
sbin_SCRIPTS = isr_admin
dist_pkgdata_DATA = Server.pm $(SRVSCRIPTS)

GEN = isr_runserv isr_admin
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) README

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
