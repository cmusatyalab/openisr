SRVCMDS = catlog checkparcel commit getconfig lock ls motd rollback stat
SRVSCRIPTS = $(patsubst %, isr_srv_%.pl, $(SRVCMDS))

bin_SCRIPTS = isr_runserv
sbin_SCRIPTS = isr_admin
dist_pkgdata_DATA = Server.pm $(SRVSCRIPTS)

GEN = isr_runserv isr_admin
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) README

include $(top_srcdir)/mkrevision.mk

$(GEN): %: %.in Makefile $(REVISION_DEPENDS)
	@echo "Generating $@ from $<"
	@sed -e "s=!!LIBDIR!!=$(pkglibdir)=g" \
				-e "s=!!SHAREDIR!!=$(pkgdatadir)=g" \
				-e "s=!!SYSCONFDIR!!=$(pkgsysconfdir)=g" \
				-e "s=!!BINDIR!!=$(bindir)=g" \
				-e "s=!!VERSION!!=$(PACKAGE_VERSION)=g" \
				-e "s=!!REVISION!!=$(RCS_REVISION)=g" $< > $@
