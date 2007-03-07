GEN = isr Isr.pm isr.1
bin_SCRIPTS = isr
pkgdata_DATA = Isr.pm
man_MANS = isr.1

dist_pkgdata_DATA = HTTPSSH.pm IsrConfigTie.pm IsrRevision.pm

CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in)

$(GEN): %: %.in Makefile
	@echo "Generating $@ from $<"
	@sed -e "s=!!LIBDIR!!=$(pkglibdir)=g" \
				-e "s=!!SHAREDIR!!=$(pkgdatadir)=g" \
				-e "s=!!SYSCONFDIR!!=$(pkgsysconfdir)=g" \
				-e "s=!!BINDIR!!=$(bindir)=g" \
				-e "s=!!VERSION!!=$(PACKAGE_VERSION)=g" $< > $@

REVISION_TYPE = perl
REVISION_DIR = client
include $(top_srcdir)/mkrevision.mk
