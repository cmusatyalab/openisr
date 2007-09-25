GEN = isr isr.1
bin_SCRIPTS = isr
man_MANS = isr.1

dist_pkgdata_DATA = IsrConfigTie.pm
pkgdata_DATA = IsrRevision.pm

CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in)

$(GEN): %: %.in Makefile
	@echo "Generating $@ from $<"
	@sed -e "s=!!LIBDIR!!=$(pkglibdir)=g" \
				-e "s=!!SHAREDIR!!=$(pkgdatadir)=g" \
				-e "s=!!SYSCONFDIR!!=$(pkgsysconfdir)=g" \
				-e "s=!!BINDIR!!=$(bindir)=g" \
				-e "s=!!VERSION!!=$(PACKAGE_VERSION)=g" $< > $@

include $(top_srcdir)/mkrevision.mk
