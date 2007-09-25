GEN = isr isr.1
bin_SCRIPTS = isr
man_MANS = isr.1

CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in)

include $(top_srcdir)/mkrevision.mk

$(GEN): %: %.in Makefile $(REVISION_DEPENDS)
	@echo "Generating $@ from $<"
	@sed -e "s=!!LIBDIR!!=$(pkglibdir)=g" \
				-e "s=!!SHAREDIR!!=$(pkgdatadir)=g" \
				-e "s=!!SYSCONFDIR!!=$(pkgsysconfdir)=g" \
				-e "s=!!BINDIR!!=$(bindir)=g" \
				-e "s=!!VERSION!!=$(PACKAGE_VERSION)=g" \
				-e "s=!!REVISION!!=$(RCS_REVISION)=g" $< > $@
