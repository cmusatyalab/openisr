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
				-e "s=!!SYSCONFDIR!!=$(sysconfdir)/openisr=g" \
				-e "s=!!BINDIR!!=$(bindir)=g" $< > $@

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh perl client
-include revision.dummy
