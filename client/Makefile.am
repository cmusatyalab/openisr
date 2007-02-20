bin_SCRIPTS = isr
pkgdata_SCRIPTS = Isr.pm HTTPSSH.pm IsrConfigTie.pm IsrRevision.pm
man_MANS = isr.1

GEN = isr Isr.pm isr.1

MOSTLYCLEANFILES = $(GEN)

$(GEN): %: %.in Makefile
	@echo "Generating $@ from $<"
	@sed -e "s=!!LIBDIR!!=$(pkglibdir)=g" \
				-e "s=!!SHAREDIR!!=$(pkgdatadir)=g" \
				-e "s=!!SYSCONFDIR!!=$(sysconfdir)/openisr=g" \
				-e "s=!!BINDIR!!=$(bindir)=g" $< > $@
	@[ $@ = "isr" ] && chmod +x $@ || true

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh perl client
-include revision.dummy
