BINDIR=$(HOME)/bin
LIBDIR=$(HOME)/bin
SHAREDIR=$(HOME)/bin
SYSCONFDIR=$(HOME)/bin

GEN=isr Isr.pm
PM=Isr.pm HTTPSSH.pm IsrConfigTie.pm IsrRevision.pm

.PHONY: all
all: $(GEN)

%: %.in
	@echo "Generating $@ from $^"
	@sed -e "s=!!LIBDIR!!=$(LIBDIR)=g" -e "s=!!SHAREDIR!!=$(SHAREDIR)=g" \
				-e "s=!!SYSCONFDIR!!=$(SYSCONFDIR)=g" $^ > $@
	@[ $@ = "isr" ] && chmod +x $@ || true

.PHONY: clean
clean:
	rm -f $(GEN)

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh perl client
-include revision.dummy

install: all
	install -d $(BINDIR) $(SHAREDIR)
	install -m 755 isr $(BINDIR)
	install -m 644 $(PM) $(SHAREDIR)
