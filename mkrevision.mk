# Makefile fragment to autogenerate revision.[ch]/IsrRevision.pm

top_srcdir ?= ..
top_builddir ?= $(top_srcdir)

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.
.PHONY: revision.dummy
revision.dummy:
	@$(top_srcdir)/mkrevision.sh update
-include revision.dummy

REVISION_FILE = $(top_srcdir)/.gitrevision
REVISION_DEPENDS = $(REVISION_FILE) $(top_builddir)/config.h
RCS_REVISION = $(shell cat $(REVISION_FILE))

revision.c: $(REVISION_DEPENDS)
	$(top_srcdir)/mkrevision.sh object

revision.h: $(REVISION_DEPENDS)
	$(top_srcdir)/mkrevision.sh header

IsrRevision.pm: $(REVISION_DEPENDS)
	$(top_srcdir)/mkrevision.sh perl

# Because of the way Automake builds its rules, Make >= 3.81 fails to build
# revision.o when both: 1. revision.c does not initially exist, and 2.
# .deps/revision.Po contains no dependency rules (i.e., is just a dummy file).
# To handle this case, we need to explicitly tell Make how to make revision.o.
revision.o: revision.c
