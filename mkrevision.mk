# Makefile fragment to autogenerate revision.[ch]/IsrRevision.pm

top_srcdir ?= ..

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.
.PHONY: revision.dummy
revision.dummy:
	@$(top_srcdir)/mkrevision.sh $(REVISION_TYPE)
-include revision.dummy

# Because of the way Automake builds its rules, Make >= 3.81 fails to build
# revision.o when both: 1. revision.c does not initially exist, and 2.
# .deps/revision.Po contains no dependency rules (i.e., is just a dummy file).
# To handle this case, we need to explicitly tell Make how to make revision.o.
revision.o: revision.c
