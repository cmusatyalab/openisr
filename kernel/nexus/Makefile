ifneq ($(KERNELRELEASE),)

include $(M)/Files.mk
obj-m := openisr.o
openisr-objs := $(NEXUS_OBJS) revision.o

else

MOD_DEPENDS := revision.c
KMODS := openisr.ko
include ../common.mk

# If we're being built inside the full OpenISR source tree, update the
# top-level .gitrevision before using it.  Otherwise, don't.
top_srcdir := ../..
-include ../../mkrevision.mk

# If we just included mkrevision.mk, don't (incorrectly) redefine the rule
# for building revision.c.  If we didn't, we need a rule.
$(if $(REVISION_DEPENDS),dummy,revision.c): ../.gitrevision ../config.h
	../mkrevision.sh object

endif
