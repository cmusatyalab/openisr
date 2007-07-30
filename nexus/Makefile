ifneq ($(KERNELRELEASE),)

include $(M)/Files.mk
obj-m := openisr.o
openisr-objs := $(NEXUS_OBJS) revision.o

else

KMODS := openisr.ko
include ../kernel.mk

REVISION_TYPE = object
include ../mkrevision.mk

endif
