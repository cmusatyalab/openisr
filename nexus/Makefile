ifneq ($(KERNELRELEASE),)

include $(M)/Files.mk
obj-m := openisr.o
openisr-objs := $(NEXUS_OBJS)

else

KMODS := openisr.ko
include ../kernel.mk

REVISION_TYPE = object
REVISION_DIR = nexus
include ../mkrevision.mk

endif
