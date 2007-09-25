ifneq ($(KERNELRELEASE),)

include $(M)/Files.mk
obj-m := openisr.o
openisr-objs := $(NEXUS_OBJS) revision.o

else

include ../mkrevision.mk

MOD_DEPENDS := revision.c
KMODS := openisr.ko
include ../kernel.mk

endif
