ifneq ($(KERNELRELEASE),)

ifeq ($(CONFIG_X86),y)
ifeq ($(CONFIG_64BIT),y)
obj-m := sha1-x86_64.o
sha1-x86_64-objs := sha1-x86_64-asm.o sha1.o
else
obj-m := sha1-i586.o
sha1-i586-objs := sha1-i586-asm.o sha1.o
endif
endif

else

KMODS := sha1-i586.ko sha1-x86_64.ko
include ../common.mk

endif
