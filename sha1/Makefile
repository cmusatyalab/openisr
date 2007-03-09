ifneq ($(KERNELRELEASE),)

ifeq ($(ARCH),i386)
obj-m := sha1-i586.o
sha1-i586-objs := sha1-i586-asm.o sha1.o
endif

ifeq ($(ARCH),x86_64)
obj-m := sha1-x86_64.o
sha1-x86_64-objs := sha1-x86_64-asm.o sha1.o
endif

else

KMODS := sha1-i586.ko sha1-x86_64.ko
include ../kernel.mk

endif
