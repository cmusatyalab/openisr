ifneq ($(KERNELRELEASE),)

obj-m := sha1-i386.o
sha1-i386-objs := sha1-i386-asm.o sha1.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all
all: assembly module

.PHONY: assembly
assembly:
	m4 sha1-compress.asm > sha1-i386-asm.S

.PHONY: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif
