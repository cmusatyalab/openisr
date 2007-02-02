ifneq ($(KERNELRELEASE),)

obj-m := sha1-i586.o
sha1-i586-objs := sha1-i586-asm.o sha1.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

.PHONY: all
all: module

.PHONY: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

.PHONY: install
install:

endif
