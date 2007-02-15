ifneq ($(KERNELRELEASE),)

ifeq ($(ARCH),x86_64)
obj-m := sha1-x86_64.o
sha1-x86_64-objs := sha1-x86_64-asm.o sha1.o
endif

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

.PHONY: install_modules
install_modules: module
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) INSTALL_MOD_PATH=$(DESTDIR) \
		INSTALL_MOD_DIR=openisr modules_install

ifneq ($(MAKELEVEL), 0)
.PHONY: distdir_version
distdir_version:
endif

endif
