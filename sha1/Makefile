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

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) modules

.PHONY: clean
clean:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) clean

.PHONY: install_modules
install_modules: module
	@$(MAKE) -C $(KERNELDIR) M=$(CURDIR) INSTALL_MOD_PATH=$(DESTDIR) \
		INSTALL_MOD_DIR=openisr modules_install

endif
