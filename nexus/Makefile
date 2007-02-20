ifneq ($(KERNELRELEASE),)

obj-m := openisr.o
openisr-objs := init.o request.o chunkdata.o chardev.o transform.o lzf.o
openisr-objs += sysfs.o thread.o revision.o 

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

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh object nexus
-include revision.dummy

ifneq ($(MAKELEVEL), 0)
.PHONY: distdir_version
distdir_version:
	install -m 644 revision.c $(DESTDIR)/nexus/
endif

endif
