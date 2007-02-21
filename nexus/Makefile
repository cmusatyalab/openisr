ifneq ($(KERNELRELEASE),)

include $(M)/Files.mk
obj-m := openisr.o
openisr-objs := $(NEXUS_OBJS)

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
# the rule, and to recalculate its target selection afterward.
.PHONY: revision.dummy
revision.dummy:
	@$../mkrevision.sh object nexus
-include revision.dummy

endif
