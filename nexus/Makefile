ifneq ($(KERNELRELEASE),)

include $(M)/Files.mk
obj-m := openisr.o
openisr-objs := $(NEXUS_OBJS)

else

KMODS := openisr.ko

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
# utsrelease.h for >= 2.6.18, version.h for < 2.6.18
KERN_RELEASE := $(shell grep -s UTS_RELEASE \
		$(KERNELDIR)/include/linux/version.h \
		$(KERNELDIR)/include/linux/utsrelease.h | cut -f2 -d\")

.PHONY: module
module: check_config
	@$(MAKE) -C $(KERNELDIR) M=$(CURDIR) modules

.PHONY: clean
clean: check_config
	@$(MAKE) -C $(KERNELDIR) M=$(CURDIR) clean


.PHONY: install
# Recent kernels automatically run depmod.  If we're using a DESTDIR,
# we don't want the depmod files installed, but if we're not (or the DESTDIR
# is a chroot or somesuch), we don't want to delete them.  So, we only delete
# them if they weren't there before we started.
install: NEED_CLEAR := $(shell [ -f \
			$(DESTDIR)/lib/modules/$(KERN_RELEASE)/modules.dep ] \
			|| echo 1)
install: check_config module
	@$(MAKE) -C $(KERNELDIR) M=$(CURDIR) INSTALL_MOD_PATH=$(DESTDIR) \
		INSTALL_MOD_DIR=openisr modules_install
	@[ "$(NEED_CLEAR)" = "1" ] && \
		rm -f $(DESTDIR)/lib/modules/$(KERN_RELEASE)/modules.* || true


.PHONY: uninstall
uninstall: check_config
	@rm -f $(foreach mod,$(KMODS),$(DESTDIR)/lib/modules/$(KERN_RELEASE)/openisr/$(mod))

.PHONY: installdirs
installdirs: check_config
	@mkdir -p $(DESTDIR)/lib/modules/$(KERN_RELEASE)/openisr

.PHONY: check_config
check_config:
ifeq ($(KERN_RELEASE),)
	@echo "Kernel tree at $(KERNELDIR) not configured"
	@exit 1
endif

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh object nexus
-include revision.dummy

endif
