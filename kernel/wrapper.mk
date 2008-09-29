# Top-level Makefile for kernel source tarball

SUBDIRS = nexus sha1
SUBMAKE = @$(foreach dir,$(SUBDIRS),make -C $(dir) $(1) && ) true

.PHONY: module
module:
	$(call SUBMAKE,module)

.PHONY: clean
clean:
	$(call SUBMAKE,clean)

.PHONY: install
install:
	$(call SUBMAKE,install)

.PHONY: uninstall
uninstall:
	$(call SUBMAKE,uninstall)
