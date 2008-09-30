# Top-level Makefile for kernel source tarball

SUBDIRS = nexus sha1
TARGETS = module clean install

.PHONY: $(TARGETS)
$(TARGETS):
	@$(foreach dir,$(SUBDIRS),make -C $(dir) $@ && ) true
