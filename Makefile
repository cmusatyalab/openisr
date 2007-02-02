DESTDIR ?= dest
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib/openisr
SHAREDIR ?= /usr/share/openisr
SYSCONFDIR ?= /etc/openisr
export DESTDIR BINDIR LIBDIR SHAREDIR SYSCONFDIR

DIRS = client vulpes libvdisk nexus sha1-i586

ifneq ($(strip $(DESTDIR)),)
# Make sure DESTDIR is an absolute path
$(shell install -d $(DESTDIR))
DESTDIR := $(shell cd $(DESTDIR) ; pwd)
endif

TARGETS = all install clean
DIRTARGETS := $(foreach tgt,$(TARGETS),$(DIRS:=__$(tgt)))

.PHONY: $(TARGETS)
$(TARGETS): $(DIRS:=__$$@)

.PHONY: $(DIRTARGETS)
$(DIRTARGETS):
	$(MAKE) -C $(subst __, ,$@)
