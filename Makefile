DESTDIR ?= dest
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib/openisr
SHAREDIR ?= /usr/share/openisr
SYSCONFDIR ?= /etc/openisr
export DESTDIR BINDIR LIBDIR SHAREDIR SYSCONFDIR

DIRS = client vulpes libvdisk nexus sha1-i586

# Make sure DESTDIR is an absolute path
ifneq ($(filter-out /%,$(strip $(DESTDIR))),)
DESTDIR := $(CURDIR)/$(DESTDIR)
endif

TARGETS = all install clean
DIRTARGETS := $(foreach tgt,$(TARGETS),$(DIRS:=__$(tgt)))

.PHONY: $(TARGETS)
$(TARGETS): $(DIRS:=__$$@)

.PHONY: $(DIRTARGETS)
$(DIRTARGETS):
	$(MAKE) -C $(subst __, ,$@)
