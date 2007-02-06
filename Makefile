BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib/openisr
SHAREDIR ?= /usr/share/openisr
MANDIR ?= /usr/share/man
SYSCONFDIR ?= /etc/openisr
export BINDIR LIBDIR SHAREDIR MANDIR SYSCONFDIR

DIRS = client vulpes libvdisk nexus sha1-i586 conf
DISTDIRS = $(DIRS) debian

# Make sure DESTDIR is an absolute path
ifneq ($(filter-out /%,$(strip $(DESTDIR))),)
override DESTDIR := $(CURDIR)/$(DESTDIR)
endif

TARGETS = all install clean install_revision
DIRTARGETS := $(foreach tgt,$(TARGETS),$(DIRS:=__$(tgt)))

.SECONDEXPANSION:
.PHONY: $(TARGETS)
$(TARGETS): $(DIRS:=__$$@)

.PHONY: $(DIRTARGETS)
$(DIRTARGETS):
	$(MAKE) -C $(subst __, ,$@) DESTDIR=$(DESTDIR)

.PHONY: distclient
distclient: distclient_tree install_revision

.PHONY: distclient_tree
distclient_tree:
	@set -e; \
	if [ -z "$(DESTDIR)" ] ; then \
		echo "You must specify \$$DESTDIR" ;\
		exit 1 ;\
	fi ;\
	for dir in . $(DISTDIRS) ; do \
		echo "Exporting $$dir" ;\
		svn export -q -N -rHEAD $$dir $(DESTDIR)/$$dir ;\
	done
