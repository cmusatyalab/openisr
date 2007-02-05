BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib/openisr
SHAREDIR ?= /usr/share/openisr
SYSCONFDIR ?= /etc/openisr
export DESTDIR BINDIR LIBDIR SHAREDIR SYSCONFDIR

DIRS = client vulpes libvdisk nexus sha1-i586 conf
DISTDIRS = $(DIRS) debian

# Make sure DESTDIR is an absolute path
ifneq ($(filter-out /%,$(strip $(DESTDIR))),)
DESTDIR := $(CURDIR)/$(DESTDIR)
endif

TARGETS = all install clean install_revision
DIRTARGETS := $(foreach tgt,$(TARGETS),$(DIRS:=__$(tgt)))

.PHONY: $(TARGETS)
$(TARGETS): $(DIRS:=__$$@)

.PHONY: $(DIRTARGETS)
$(DIRTARGETS):
	$(MAKE) -C $(subst __, ,$@)

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
