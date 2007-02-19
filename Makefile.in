BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib/openisr
SHAREDIR ?= /usr/share/openisr
MANDIR ?= /usr/share/man
SYSCONFDIR ?= /etc/openisr
export BINDIR LIBDIR SHAREDIR MANDIR SYSCONFDIR

MODULEDIRS := nexus sha1
SRCDIRS := client vulpes libvdisk $(MODULEDIRS) conf
OTHERDIRS := debian
DIRS := $(SRCDIRS) $(OTHERDIRS)

# Make sure DESTDIR is an absolute path
ifneq ($(filter-out /%,$(strip $(DESTDIR))),)
override DESTDIR := $(CURDIR)/$(DESTDIR)
endif

TARGETS = all install clean distdir_version install_modules
DIRTARGETS := $(foreach tgt,$(TARGETS),$(SRCDIRS:=__$(tgt)))
SRCDISTTARGETS := $(SRCDIRS:=__distdir)
OTHERDISTTARGETS := $(OTHERDIRS:=__distdir) root__distdir
DISTTARGETS := $(SRCDISTTARGETS) $(OTHERDISTTARGETS)

.SECONDEXPANSION:
.PHONY: $(TARGETS)
$(TARGETS): $(SRCDIRS:=__$$@)

.PHONY: clean_modules
clean_modules: $(MODULEDIRS:=__clean)

.PHONY: $(DIRTARGETS)
$(DIRTARGETS):
	$(MAKE) -C $(subst __, ,$@) DESTDIR=$(DESTDIR)

.PHONY: distclient
distclient: root__distdir $(DIRS:=__distdir)

.PHONY: distmodules
distmodules: root__distdir $(MODULEDIRS:=__distdir)

.PHONY: $(SRCDISTTARGETS) $(OTHERDISTTARGETS)
$(SRCDISTTARGETS): $$@_copy $$@_version
$(OTHERDISTTARGETS): $$@_copy

.PHONY: $(DISTTARGETS:=_copy)
$(DISTTARGETS:=_copy):
	@set -e; \
	if [ -z "$(DESTDIR)" ] ; then \
		echo "You must specify \$$DESTDIR" ;\
		exit 1 ;\
	fi ;\
	dir=$(word 1,$(subst __, ,$@)) ;\
	[ "$$dir" = "root" ] && dir=. || true ;\
	echo "Exporting $$dir" ;\
	svn export -q -N -rHEAD $$dir $(DESTDIR)/$$dir
