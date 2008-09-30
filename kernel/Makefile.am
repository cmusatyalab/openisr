include $(top_srcdir)/mkrevision.mk
include nexus/Files.mk

NEXUS_FILE_LIST = Makefile Files.mk $(NEXUS_OBJS:.o=.c) $(NEXUS_HDRS)
SHA1_FILE_LIST = Makefile sha1.c sha1-i586-asm.S sha1-x86_64-asm.S
NEXUS_FILES = $(foreach file,$(NEXUS_FILE_LIST),$(srcdir)/nexus/$(file))
SHA1_FILES = $(foreach file,$(SHA1_FILE_LIST),$(srcdir)/sha1/$(file))
NEXUS_DIST_FILES = $(NEXUS_FILES) nexus/HACKING
SHA1_DIST_FILES = $(SHA1_FILES)

pkgdata_DATA = openisr-modules.tar.gz
MOSTLYCLEANFILES = openisr-modules.tar.gz
EXTRA_DIST  = $(NEXUS_DIST_FILES) $(SHA1_DIST_FILES) common.mk wrapper.mk

TOP_FILES = $(srcdir)/common.mk $(top_srcdir)/mkrevision.sh $(REVISION_DEPENDS)
COPY_DIR = mkdir -p openisr-modules/$(1) && cp $(2) openisr-modules/$(1)/
openisr-modules.tar.gz: $(NEXUS_FILES) $(SHA1_FILES) $(TOP_FILES) wrapper.mk
	rm -rf openisr-modules
	$(call COPY_DIR,nexus,$(NEXUS_FILES))
	$(call COPY_DIR,sha1,$(SHA1_FILES))
	cp $(TOP_FILES) openisr-modules/
	cp $(srcdir)/wrapper.mk openisr-modules/Makefile
	tar czf $@ openisr-modules
	rm -rf openisr-modules
