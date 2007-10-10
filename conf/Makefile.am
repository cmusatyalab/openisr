initexecdir = ${sysconfdir}/init.d
udevdir = ${sysconfdir}/udev
udevrulesdir = ${udevdir}/rules.d

dist_pkgdata_DATA = config
dist_udev_DATA = openisr.rules
initexec_SCRIPTS = openisr.init
sbin_SCRIPTS = openisr-config

# Dummy variables to cause directories to be created
dist_pkgsysconf_DATA = 
dist_udevrules_DATA = 

GEN = openisr.init openisr-config
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) magic

$(GEN): %: %.in Makefile
	@echo "Generating $@ from $<"
	@sed -e "s=!!LIBDIR!!=$(pkglibdir)=g" \
				-e "s=!!SHAREDIR!!=$(pkgdatadir)=g" \
				-e "s=!!SYSCONFDIR!!=$(pkgsysconfdir)=g" \
				-e "s=!!BINDIR!!=$(bindir)=g" \
				-e "s=!!VERSION!!=$(PACKAGE_VERSION)=g" $< > $@

install-exec-hook:
	mv $(DESTDIR)$(initexecdir)/openisr.init \
				$(DESTDIR)$(initexecdir)/openisr

install-data-hook:
	ln -sf ../openisr.rules $(DESTDIR)$(udevrulesdir)

uninstall-hook:
	rm -f $(DESTDIR)$(initexecdir)/openisr \
				$(DESTDIR)$(udevrulesdir)/openisr.rules
