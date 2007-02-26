modprobedir = ${sysconfdir}/modprobe.d
initexecdir = ${sysconfdir}/init.d
udevdir = ${sysconfdir}/udev
udevrulesdir = ${udevdir}/rules.d

dist_pkgdata_DATA = config
dist_modprobe_DATA = openisr.modprobe
dist_udev_DATA = openisr.rules
dist_initexec_SCRIPTS = openisr.init

# Dummy variables to cause directories to be created
dist_pkgsysconf_DATA = 
dist_udevrules_DATA = 

GEN = openisr.init
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
	mv $(DESTDIR)$(modprobedir)/openisr.modprobe \
				$(DESTDIR)$(modprobedir)/openisr
	ln -sf ../openisr.rules $(DESTDIR)$(udevrulesdir)

uninstall-hook:
	rm -f $(DESTDIR)$(initexecdir)/openisr \
				$(DESTDIR)$(modprobedir)/openisr \
				$(DESTDIR)$(udevrulesdir)/openisr.rules
