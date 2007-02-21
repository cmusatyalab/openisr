modprobedir="${sysconfdir}/modprobe.d"
initexecdir="${sysconfdir}/init.d"
udevdir="${sysconfdir}/udev"

dist_pkgdata_DATA = config
dist_modprobe_DATA = openisr.modprobe
dist_udev_DATA = openisr.rules
dist_initexec_SCRIPTS = openisr.init
EXTRA_DIST = magic

install-exec-hook:
	mv $(DESTDIR)$(initexecdir)/openisr.init \
				$(DESTDIR)$(initexecdir)/openisr

install-data-hook:
	mv $(DESTDIR)$(modprobedir)/openisr.modprobe \
				$(DESTDIR)$(modprobedir)/openisr

uninstall-hook:
	rm -f $(DESTDIR)$(initexecdir)/openisr \
				$(DESTDIR)$(modprobedir)/openisr
