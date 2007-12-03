udevdir = ${sysconfdir}/udev
udevrulesdir = ${udevdir}/rules.d

dist_pkgdata_DATA = config
dist_udev_DATA = openisr.rules
initexec_SCRIPTS = openisr.init

# Dummy variables to cause directories to be created
dist_pkgsysconf_DATA = 
dist_udevrules_DATA = 

GEN = openisr.init
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) magic

install-exec-hook:
	mv $(DESTDIR)$(initexecdir)/openisr.init \
				$(DESTDIR)$(initexecdir)/openisr

install-data-hook:
	ln -sf ../openisr.rules $(DESTDIR)$(udevrulesdir)

uninstall-hook:
	rm -f $(DESTDIR)$(initexecdir)/openisr \
				$(DESTDIR)$(udevrulesdir)/openisr.rules

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
