udevdir = ${sysconfdir}/udev
udevrulesdir = ${udevdir}/rules.d
completiondir = ${sysconfdir}/bash_completion.d

dist_pkgdata_DATA = config
dist_udev_DATA = openisr.rules
initexec_SCRIPTS = openisr.init
completion_DATA = openisr.completion

# Dummy variables to cause directories to be created
dist_pkgsysconf_DATA = 
dist_udevrules_DATA = 

GEN = openisr.init openisr.completion
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) magic

install-exec-hook:
	mv $(DESTDIR)$(initexecdir)/openisr.init \
				$(DESTDIR)$(initexecdir)/openisr

install-data-hook:
	mv $(DESTDIR)$(completiondir)/openisr.completion \
				$(DESTDIR)$(completiondir)/openisr
	ln -sf ../openisr.rules $(DESTDIR)$(udevrulesdir)

uninstall-hook:
	rm -f $(DESTDIR)$(initexecdir)/openisr \
				$(DESTDIR)$(udevrulesdir)/openisr.rules \
				$(DESTDIR)$(completiondir)/openisr

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
