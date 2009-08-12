udevdir = ${sysconfdir}/udev
udevrulesdir = ${udevdir}/rules.d
completiondir = ${sysconfdir}/bash_completion.d

dist_pkgdata_DATA = config
udev_DATA = openisr-client.rules
initexec_SCRIPTS = openisr-client.init
completion_DATA = openisr-client.completion

# Dummy variables to cause directories to be created
dist_pkgsysconf_DATA = 
dist_udevrules_DATA = 

GEN = openisr-client.init openisr-client.rules openisr-client.completion
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) magic

install-exec-hook:
	cd $(DESTDIR)$(initexecdir) && mv openisr-client.init openisr-client

install-data-hook:
	cd $(DESTDIR)$(completiondir) && \
				mv openisr-client.completion openisr-client
	ln -sf ../openisr-client.rules $(DESTDIR)$(udevrulesdir)

uninstall-hook:
	rm -f $(DESTDIR)$(initexecdir)/openisr-client \
				$(DESTDIR)$(udevdir)/openisr-client.rules \
				$(DESTDIR)$(udevrulesdir)/openisr-client.rules \
				$(DESTDIR)$(completiondir)/openisr-client

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
