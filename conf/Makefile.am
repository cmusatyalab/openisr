udevdir = ${sysconfdir}/udev
udevrulesdir = ${udevdir}/rules.d
completiondir = ${sysconfdir}/bash_completion.d
sleepdir = ${libdir}/pm-utils/sleep.d

dist_pkgdata_DATA = config
udev_DATA = openisr-client.rules
dist_sleep_SCRIPTS = openisr-client.pm-utils
completion_DATA = openisr-client.completion

# Dummy variables to cause directories to be created
dist_pkgsysconf_DATA = 
dist_udevrules_DATA = 

GEN = openisr-client.rules openisr-client.completion
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) magic

install-data-hook:
	cd $(DESTDIR)$(sleepdir) && mv openisr-client.pm-utils 20openisr-client
	cd $(DESTDIR)$(completiondir) && \
				mv openisr-client.completion openisr-client
	ln -sf ../openisr-client.rules $(DESTDIR)$(udevrulesdir)

uninstall-hook:
	rm -f $(DESTDIR)$(udevdir)/openisr-client.rules \
				$(DESTDIR)$(udevrulesdir)/openisr-client.rules \
				$(DESTDIR)$(completiondir)/openisr-client \
				$(DESTDIR)$(sleepdir)/20openisr-client

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
