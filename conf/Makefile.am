completiondir = ${sysconfdir}/bash_completion.d
sleepdir = ${libdir}/pm-utils/sleep.d

dist_pkgdata_DATA = config
dist_sleep_SCRIPTS = openisr-client.pm-utils
completion_DATA = openisr-client.completion

# Dummy variable to cause the directory to be created
dist_pkgsysconf_DATA = 

GEN = openisr-client.completion
CLEANFILES = $(GEN)
EXTRA_DIST = $(GEN:=.in) magic

install-data-hook:
	cd $(DESTDIR)$(sleepdir) && mv openisr-client.pm-utils 20openisr-client
	cd $(DESTDIR)$(completiondir) && \
				mv openisr-client.completion openisr-client

uninstall-hook:
	rm -f $(DESTDIR)$(completiondir)/openisr-client \
				$(DESTDIR)$(sleepdir)/20openisr-client

include $(top_srcdir)/mkrevision.mk
include $(top_srcdir)/subst.mk
