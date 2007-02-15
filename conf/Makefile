SHAREDIR ?= $(HOME)/bin
SYSCONFDIR ?= $(HOME)/bin

.PHONY: all
all:

.PHONY: clean
clean:

.PHONY: install
install:
	install -d $(DESTDIR)/$(SYSCONFDIR) $(DESTDIR)/$(SHAREDIR) $(DESTDIR)/etc/modprobe.d $(DESTDIR)/etc/init.d
	install -m 644 config $(DESTDIR)/$(SHAREDIR)
	install -m 644 openisr.modprobe $(DESTDIR)/etc/modprobe.d/openisr
	install -m 755 openisr.init $(DESTDIR)/etc/init.d/openisr

.PHONY: install_modules
install_modules:

ifneq ($(MAKELEVEL), 0)
.PHONY: distdir_version
distdir_version:
endif
