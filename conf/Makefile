SHAREDIR ?= $(HOME)/bin
SYSCONFDIR ?= $(HOME)/bin

.PHONY: all
all:

.PHONY: clean
clean:

.PHONY: install
install:
	install -d $(DESTDIR)/$(SYSCONFDIR) $(DESTDIR)/$(SHAREDIR)
	install -m 644 config $(DESTDIR)/$(SHAREDIR)

.PHONY: install_modules
install_modules:

ifneq ($(MAKELEVEL), 0)
.PHONY: distdir_version
distdir_version:
endif
