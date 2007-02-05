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

ifneq ($(MAKELEVEL), 0)
.PHONY: install_revision
install_revision:
endif
