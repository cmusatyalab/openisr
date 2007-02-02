DESTDIR ?= dest
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib/openisr
SHAREDIR ?= /usr/share/openisr
SYSCONFDIR ?= /etc/openisr
export DESTDIR BINDIR LIBDIR SHAREDIR SYSCONFDIR

DIRS=client vulpes libvdisk nexus sha1-i586

.PHONY: default
default: all

%:
	for dir in $(DIRS) ; do \
		make -C $$dir $@; \
	done

