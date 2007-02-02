CFLAGS=-W -Wall -Wstrict-prototypes -O2 -fno-strict-aliasing
MAJOR=0
MINOR=0
REV=0

.PHONY: all
all: libvdisk.so

libvdisk.so: libvdisk.lo
	gcc -shared -Wl,-soname,libvdisk.so.$(MAJOR) -fPIC -ldl -o $@ $^

libvdisk.lo: revision.h
%.lo: %.c
	gcc $(CFLAGS) -fPIC -o $@ -c $<

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh header libvdisk
-include revision.dummy

.PHONY: install
install: libvdisk.so
	install -d $(DESTDIR)/usr/lib
	install -m 4644 -s libvdisk.so $(DESTDIR)/usr/lib/libvdisk.so.$(MAJOR).$(MINOR).$(REV)
# ignore return value, ldconfig can be called by dpkg/rpm/etc
	-ldconfig

.PHONY: clean
clean:
	rm -f *.o *.lo *.so

ifneq ($(MAKELEVEL), 0)
.PHONY: install_revision
install_revision:
	install -m 644 revision.h $(DESTDIR)/libvdisk/
endif
