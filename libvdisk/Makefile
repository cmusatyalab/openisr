CFLAGS=-W -Wall -Wstrict-prototypes -O2 -fno-strict-aliasing
LIBVERSION=0.0.0

.PHONY: all
all: libvdisk.so

libvdisk.so: libvdisk.lo
	gcc -shared -Wl,-soname,libvdisk.so.0 -fPIC -ldl -o $@ $^

%.lo: %.c
	gcc $(CFLAGS) -fPIC -o $@ -c $<

.PHONY: install
install: libvdisk.so
	install -m 4644 -s libvdisk.so /usr/lib/libvdisk.so.$(LIBVERSION)
	ldconfig

.PHONY: clean
clean:
	rm -f *.o *.lo *.so
