CFLAGS=-W -Wall -Wstrict-prototypes -g

.PHONY: all
all: libvdisk.so

libvdisk.so: libvdisk.lo
	gcc -shared -fPIC -ldl -o $@ $^

%.lo: %.c
	gcc $(CFLAGS) -fPIC -o $@ -c $<

.PHONY: install
install: libvdisk.so
	cp libvdisk.so /usr/lib
	chmod u+s /usr/lib/libvdisk.so

.PHONY: clean
clean:
	rm -f *.o *.lo *.so
