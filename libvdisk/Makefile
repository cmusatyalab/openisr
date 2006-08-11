CFLAGS=-W -Wall -Wstrict-prototypes -g

all: libvdisk.so

libvdisk.so: libvdisk.c
	gcc $(CFLAGS) -fPIC -o libvdisk.o -c libvdisk.c
	gcc -shared -fPIC -ldl -o libvdisk.so libvdisk.o

.PHONY: install
install: libvdisk.so
	cp libvdisk.so /usr/lib
	chmod u+s /usr/lib/libvdisk.so

.PHONY: clean
clean:
	rm -f *.o *.so
