CFLAGS=-W -Wall -Wstrict-prototypes -g

all: libvdisk.so test probe

libvdisk.so: libvdisk.c
	gcc $(CFLAGS) -fPIC -o libvdisk.o -c libvdisk.c
	gcc -shared -fPIC -ldl -o libvdisk.so libvdisk.o

test: test.c
	gcc $(CFLAGS) -o test test.c

probe: probe.c
	gcc $(CFLAGS) -o probe probe.c

.PHONY: clean
clean:
	rm -f *.o *.so test
