CFLAGS=-W -Wall -Wstrict-prototypes -g

all: libvdisk.so

libvdisk.so: libvdisk.c
	gcc $(CFLAGS) -fPIC -o libvdisk.o -c libvdisk.c
	gcc -shared -fPIC -ldl -o libvdisk.so libvdisk.o

.PHONY: clean
clean:
	rm -f *.o *.so
