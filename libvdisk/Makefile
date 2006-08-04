all: libvdisk.so test

libvdisk.so: libvdisk.c
	gcc -Wall -fPIC -o libvdisk.o -c libvdisk.c
	gcc -shared -fPIC -ldl -o libvdisk.so libvdisk.o

test: test.c
	gcc -o test test.c

.PHONY: clean
clean:
	rm -f *.o *.so test
