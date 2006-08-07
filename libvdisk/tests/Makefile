CFLAGS=-Wall -Wstrict-prototypes -g

all: open stat probe

open: open.c
	gcc $(CFLAGS) -o open open.c

stat: stat.c
	gcc $(CFLAGS) -o stat stat.c

probe: probe.c
	gcc $(CFLAGS) -o probe probe.c

.PHONY: clean
clean:
	rm -f open stat probe
