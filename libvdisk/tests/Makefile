CFLAGS=-Wall -Wstrict-prototypes -g
PROGS=open stat probe

.PHONY: all
all: $(PROGS)

%: %.c
	gcc $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f $(PROGS)
