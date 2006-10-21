PROGS = hextostream monte

.PHONY: all
all: $(PROGS)

%: %.c
	gcc -o $@ -O2 -g $^

.PHONY: clean
clean:
	rm -f $(PROGS)
