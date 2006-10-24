ifneq ($(KERNELRELEASE),)

obj-m := openisr.o
openisr-objs := init.o request.o chunkdata.o chardev.o transform.o lzf.o
openisr-objs += revision.o 

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CFLAGS = -O2 -g -W -Wall -Wstrict-prototypes

.PHONY: all
all: module test readstats

.PHONY: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

test: test.c convergent-user.h
	$(CC) $(CFLAGS) -lssl -o $@ test.c

readstats: readstats.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f test
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh object convergent
-include revision.dummy

endif
