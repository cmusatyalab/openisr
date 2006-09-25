ifneq ($(KERNELRELEASE),)

obj-m := isr-convergent.o
isr-convergent-objs := convergent.o workqueue.o chunkdata.o chardev.o
isr-convergent-objs += transform.o revision.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CFLAGS = -O2 -g -W -Wall -Wstrict-prototypes

.PHONY: all
all: module test

.PHONY: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

test: test.c convergent-user.h
	$(CC) $(CFLAGS) -o $@ test.c

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
