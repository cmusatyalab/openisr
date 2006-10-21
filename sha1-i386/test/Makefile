ifneq ($(KERNELRELEASE),)

obj-m := sha1test.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
PROGS = hextostream monte

.PHONY: all
all: module $(PROGS)

%: %.c
	gcc -o $@ -O2 -g $^

.PHONY: module
module:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

.PHONY: clean
clean:
	rm -f $(PROGS)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

endif

