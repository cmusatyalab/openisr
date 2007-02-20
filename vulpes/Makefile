CC=gcc
CFLAGS= -MMD -g -O2 -Wall -Wstrict-prototypes -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I../nexus -I/lib/modules/`uname -r`/build/include
LFLAGS= -lz -lssl -lcurl

LIBDIR ?= $(HOME)/bin

SRCS=revision.c main.c driver.c transport.c cache.c crypto.c log.c util.c lookaside.c

OBJS=$(SRCS:.c=.o)
ASS=$(SRCS:.c=.s)
PRE=$(SRCS:.c=.i)
DEP=$(SRCS:.c=.d)

.PHONY: all
all: vulpes

$(OBJS): %.o : %.c
	$(CC) $(CFLAGS) $< -c -o $@

$(PRE): %.i : %.c
	$(CC) $(CFLAGS) $< -E -o $@

$(ASS): %.s : %.c
	$(CC) $(CFLAGS) $< -S -o $@

$(DEP): %.d : %.c
	@touch $@

-include $(DEP)

.PHONY: clean
clean:
	rm -f $(DEP) $(ASS) $(PRE) $(OBJS) *~ vulpes vulpes-*.tgz

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh object vulpes
-include revision.dummy

.PHONY: install
install: vulpes
	install -d $(DESTDIR)/$(LIBDIR)
	install -m 755 vulpes $(DESTDIR)/$(LIBDIR)

.PHONY: install_modules
install_modules:

vulpes: $(OBJS)
	$(CC) -o $@ $(LFLAGS) $^

ifneq ($(MAKELEVEL), 0)
.PHONY: distdir_version
distdir_version:
	install -m 644 revision.c $(DESTDIR)/vulpes/
endif
