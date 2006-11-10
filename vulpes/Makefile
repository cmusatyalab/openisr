CC=gcc

CFLAGS= -MMD -g -O2 -Wall -Wstrict-prototypes -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I../convergent

LFLAGS= -lz -lssl -lcurl

ISR_HOME=$(PWD)
BINDIR=$(ISR_HOME)/local/bin

APP=vulpes
UTILS=keyring-utils

SRCS=revision.c vulpes.c vulpes_driver.c vulpes_transport_http.c vulpes_cache.c vulpes_crypto.c vulpes_log.c vulpes_util.c vulpes_lka.c

OBJS=$(SRCS:.c=.o)
ASS=$(SRCS:.c=.s)
PRE=$(SRCS:.c=.i)
DEP=$(SRCS:.c=.d)

CURL_VER=
CURL_VER :=  $(shell curl-config --version|cut -f2 -d' '|cut -f2 -d'.')
ifneq (,$(CURL_VER))
CURL_TOO_OLD :=  $(shell echo " ${CURL_VER} < 12 "|bc)
else
CURL_TOO_OLD=1
endif

all: checklibs $(APP)

.PHONY: checklibs
checklibs:
ifeq (1,$(CURL_TOO_OLD))
	@echo "You must have curl 7.12 or later installed."
	@exit 1
endif

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
	rm -f $(DEP) $(ASS) $(PRE) $(OBJS) *~ $(APP) processchunk vulpes_lka.d vulpes_lka.o vulpes-*.tgz

# This is a hack.  The include directive forces make to always execute
# the rule, and to recalculate its target selection afterward.  Note
# that if any source files have changed, this rule will be executed
# twice due to %.d updates.
.PHONY: revision.dummy
revision.dummy:
	@../mkrevision.sh object vulpes
-include revision.dummy

install: 
	@mkdir -p $(BINDIR)
	@cp $(APP) $(BINDIR)

vulpes: $(OBJS)
	$(CC) -o $@ $(LFLAGS) $^

keyring-utils: processchunk

processchunk: processchunk.c vulpes_lev1_encryption.o vulpes_log.o
	$(CC) -o processchunk $^ -lz -lssl

.PHONY: dist
dist: REV=$(shell svnversion .)
dist:
	svn export -q . vulpes-$(REV)
	cp revision.c vulpes-$(REV)
	tar czf vulpes-$(REV).tgz --force-local vulpes-$(REV)
	rm -rf vulpes-$(REV)
	@echo "Created vulpes-$(REV).tgz"
