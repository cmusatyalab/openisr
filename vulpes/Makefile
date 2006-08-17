#
# $Id: Makefile,v 1.18 2005/03/11 21:26:07 makozuch Exp $

CC=gcc
CCC=g++

CFLAGS= -MMD -g -O2 -Wall -D_GNU_SOURCE -D_LARGEFILE_SOURCE

LFLAGS= -static -static-libgcc -L/usr/kerberos/lib 
LLIBS= -lz -lcurl -lk5crypto -lkrb5 -lcrypto -lgssapi_krb5 -ldl -lssl -lcom_err -lresolv 

ISR_HOME=$(PWD)
BINDIR=$(ISR_HOME)/local/bin

APP=vulpes
UTILS=keyring-utils

SRCS=vulpes.c vulpes_lev1.c vulpes_fids.c vulpes_logstats.c vulpes_lev1_encryption.c vulpes_log.c # vulpes_simple.c 

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

all: LIBS $(APP)

LIBS: 
ifeq (1,$(CURL_TOO_OLD))
	tar jxf curl-7.12.1.tar.bz2
	cd curl-7.12.1
	cd curl-7.12.1 && ./configure --prefix=/usr --exec-prefix=/usr
	cd curl-7.12.1 && make
	cd curl-7.12.1 && make install
	rm -fr curl-7.12.1
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

clean:
	rm -f $(DEP) $(ASS) $(PRE) $(OBJS) *~ $(APP) processchunk vulpes_lka.d vulpes_lka.o

install: 
	@mkdir -p $(BINDIR)
	@cp $(APP) $(BINDIR)

vulpes_lka.o: vulpes_lka.C
	$(CCC) $(CFLAGS) $< -c -o $@

vulpes: $(OBJS) vulpes_lka.o 
	$(CCC) -o $@ $^ $(LFLAGS) $(LLIBS) $(LLIBS) $(LLIBS)

keyring-utils: processchunk

processchunk: processchunk.c vulpes_lev1_encryption.o vulpes_log.o
	$(CC) -o processchunk $^ -lz -lssl

analyze_logstats: analyze_logstats.cpp
	$(CCC) -o analyze_logstats analyze_logstats.cpp

vulpes.tgz:
	tar cvzf vulpes.tgz $(SRCS) tf.c Makefile 
