#
# $Id: Makefile,v 1.18 2005/03/11 21:26:07 makozuch Exp $

CC=gcc
CCC=g++

# if you wish to override `uname -r`, let configure 
# fill this up with the location/pathname of the kernel tree.

KERNELSRC=
ifneq (,$(KERNELSRC))
KERNELVER := $(shell grep UTS_RELEASE $(KERNELSRC)/include/linux/version.h | cut -d\" -f2)
else
KERNELVER := $(shell uname -r)
endif
KERNELBUILDDIR := /lib/modules/$(KERNELVER)/build
KERNELINCLUDEDIR := $(KERNELBUILDDIR)/include

UCFLAGS= -MMD -g -O2 -Wall -D_GNU_SOURCE -D_LARGEFILE_SOURCE
KCFLAGS= -MMD -Wall -O2 -DMODULE -D__KERNEL__ -DLINUX -I $(KERNELINCLUDEDIR)

# ULFLAGS= -static -static-libgcc -lz -lcrypto -lcurl -L/usr/kerberos/lib -lssl -lgssapi_krb5 -lkrb5 -lcom_err -lk5crypto -lresolv -ldl -L/usr/kerberos/lib 
ULFLAGS= -static -static-libgcc -L/usr/kerberos/lib 
ULLIBS= -lz -lcurl -lk5crypto -lkrb5 -lcrypto -lgssapi_krb5 -ldl -lssl -lcom_err -lresolv 
KLFLAGS=

ISR_HOME=$(PWD)
DRIVERDIR=$(ISR_HOME)/local/drivers
BINDIR=$(ISR_HOME)/local/bin

DRIVER=fauxide.o
DRIVER26=isr.ko
APP=vulpes
UTILS=keyring-utils

KSRCS=fauxide.c
KSRCS26=isr.c
USRCS=vulpes.c vulpes_lev1.c vulpes_fids.c vulpes_logstats.c vulpes_lev1_encryption.c vulpes_log.c # vulpes_simple.c 

KOBJS=$(KSRCS:.c=.o)
UOBJS=$(USRCS:.c=.o)
KASS=$(KSRCS:.c=.s)
UASS=$(USRCS:.c=.s)
KPRE=$(KSRCS:.c=.i)
UPRE=$(USRCS:.c=.i)
KDEP=$(KSRCS:.c=.d)
UDEP=$(USRCS:.c=.d)

CURL_VER=
CURL_VER :=  $(shell curl-config --version|cut -f2 -d' '|cut -f2 -d'.')
ifneq (,$(CURL_VER))
CURL_TOO_OLD :=  $(shell echo " ${CURL_VER} < 12 "|bc)
else
CURL_TOO_OLD=1
endif

all: LIBS $(DRIVER) $(APP)

LIBS: 
ifeq (1,$(CURL_TOO_OLD))
	tar jxf curl-7.12.1.tar.bz2
	cd curl-7.12.1
	cd curl-7.12.1 && ./configure --prefix=/usr --exec-prefix=/usr
	cd curl-7.12.1 && make
	cd curl-7.12.1 && make install
	rm -fr curl-7.12.1
endif

DRIVERBUILDDIR=$(PWD)/isr-driver-build
DRIVER26:
	(mkdir -p $(DRIVERBUILDDIR) \
	 && cd $(DRIVERBUILDDIR) \
	 && ln -sf ../Makefile.driver26 Makefile \
	 && ln -sf ../isr.c ../fauxide.h . \
	 && make \
	 && cd .. )

$(KOBJS): %.o : %.c
	$(CC) $(KCFLAGS) $< -c -o $@

$(UOBJS): %.o : %.c
	$(CC) $(UCFLAGS) $< -c -o $@

$(KPRE): %.i : %.c
	$(CC) $(KCFLAGS) $< -E -o $@

$(UPRE): %.i : %.c
	$(CC) $(UCFLAGS) $< -E -o $@

$(KASS): %.s : %.c
	$(CC) $(KCFLAGS) $< -S -o $@

$(UASS): %.s : %.c
	$(CC) $(UCFLAGS) $< -S -o $@

$(KDEP): %.d : %.c
	@touch $@

$(UDEP): %.d : %.c
	@touch $@

-include $(KDEP) 
-include $(UDEP)

clean:
	rm -f $(UDEP) $(KDEP) $(UASS) $(KASS) $(UPRE) $(KPRE) $(UOBJS) $(KOBJS) *~ $(APP) processchunk vulpes_lka.d vulpes_lka.o
	rm -fr $(DRIVERBUILDDIR)

install: 
	@mkdir -p $(DRIVERDIR)
	@mkdir -p $(BINDIR)
	@cp $(DRIVER) $(DRIVERDIR)
	@cp $(APP) $(BINDIR)

vulpes_lka.o: vulpes_lka.C
	$(CCC) $(UCFLAGS) $< -c -o $@

vulpes: $(UOBJS) vulpes_lka.o 
	$(CCC) -o $@ $^ $(ULFLAGS) $(ULLIBS) $(ULLIBS) $(ULLIBS)

keyring-utils: processchunk

processchunk: processchunk.c vulpes_lev1_encryption.o vulpes_log.o
	$(CC) -o processchunk $^ -lz -lssl

analyze_logstats: analyze_logstats.cpp
	$(CCC) -o analyze_logstats analyze_logstats.cpp

fauxide.tgz:
	tar cvzf fauxide.tgz $(KSRCS) $(USRCS) tf.c Makefile 
