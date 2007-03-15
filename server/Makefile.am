AM_CFLAGS = -Wall -Wstrict-prototypes -D_FILE_OFFSET_BITS=64
AM_LDFLAGS = -lmysqlclient

sbin_PROGRAMS = isrserv
isrserv_SOURCES = revision.c main.c

REVISION_TYPE = object
REVISION_DIR = server
include $(top_srcdir)/mkrevision.mk
