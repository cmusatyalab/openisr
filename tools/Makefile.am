AM_CPPFLAGS = -D_GNU_SOURCE
AM_CFLAGS = -W -Wall -Wstrict-prototypes -I..
AM_LDFLAGS = $(SQLITE_LIBS)

pkglib_PROGRAMS = query
EXTRA_PROGRAMS = convert-keyring convert-chunks
CLEANFILES = $(EXTRA_PROGRAMS)
convert_chunks_LDFLAGS = $(AM_LDFLAGS) -lcrypto -lz
