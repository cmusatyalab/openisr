AM_CPPFLAGS = -D_GNU_SOURCE
AM_CFLAGS = -W -Wall -Wstrict-prototypes -I..
AM_LDFLAGS = $(SQLITE_LIBS)

if WANT_SERVER
ZLIB_PROGRAM = zlib
endif

pkglib_PROGRAMS = query $(ZLIB_PROGRAM)
EXTRA_PROGRAMS = convert-keyring convert-chunks
CLEANFILES = $(EXTRA_PROGRAMS) zlib
convert_chunks_LDFLAGS = $(AM_LDFLAGS) -lcrypto -lz
zlib_LDFLAGS = -lz
