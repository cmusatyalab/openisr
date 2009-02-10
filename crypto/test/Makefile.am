AM_CPPFLAGS = -I$(srcdir)/..
AM_CFLAGS = -W -Wall -Wstrict-prototypes -Wno-unused-parameter
AM_LDFLAGS = -L$(builddir)/.. -lisrcrypto

TESTS = run_vectors
check_PROGRAMS = $(TESTS)
run_vectors_SOURCES  = run_vectors.c vectors.h vectors_aes.h vectors_blowfish.h
run_vectors_SOURCES += vectors_md5.h vectors_sha1.h
