AM_CPPFLAGS = -I$(srcdir)/..
AM_CFLAGS = -W -Wall -Wstrict-prototypes -Wno-unused-parameter
AM_LDFLAGS = -L$(builddir)/.. -lisrcrypto

TESTS = run_vectors
check_PROGRAMS = $(TESTS)
run_vectors_SOURCES  = run_vectors.c vectors.h vectors_aes.h vectors_blowfish.h
run_vectors_SOURCES += vectors_hmac.h vectors_md5.h vectors_rsa.h
run_vectors_SOURCES += vectors_sha1.h
nodist_run_vectors_SOURCES = $(builddir)/../rsa-key-tab.c
run_vectors_CFLAGS = $(AM_CFLAGS) $(libtasn1_CFLAGS)
run_vectors_LDFLAGS = $(AM_LDFLAGS) $(libtasn1_LIBS)

EXTRA_PROGRAMS = sign
sign_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS)
sign_LDFLAGS = $(AM_LDFLAGS) $(glib_LIBS)
