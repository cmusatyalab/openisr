AM_CFLAGS = -W -Wall -Wstrict-prototypes -Wno-unused-parameter
AM_LDFLAGS = -lisrcrypto

TESTS = run_vectors
check_PROGRAMS = $(TESTS)
run_vectors_SOURCES  = run_vectors.c vectors.h vectors_aes.h vectors_blowfish.h
run_vectors_SOURCES += vectors_compress.h vectors_hmac.h vectors_md5.h
run_vectors_SOURCES += vectors_rsa.h vectors_sha1.h
nodist_run_vectors_SOURCES = $(builddir)/../rsa-key-tab.c
run_vectors_CFLAGS = $(AM_CFLAGS) $(libtasn1_CFLAGS)
run_vectors_LDFLAGS = $(AM_LDFLAGS) $(libtasn1_LIBS)

EXTRA_PROGRAMS = sign compress
sign_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS)
sign_LDFLAGS = $(AM_LDFLAGS) $(glib_LIBS)
compress_CFLAGS = $(AM_CFLAGS) $(glib_CFLAGS)
compress_LDFLAGS = $(AM_LDFLAGS) $(glib_LIBS)
