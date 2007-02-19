#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([OpenISR], [0.8], [isr-list@mailman.srv.cs.cmu.edu])
AC_CONFIG_SRCDIR([nexus/request.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_HEADERS([curl/curl.h],,
			AC_MSG_FAILURE([Can't find cURL headers]))
AC_CHECK_LIB([curl], [curl_easy_init],,
			AC_MSG_FAILURE([Can't find cURL library]))

AC_CHECK_HEADERS([openssl/evp.h openssl/blowfish.h],,
			AC_MSG_FAILURE([Can't find OpenSSL headers]))
AC_CHECK_LIB([ssl], [EVP_EncryptUpdate],,
			AC_MSG_FAILURE([Can't find OpenSSL library]))

AC_CHECK_HEADERS([zlib.h],,
			AC_MSG_FAILURE([Can't find zlib headers]))
AC_CHECK_LIB([z], [inflate],,
			AC_MSG_FAILURE([Can't find zlib library]))

# XXX only if libvdisk
AC_CHECK_HEADERS([dlfcn.h],,
			AC_MSG_FAILURE([Can't find dl headers]))
AC_CHECK_LIB([dl], [dlopen],,
			AC_MSG_FAILURE([Can't find dl library]))

AC_CONFIG_FILES([Makefile])
#AC_CONFIG_FILES([Makefile
#                 client/Makefile
#                 conf/Makefile
#                 libvdisk/Makefile
#                 nexus/Makefile
#                 sha1/Makefile
#                 vulpes/Makefile])
AC_OUTPUT
