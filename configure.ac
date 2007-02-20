## Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([OpenISR], [0.8], [isr-list@mailman.srv.cs.cmu.edu])
AM_INIT_AUTOMAKE([foreign])
AC_COPYRIGHT([Copyright (C) 2007 Carnegie Mellon University])
AC_CONFIG_SRCDIR([nexus/request.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([autoconf])

AC_ARG_ENABLE([libvdisk], [AS_HELP_STRING([--disable-libvdisk],
			[don't build libvdisk])],, [enable_libvdisk=yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_CURL([7.12],, AC_MSG_FAILURE([curl too old]))
AC_CHECK_HEADERS([curl/curl.h],,
			AC_MSG_FAILURE([Can't find cURL headers]))
AC_CHECK_LIB([curl], [curl_easy_init],,
			AC_MSG_FAILURE([Can't find cURL library]))

CHECK_SSL
AC_CHECK_HEADERS([openssl/evp.h openssl/blowfish.h],,
			AC_MSG_FAILURE([Can't find OpenSSL headers]))
AC_CHECK_LIB([ssl], [EVP_EncryptUpdate],,
			AC_MSG_FAILURE([Can't find OpenSSL library]))

CHECK_ZLIB

if test "z$enable_libvdisk" = "zyes" ; then
	AC_CHECK_HEADERS([dlfcn.h],,
				AC_MSG_FAILURE([Can't find dl headers]))
	AC_CHECK_LIB([dl], [dlopen],,
				AC_MSG_FAILURE([Can't find dl library]))
fi

AC_CONFIG_FILES([Makefile
                 client/Makefile
                 libvdisk/Makefile
                 nexus/GNUmakefile
                 nexus/tools/Makefile
                 vulpes/Makefile])
#                 conf/Makefile
#                 sha1/Makefile
AC_OUTPUT
