## Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([OpenISR], [0.8], [isr-list@mailman.srv.cs.cmu.edu])
AM_INIT_AUTOMAKE([foreign])
AC_COPYRIGHT([Copyright (C) 2007 Carnegie Mellon University])
AC_CONFIG_SRCDIR([nexus/request.c])
AC_CONFIG_MACRO_DIR([autoconf])
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for optional features.
AC_ARG_ENABLE([client], [AS_HELP_STRING([--enable-client],
			[build client code [yes]])],, [enable_client=yes])
AC_ARG_ENABLE([modules], [AS_HELP_STRING([--enable-modules],
			[build kernel modules [$client]])],,
			[enable_modules=${enable_client}])
AC_ARG_ENABLE([libvdisk], [AS_HELP_STRING([--enable-libvdisk],
			[build libvdisk [$client]])],,
			[enable_libvdisk=${enable_client}])

PROCESS_ENABLE_VAR([$enable_client], [WANT_CLIENT],
			[whether we should build the client])
PROCESS_ENABLE_VAR([$enable_libvdisk], [WANT_LIBVDISK],
			[whether we should build libvdisk])
PROCESS_ENABLE_VAR([$enable_modules], [WANT_MODULES],
			[whether we should build the kernel modules])

# Checks for libraries.
AC_ARG_WITH([ssl], [AS_HELP_STRING([--with-ssl=DIR],
			[look for OpenSSL in DIR])])
AC_ARG_WITH([zlib], [AS_HELP_STRING([--with-zlib=DIR],
			[look for zlib in DIR])])
AC_ARG_WITH([curl], [AS_HELP_STRING([--with-curl=DIR],
			[look for curl in DIR])])

if test z$enable_client = zyes; then
	FIND_LIBRARY([curl], [curl], [curl_easy_init], [curl/curl.h],
				[$with_curl /usr/local /usr])
	AC_CHECK_CURL([7.12],, AC_MSG_FAILURE([curl too old]))
	
	FIND_LIBRARY([OpenSSL], [ssl], [EVP_EncryptUpdate],
				[openssl/ssl.h openssl/evp.h openssl/blowfish.h],
				[$with_ssl /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/local /usr])
	
	FIND_LIBRARY([zlib], [z], [inflate], [zlib.h],
				[$with_zlib /usr/local /usr])
fi

if test "z$enable_libvdisk" = "zyes" ; then
	# We don't provide a --with-dl=DIR option because this is supposed
	# to be a system function.
	FIND_LIBRARY([libdl], [dl], [dlopen], [dlfcn.h], [/usr])
fi

AC_CONFIG_FILES([Makefile
                 conf/Makefile
                 client/Makefile
                 libvdisk/Makefile
                 nexus/GNUmakefile
                 nexus/tools/Makefile
                 sha1/GNUmakefile
                 vulpes/Makefile])
AC_OUTPUT
