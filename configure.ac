#
# configure.ac - build infrastructure for the OpenISR system
#
# Copyright (C) 2007 Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

## Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([OpenISR], [0.8.1], [isr-list@mailman.srv.cs.cmu.edu])
AM_INIT_AUTOMAKE([foreign])
AC_COPYRIGHT([Copyright (C) 2007 Carnegie Mellon University])
AC_CONFIG_SRCDIR([nexus/request.c])
AC_DISABLE_STATIC

# We must choose between generating a config.h, which we don't need, or
# including several lines worth of -D flags on every gcc command line.
# In the interest of (somewhat) more readable compile logs, we generate
# a useless config.h.
AC_CONFIG_HEADERS([config.h])
AH_TOP([/* This file is not used, but generating it makes compiles quieter */])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for optional features.
AC_ARG_ENABLE([client], [AS_HELP_STRING([--enable-client],
			[build client code [yes]])],, [enable_client=yes])
AC_ARG_ENABLE([libvdisk], [AS_HELP_STRING([--enable-libvdisk],
			[build libvdisk [$client]])],,
			[enable_libvdisk=${enable_client}])
AC_ARG_ENABLE([modules], [AS_HELP_STRING([--enable-modules=DIR],
			[build kernel modules (against kernel source in DIR,
			if specified) [$client]])],,
			[enable_modules=${enable_client}])

PROCESS_ENABLE_VAR([$enable_client], [WANT_CLIENT],
			[whether we should build the client])
PROCESS_ENABLE_VAR([$enable_libvdisk], [WANT_LIBVDISK],
			[whether we should build libvdisk])
PROCESS_ENABLE_VAR([$enable_modules], [WANT_MODULES],
			[whether we should build the kernel modules])

if test z$enable_modules != zno ; then
	if test z$srcdir != z. ; then
		AC_MSG_ERROR([cannot build outside source tree when --enable-modules is set])
		# ...because Kbuild doesn't support it
	fi
	
	AC_MSG_CHECKING([for kernel source])
	# KERNELDIR is set to the argument passed to --enable-modules, if not
	# "yes".  Otherwise, it's the value of the KERNELDIR environment
	# variable, if set.  Otherwise, we produce a default from uname -r.
	if test z$enable_modules != zyes ; then
		KERNELDIR=$enable_modules
	elif test z$KERNELDIR = z ; then
		KERNELDIR=/lib/modules/`uname -r`/build
	fi
	AC_MSG_RESULT([$KERNELDIR])
	
	if test ! -f $KERNELDIR/include/linux/version.h ; then
		AC_MSG_ERROR([$KERNELDIR is not a configured kernel source tree])
	fi
	AC_SUBST([KERNELDIR])
	AC_ARG_VAR([KERNELDIR], [location of configured kernel source])
fi

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
	CHECK_CURL_VERSION([$FOUND_PATH], [7.12])
	
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

AC_SUBST([pkgsysconfdir], [\$\(sysconfdir\)/$PACKAGE])
AC_CONFIG_FILES([Makefile
                 conf/Makefile
                 client/Makefile
                 libvdisk/Makefile
                 nexus/GNUmakefile
                 nexus/tools/Makefile
                 sha1/GNUmakefile
                 vulpes/Makefile])
AC_OUTPUT
