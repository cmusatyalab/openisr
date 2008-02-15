#
# configure.ac - build infrastructure for the OpenISR (R) system
#
# Copyright (C) 2007-2008 Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

## Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([OpenISR], [0.9.1])
AM_INIT_AUTOMAKE([foreign 1.10])
AC_COPYRIGHT([Copyright (C) 2007-2008 Carnegie Mellon University])
AC_CONFIG_SRCDIR([nexus/request.c])
AC_DISABLE_STATIC

# Generating a config.h prevents the introduction of several lines' worth of
# -D flags on every gcc command line
AC_CONFIG_HEADERS([config.h])

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
AC_ARG_ENABLE([modules], [AS_HELP_STRING([--enable-modules],
			[build kernel modules [$client]])],,
			[enable_modules=${enable_client}])
AC_ARG_ENABLE([server], [AS_HELP_STRING([--enable-server],
			[build server code [no]])],, [enable_server=no])
AC_ARG_WITH([kbuild-wrapper],
			[AS_HELP_STRING([--with-kbuild-wrapper={none|debian|dkms}],
			[for use by packaging scripts only])],,
			[with_kbuild_wrapper=none])
AC_ARG_WITH([group], [AS_HELP_STRING([--with-group=GROUP],
			[group for device node access [isrusers]])],,
			[with_group=isrusers])

PROCESS_ENABLE_VAR([$enable_client], [WANT_CLIENT],
			[whether we should build the client])
PROCESS_ENABLE_VAR([$enable_libvdisk], [WANT_LIBVDISK],
			[whether we should build libvdisk])
PROCESS_ENABLE_VAR([$enable_modules], [WANT_MODULES],
			[whether we should build the kernel modules])
PROCESS_ENABLE_VAR([$enable_server], [WANT_SERVER],
			[whether we should build the server])
AM_CONDITIONAL([WANT_COMMON],
			[test z$enable_client = zyes -o z$enable_server = zyes])

if test z$enable_client = zyes ; then
	AC_MSG_CHECKING([group for OpenISR device nodes])
	AC_MSG_RESULT([$with_group])
	AC_SUBST([ISRGROUP], [$with_group])
fi

if test z$enable_client = zyes -o z$enable_modules = zyes ; then
	AC_MSG_CHECKING([how to build kernel modules])
	if test x$with_kbuild_wrapper = xnone ; then
		AC_MSG_RESULT([source])
		AC_SUBST([KBUILDTYPE], [source])
	elif test x$with_kbuild_wrapper = xdebian -o x$with_kbuild_wrapper = xdkms
	then
		AC_MSG_RESULT([$with_kbuild_wrapper])
		if test z$enable_modules = zyes ; then
			AC_MSG_ERROR([--enable-modules cannot be used with a kbuild wrapper])
		fi
		AC_SUBST([KBUILDTYPE], [$with_kbuild_wrapper])
	else
		AC_MSG_ERROR([unknown kbuild wrapper $with_kbuild_wrapper])
	fi
fi
AM_CONDITIONAL([WANT_MODULE_SOURCE], [test z$enable_client = zyes -a \
			z$with_kbuild_wrapper = znone])

if test z$enable_modules = zyes ; then
	if test z$srcdir != z. ; then
		AC_MSG_ERROR([cannot build outside source tree when --enable-modules is set])
		# ...because Kbuild doesn't support it
	fi
fi

build_32=no
if test z$enable_libvdisk = zyes ; then
	# See if we're on an x86_64 system with multilib support.  If so, build
	# both 32-bit and 64-bit versions of libvdisk.
	if test z$host_cpu = zx86_64; then
		CHECK_COMPILER_OPTION_VAR([-m32])
		if test z$have_option = zyes ; then
			build_32=yes
			FIND_DIR([32-bit system libraries],
						[/usr/lib32 /usr/lib],
						[LIBVDISK_DIRPATH_32])
		else
			AC_MSG_WARN([cannot build 32-bit libvdisk; building only 64-bit version])
		fi
		FIND_DIR([64-bit system libraries], [/usr/lib64 /usr/lib],
					[LIBVDISK_DIRPATH])
	else
		FIND_DIR([system libraries], [/usr/lib], [LIBVDISK_DIRPATH])
	fi
	
	# Check for old hd_driveid definition that doesn't know about
	# 48-bit LBA
	CHECK_COMPILE([for lba_capacity_2 in hd_driveid],
				[AC_LANG_PROGRAM([#include <linux/hdreg.h>], 
				[struct hd_driveid id;
				unsigned long long cap=id.lba_capacity_2;])],
				HAVE_LBA_CAPACITY_2,
				[Define if struct hd_driveid in <linux/hdreg.h> contains an lba_capacity_2 member.])
fi
AM_CONDITIONAL([LIBVDISK_BUILD_32], [test z$build_32 = zyes])

# Checks for programs.
AC_PATH_PROG([PERL], [perl], [no])
if test z$PERL = zno ; then
	AC_MSG_ERROR([Perl not found])
fi
AC_SUBST([PERL])
AC_ARG_VAR([PERL], [path to Perl])

# Checks for libraries.
AC_ARG_WITH([kernel], [AS_HELP_STRING([--with-kernel=DIR],
			[look for configured kernel source tree in DIR])])
AC_ARG_WITH([ssl], [AS_HELP_STRING([--with-ssl=DIR],
			[look for OpenSSL in DIR])])
AC_ARG_WITH([zlib], [AS_HELP_STRING([--with-zlib=DIR],
			[look for zlib in DIR])])
AC_ARG_WITH([curl], [AS_HELP_STRING([--with-curl=DIR],
			[look for curl in DIR])])

# We need this for the kernel modules and for Vulpes (since it grabs loop.h
# from the kernel source tree)
if test z$enable_client = zyes -o z$enable_modules = zyes ; then
	AC_MSG_CHECKING([for kernel source])
	# KERNELDIR is set to the argument passed to --with-kernel, if set.
	# Otherwise, it's the value of the KERNELDIR environment variable,
	# if set.  Otherwise, we produce a default from uname -r.
	if test z$with_kernel != z ; then
		KERNELDIR=$with_kernel
	elif test z$KERNELDIR = z ; then
		KERNELDIR=/lib/modules/`uname -r`/build
	fi
	AC_MSG_RESULT([$KERNELDIR])
	
	if test ! -f $KERNELDIR/include/linux/version.h ; then
		AC_MSG_ERROR([$KERNELDIR is not a configured kernel source tree])
	fi
	AC_SUBST([KERNELDIR])
	AC_ARG_VAR([KERNELDIR], [location of configured kernel source (equivalent to --with-kernel)])
fi

if test z$enable_client = zyes ; then
	FIND_LIBRARY([curl], [curl], [curl_easy_init], [curl/curl.h],
				[$with_curl /usr/local /usr])
	CHECK_CURL_VERSION([$FOUND_PATH], [7.12.3])
	
	FIND_LIBRARY([OpenSSL], [ssl], [EVP_EncryptUpdate],
				[openssl/ssl.h openssl/evp.h openssl/blowfish.h],
				[$with_ssl /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/local /usr])
	
	FIND_LIBRARY([zlib], [z], [inflate], [zlib.h],
				[$with_zlib /usr/local /usr])
	
	PKG_CHECK_MODULES([OSSP_UUID], [ossp-uuid])
fi

if test z$enable_libvdisk = zyes ; then
	# We don't provide a --with-dl=DIR option because this is supposed
	# to be a system function.
	FIND_LIBRARY([libdl], [dl], [dlopen], [dlfcn.h], [/usr])
fi

AC_SUBST([pkgsysconfdir], [\$\(sysconfdir\)/$PACKAGE])
AC_SUBST([initexecdir], [\$\(sysconfdir\)/init.d])
AC_CONFIG_FILES([Makefile
                 conf/Makefile
                 client/Makefile
                 libvdisk/Makefile
                 locksrv/Makefile
                 nexus/GNUmakefile
                 nexus/tools/Makefile
                 parcelkeeper/Makefile
                 sqlite/Makefile
                 sha1/GNUmakefile
                 tools/Makefile])
AC_OUTPUT
