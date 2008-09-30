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
AC_INIT([OpenISR], [0.9.3])
AM_INIT_AUTOMAKE([foreign 1.10])
AC_COPYRIGHT([Copyright (C) 2007-2008 Carnegie Mellon University])
AC_CONFIG_SRCDIR([parcelkeeper/nexus.c])
AC_DISABLE_STATIC

# Generating a config.h prevents the introduction of several lines' worth of
# -D flags on every gcc command line
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG()

# Checks for optional features.
AC_ARG_ENABLE([client], [AS_HELP_STRING([--enable-client],
			[build client code [yes]])],, [enable_client=yes])
AC_ARG_ENABLE([vmm-drivers], [AS_HELP_STRING([--enable-vmm-drivers=<list>],
			[build VMM drivers [$client]])],,
			[enable_vmm_drivers=${enable_client}])
AC_ARG_ENABLE([server], [AS_HELP_STRING([--enable-server],
			[build server code [no]])],, [enable_server=no])
AC_ARG_WITH([group], [AS_HELP_STRING([--with-group=GROUP],
			[group for device node access [isrusers]])],,
			[with_group=isrusers])

PROCESS_ENABLE_VAR([$enable_client], [WANT_CLIENT],
			[whether we should build the client])
PROCESS_ENABLE_VAR([$enable_server], [WANT_SERVER],
			[whether we should build the server])
AM_CONDITIONAL([WANT_COMMON],
			[test z$enable_client = zyes -o z$enable_server = zyes])

AC_MSG_CHECKING([which VMM drivers to build])
REQUESTED_VMMS=`echo "$enable_vmm_drivers" | sed -e 's/,/ /g'`
AC_SUBST([REQUESTED_VMMS])
export REQUESTED_VMMS
vmms=`$am_make -f $srcdir/vmm.mk --no-print-directory list_chosen_vmms`
unknown_vmms=`$am_make -f $srcdir/vmm.mk --no-print-directory list_invalid_vmms`
if test -n "$unknown_vmms" ; then
	AC_MSG_ERROR([unknown VMM drivers requested: $unknown_vmms])
fi
if test -n "$vmms" ; then
	AC_MSG_RESULT([$vmms])
else
	AC_MSG_RESULT([none])
fi
AM_CONDITIONAL([WANT_VBOX_XPCOM], [WANT_VMM([virtualbox])])
AM_CONDITIONAL([WANT_LIBVDISK], [WANT_VMM([vmware])])

if test z$enable_client = zyes ; then
	AC_MSG_CHECKING([group for OpenISR device nodes])
	AC_MSG_RESULT([$with_group])
	AC_SUBST([ISRGROUP], [$with_group])
fi

build_32=no
if WANT_VMM([vmware]) ; then
	# See if we're on an x86_64 system with multilib support.  If so, build
	# both 32-bit and 64-bit versions of libvdisk.
	if test z$host_cpu = zx86_64; then
		CHECK_COMPILER_OPTION([-m32])
		if test z$success = zyes ; then
			build_32=yes
			FIND_DIR([32-bit system libraries],
					[$LIBVDISK_PATH32 /usr/lib32 /usr/lib],
					[LIBVDISK_DIRPATH_32])
		else
			AC_MSG_WARN([cannot build 32-bit libvdisk; building only 64-bit version])
		fi
		FIND_DIR([64-bit system libraries],
					[$LIBVDISK_PATH /usr/lib64 /usr/lib],
					[LIBVDISK_DIRPATH])
	else
		FIND_DIR([system libraries], [$LIBVDISK_PATH /usr/lib],
					[LIBVDISK_DIRPATH])
	fi
fi
AM_CONDITIONAL([LIBVDISK_BUILD_32], [test z$build_32 = zyes])
AC_ARG_VAR([LIBVDISK_PATH], [destination directory for native libvdisk])
AC_ARG_VAR([LIBVDISK_PATH32], [destination directory for 32-bit libvdisk (if built)])

# Checks for programs.
AC_PATH_PROG([PERL], [perl], [no])
if test z$PERL = zno ; then
	AC_MSG_ERROR([Perl not found])
fi
AC_SUBST([PERL])
AC_ARG_VAR([PERL], [path to Perl])

if WANT_VMM([virtualbox]) ; then
	AC_PATH_PROG([PYTHON], [python], [no])
	if test z$PYTHON = zno ; then
		AC_MSG_ERROR([Python not found])
	fi
	AC_SUBST([PYTHON])
	AC_ARG_VAR([PYTHON], [path to Python])
	ver=`$PYTHON -V 2>&1 | cut -f2 -d\  `
	CHECK_VERSION_VAL([python], [$ver], [2.4])
fi

# Checks for kernel features.
if test z$enable_client = zyes ; then
	RUN_TEST([COMPILE], [whether loop.h is usable],
				[AC_LANG_PROGRAM([#include <linux/loop.h>], 
				[unsigned get=LOOP_GET_STATUS64;
				unsigned set=LOOP_SET_STATUS64;])])
	if test z$success = zno ; then
		AC_MSG_ERROR([kernel headers in /usr/include/linux are too old])
	fi
fi

if WANT_VMM([vmware]) ; then
	RUN_TEST([COMPILE], [for lba_capacity_2 in hd_driveid],
				[AC_LANG_PROGRAM([#include <linux/hdreg.h>], 
				[struct hd_driveid id;
				unsigned long long cap=id.lba_capacity_2;])])
	if test z$success = zno ; then
		AC_MSG_ERROR([kernel headers in /usr/include/linux are too old])
	fi
fi

# Checks for libraries.
AC_ARG_WITH([ssl], [AS_HELP_STRING([--with-ssl=DIR],
			[look for OpenSSL libraries in DIR])])
AC_ARG_WITH([zlib], [AS_HELP_STRING([--with-zlib=DIR],
			[look for zlib in DIR])])
AC_ARG_WITH([curl], [AS_HELP_STRING([--with-curl=DIR],
			[look for libcurl in DIR])])

if test z$enable_client = zyes ; then
	FIND_LIBRARY([libcurl], [curl], [curl_easy_init], [curl/curl.h],
				[$with_curl /usr/local /usr])
	if test ! -x $FOUND_PATH/bin/curl-config ; then
		AC_MSG_ERROR([cannot find curl-config])
	fi
	ver=`$FOUND_PATH/bin/curl-config --version | cut -f2 -d\  `
	CHECK_VERSION_VAL([curl], [$ver], [7.12.3])
	
	PKG_CHECK_MODULES([OSSP_UUID], [ossp-uuid])
fi

if test z$enable_client = zyes -o z$enable_server = zyes ; then
	FIND_LIBRARY([libcrypto], [crypto], [EVP_EncryptUpdate],
				[openssl/evp.h openssl/blowfish.h],
				[$with_ssl /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/local /usr])
	
	FIND_LIBRARY([zlib], [z], [inflate], [zlib.h],
				[$with_zlib /usr/local /usr])
fi

if WANT_VMM([vmware]) ; then
	# We don't provide a --with-dl=DIR option because this is supposed
	# to be a system function.
	FIND_LIBRARY([libdl], [dl], [dlopen], [dlfcn.h], [/usr])
fi

AC_SUBST([pkgsysconfdir], [\$\(sysconfdir\)/$PACKAGE])
AC_SUBST([initexecdir], [\$\(sysconfdir\)/init.d])
AC_CONFIG_FILES([Makefile
                 conf/Makefile
                 client/Makefile
                 kernel/Makefile
                 locksrv/Makefile
                 parcelkeeper/Makefile
                 sqlite/Makefile
                 tools/Makefile
                 vmm/Makefile
                 vmm/libvdisk/Makefile
                 vmm/xpcom/Makefile])
AC_OUTPUT
