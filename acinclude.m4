#
# acinclude.m4 - autoconf macros for the OpenISR (R) system
#
# Copyright (C) 2007 Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

# PROCESS_ENABLE_VAR([SHELL_VAR], [AUTOMAKE_VAR], [MESSAGE])
# ----------------------------------------------------------
AC_DEFUN([PROCESS_ENABLE_VAR], [
	AC_MSG_CHECKING($3)
	if test x$1 = xyes; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi
	AM_CONDITIONAL($2, [test x$1 = xyes])
])


# FIND_LIBRARY([PRETTY_NAME], [LIBRARY_NAME], [LIBRARY_FUNCTION],
#              [HEADER_LIST], [PATH_LIST])
# The paths in PATH_LIST are searched to determine whether they contain the
# first header in HEADER_LIST.  If so, that path is added to the include and
# library paths.  Then the existence of all headers in HEADER_LIST, and of
# LIBRARY_FUNCTION within LIBRARY_NAME, is validated.  $FOUND_PATH is
# set to the name of the directory we've decided on.
# -----------------------------------------------------------------------------
AC_DEFUN([FIND_LIBRARY], [
	AC_MSG_CHECKING([for $1])
	for firsthdr in $4; do break; done
	found_lib=0
	for path in $5
	do
		if test -r $path/include/$firsthdr ; then
			found_lib=1
			CPPFLAGS="$CPPFLAGS -I${path}/include"
			LDFLAGS="$LDFLAGS -L${path}/lib"
			AC_MSG_RESULT([$path])
			break
		fi
	done
	
	if test $found_lib = 0 ; then
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([cannot find $1 in $5])
	fi
	
	# By default, AC_CHECK_LIB([foo], ...) will add "-lfoo" to the linker
	# flags for ALL programs and libraries, which is not what we want.
	# We put a no-op in the third argument to disable this behavior.
	AC_CHECK_HEADERS([$4],, AC_MSG_FAILURE([cannot find $1 headers]))
	AC_CHECK_LIB([$2], [$3], :, AC_MSG_FAILURE([cannot find $1 library]))
	FOUND_PATH=$path
])


# CHECK_VERSION_VAL([PACKAGE], [FOUND], [MINIMUM])
# ------------------------------------------------
AC_DEFUN([CHECK_VERSION_VAL], [
	AC_MSG_CHECKING([for $1 >= $3])
	
	found_major=`echo $2 | cut -f1 -d.`
	found_minor=`echo $2 | cut -f2 -d.`
	found_rev=`echo $2 | cut -f3 -d.`
	want_major=`echo $3 | cut -f1 -d.`
	want_minor=`echo $3 | cut -f2 -d.`
	want_rev=`echo $3 | cut -f3 -d.`
	
	if test z$found_rev = z ; then
		found_rev=0
	fi
	if test z$want_rev = z ; then
		want_rev=0
	fi
	
	AC_MSG_RESULT([$2])
	
	if test $found_major -eq $want_major ; then
		if test $found_minor -eq $want_minor ; then
			if test $found_rev -lt $want_rev ; then
				AC_MSG_ERROR([$1 too old])
			fi
		elif test $found_minor -lt $want_minor ; then
			AC_MSG_ERROR([$1 too old])
		fi
	elif test $found_major -lt $want_major ; then
		AC_MSG_ERROR([$1 too old])
	fi
])


# RUN_TEST([TYPE], [MESSAGE], [TEST_PROGRAM])
# Run test of type TYPE against TEST_PROGRAM, and set $success to "yes" or
# "no" depending on whether it succeeds.  Print MESSAGE beforehand and result
# afterward.  TYPE can be [COMPILE], [LINK], or [RUN].
# ---------------------------------------------------------------------------
AC_DEFUN([RUN_TEST], [
	AC_MSG_CHECKING($2)
	AC_$1_IFELSE([$3], [success=yes], [success=no])
	if test z$success = zyes ; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi
])


# CHECK_COMPILER_OPTION([OPTION])
# If the compiler supports the command line option OPTION, set $success
# to "yes".  Otherwise, set $success to "no".
# ---------------------------------------------------------------------
AC_DEFUN([CHECK_COMPILER_OPTION], [
	saved_cflags="$CFLAGS"
	CFLAGS="$saved_cflags $1"
	RUN_TEST([COMPILE], [if compiler supports $1], [AC_LANG_SOURCE([])])
	CFLAGS="$saved_cflags"
])


# FIND_DIR([PRETTY_NAME], [PATH_LIST], [SUBST])
# Print a message saying that we are looking for the path to PRETTY_NAME.
# Check each of the paths in PATH_LIST to see whether it is a valid directory.
# If so, subst the path into SUBST and stop.  If none of the paths are valid,
# error out.
# ----------------------------------------------------------------------------
AC_DEFUN([FIND_DIR], [
	AC_MSG_CHECKING([for path to $1])
	found_dir=0
	for path in $2
	do
		if test -d $path ; then
			AC_MSG_RESULT([$path])
			AC_SUBST([$3], [$path])
			found_dir=1
			break
		fi
	done
	if test $found_dir = 0 ; then
		AC_MSG_ERROR([not found in $2])
	fi
])
