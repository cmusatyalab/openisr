##### http://autoconf-archive.cryp.to/ac_check_curl.html
#
# SYNOPSIS
#
#   AC_CHECK_CURL(version, action-if, action-not)
#
# DESCRIPTION
#
#   Defines CURL_LIBS, CURL_CFLAGS. See curl-config(1) man page.
#
# LAST MODIFICATION
#
#   2005-09-20
#
# COPYLEFT
#
#   Copyright (c) 2005 Akos Maroy <darkeye@tyrell.hu>
#
#   Copying and distribution of this file, with or without
#   modification, are permitted in any medium without royalty provided
#   the copyright notice and this notice are preserved.

AC_DEFUN([AC_CHECK_CURL], [
  succeeded=no

  if test -z "$CURL_CONFIG"; then
    AC_PATH_PROG(CURL_CONFIG, curl-config, no)
  fi

  if test "$CURL_CONFIG" = "no" ; then
    AC_MSG_ERROR([the curl-config script could not be found])
  else
    dnl curl-config --version returns "libcurl <version>", thus cut the number
    CURL_VERSION=`$CURL_CONFIG --version | cut -d" " -f2`
    AC_MSG_CHECKING(for curl >= $1)
        VERSION_CHECK=`expr $CURL_VERSION \>\= $1`
        if test "$VERSION_CHECK" = "1" ; then
            AC_MSG_RESULT(yes)
            succeeded=yes
        else
            ## If we have a custom action on failure, don't print errors, but
            ## do set a variable so people can do so.
            ifelse([$3], ,echo "can't find curl >= $1",:)
        fi
  fi

  if test $succeeded = yes; then
     ifelse([$2], , :, [$2])
  else
     ifelse([$3], , AC_MSG_ERROR([Library requirements (curl) not met.]), [$3])
  fi
])