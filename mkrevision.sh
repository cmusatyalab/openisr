#!/bin/sh
#
# mkrevision.sh - generate revision headers from Git and Autoconf metadata
#
# Copyright (C) 2006-2008 Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

set -e

BASEDIR=`dirname $0`
BUILDDIR="$1"
REVFILE="$BASEDIR/.gitrevision"

if [ "$2" = "update" ] ; then
	if [ ! -d $BASEDIR/.git ] ; then
		exit 0
	fi
	GIT="git --git-dir=$BASEDIR/.git"

	# git describe will throw a fatal error if there is no predecessor
	# tag to the current commit
	REV=`$GIT describe 2>/dev/null || $GIT rev-parse --short HEAD`
	# Coda-specific workaround: different Coda clients may see different
	# stat information for the same files, which can cause a client to
	# believe the git index is not up-to-date, which could cause the
	# "-dirty" flag to be added against a clean repository.  So we
	# refresh the git index before checking it.
	$GIT update-index --refresh > /dev/null 2>&1 || true
	if $GIT diff-index HEAD | read junk ; then
		# There are uncommitted changes in the working copy
		REV="$REV-dirty"
	fi
	
	if [ -r $REVFILE ] ; then
		OLDREV=`cat $REVFILE`
	else
		OLDREV=""
	fi
	if [ "$REV" != "$OLDREV" ] ; then
		echo $REV > $BASEDIR/.gitrevision
	fi
	exit 0
fi

REV=`cat $REVFILE`
REL=`awk 'BEGIN { FS="\"" } /#define PACKAGE_VERSION/ { print $2 }' \
			$BUILDDIR/config.h`

# It's better to use a separate object file for the revision data,
# since "git pull" will then force a relink but not a recompile.
# However, we shouldn't do this for shared libraries, because then
# "rcs_revision" becomes part of the library's ABI.
case $2 in
object)
	cat > revision.c <<- EOF
		const char *isr_release = "$REL";
		const char *rcs_revision = "$REV";
		
		#ifdef __KERNEL__
		#include <linux/module.h>
		MODULE_VERSION("$REL");
		MODULE_INFO(revision, "$REV");
		#endif
	EOF
	;;
header)
	cat > revision.h <<- EOF
		#define ISR_RELEASE "$REL"
		#define RCS_REVISION "$REV"
	EOF
	;;
*)
	echo "Usage: $0 <build_dir> {update|object|header}" >&2
	exit 1
	;;
esac
