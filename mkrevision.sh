#!/bin/sh
#
# mkrevision.sh - generate revision headers from Subversion metadata
#
# Copyright (C) 2006-2007 Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

set -e

FILETYPE=$1
SUBDIR=$2

if [ -e .svn ] ; then
	VER=`svnversion .`
	BRANCH=`svn info . | egrep "^URL: " | sed -e "s:^.*/svn/openisr/::" \
				-e "s:/${SUBDIR}$::"`
	REV="$VER ($BRANCH)"
elif [ -d `dirname $0`/.git ] ; then
	REV=`git-describe`
else
	exit 0
fi

# It's better to use a separate object file for the revision data,
# since "svn update" will then force a relink but not a recompile.
# However, we shouldn't do this for shared libraries, because then
# "rcs_revision" becomes part of the library's ABI.
case $FILETYPE in
object)
	FILENAME=revision.c
	cat > $FILENAME-new <<- EOF
		const char *rcs_revision = "$REV";
		
		#ifdef __KERNEL__
		#include <linux/module.h>
		MODULE_INFO(revision, "$REV");
		#endif
	EOF
	;;
header)
	FILENAME=revision.h
	cat > $FILENAME-new <<- EOF
		#define RCS_REVISION "$REV"
	EOF
	;;
perl)
	FILENAME=IsrRevision.pm
	cat > $FILENAME-new <<- EOF
		package Isr;
		\$RCS_REVISION = "$REV";
		1;
	EOF
	;;
*)
	echo "Usage: $0 {object|header|perl} <subdir>" >&2
	exit 1
	;;
esac

if [ -f $FILENAME ] && cmp -s $FILENAME $FILENAME-new ; then
	# No need to rebuild if the actual content of $FILENAME
	# hasn't changed
	rm -f $FILENAME-new
else
	mv $FILENAME-new $FILENAME
fi
