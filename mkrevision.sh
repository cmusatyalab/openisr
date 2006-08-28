#!/bin/sh

set -e

FILETYPE=$1
SUBDIR=$2

[ -e .svn ] || exit 0

VER=`svnversion .`
BRANCH=`svn info . | egrep "^URL: " | sed -e "s:^.*/svn/openisr/::" \
		-e "s:/${SUBDIR}$::"`

# It's better to use a separate object file for the revision data,
# since "svn update" will then force a relink but not a recompile.
# However, we shouldn't do this for shared libraries, because then
# "svn_revision" and "svn_branch" become part of the library's ABI.
case $FILETYPE in
object)
	FILENAME=revision.c
	echo "const char *svn_revision = \"$VER\";" > $FILENAME-new
	echo "const char *svn_branch = \"$BRANCH\";" >> $FILENAME-new
	;;
header)
	FILENAME=revision.h
	echo "#define SVN_REVISION \"$VER\"" > $FILENAME-new
	echo "#define SVN_BRANCH \"$BRANCH\"" >> $FILENAME-new
	;;
*)
	echo "Usage: $0 {object|header} <subdir>" >&2
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
