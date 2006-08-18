#!/bin/sh

set -e

[ -e .svn ] || exit 0

VER=`svnversion .`
echo "const char *svn_revision = \"$VER\";" > revision.c-new
BRANCH=`svn info . | egrep "^URL: " | sed -e "s:^.*/svn/openisr/::" \
		-e "s:/vulpes$::"`
echo "const char *svn_branch = \"$BRANCH\";" >> revision.c-new

if [ -f revision.c ] && cmp -s revision.c revision.c-new ; then
	# No need to rebuild if the actual content of revision.c
	# hasn't changed
	rm -f revision.c-new
else
	mv revision.c-new revision.c
fi
