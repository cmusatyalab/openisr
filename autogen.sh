#!/bin/sh

# We're supposed to use "autoreconf", but "autoreconf" doesn't honor -I for
# aclocal
aclocal -I autoconf/
autoconf
automake
