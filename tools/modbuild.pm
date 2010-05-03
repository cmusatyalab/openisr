#
# modbuild.pm - openisr-config module to build kernel modules from source
#
# Copyright (C) 2007-2008 Carnegie Mellon University
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 2 of the GNU General Public License as published
# by the Free Software Foundation.  A copy of the GNU General Public License
# should have been distributed along with this program in the file
# LICENSE.GPL.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#

use strict;
use warnings;
use File::Temp qw/tempdir/;

sub fail_cd {
	my $msg = shift;

	# Prevent errors when File::Tree tries to clean up $topdir
	chdir("/");
	fail $msg;
}

sub build {
	my $topdir;
	my $found_version = 0;

	status "Unpacking kernel module source...";
	$topdir= tempdir("openisr-config-XXXXXXXX", TMPDIR => 1, CLEANUP => 1)
		or fail "Couldn't create temporary directory";
	system("tar xzof " . SHAREDIR . "/openisr-modules.tar.gz -C $topdir " .
				"--no-same-permissions") == 0
		or fail "Couldn't unpack kernel sources";
	chdir("$topdir/openisr-modules")
		or fail "Couldn't chdir";
	open(CFGH, "config.h")
		or fail_cd "Couldn't read config.h";
	while (<CFGH>) {
		next unless /^#define\s+([^\s]+)\s+"([^"]+)"$/;
		if ($1 eq "VERSION") {
			$found_version = 1;
			warning "Expected module version " . VERSION .
						", found $2"
				if $2 ne VERSION;
		}
	}
	close CFGH;
	warning "Unknown module version"
		unless $found_version;

	status "Building kernel modules...";
	system("make") == 0
		or fail_cd "Couldn't build kernel source";

	status "Installing kernel modules...";
	system("make install") == 0
		or fail_cd "Couldn't install kernel modules";
	system("depmod") == 0
		or fail_cd "Couldn't run depmod";

	# If our working directory is inside $topdir when we exit, some
	# versions of File::Tree will fail when trying to delete $topdir
	chdir("/");
}

1;
