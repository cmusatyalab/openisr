#
# modbuild.pm - openisr-config module to build kernel modules from source
#
# Copyright (C) 2007-2008 Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public License,
# Version 1.0 which can be found in the file named LICENSE.Eclipse.  ANY USE,
# REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S
# ACCEPTANCE OF THIS AGREEMENT
#

use strict;
use warnings;
use File::Temp qw/tempdir/;

our $warn_initscript = 1;

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
		or fail "Couldn't read config.h";
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
		or fail "Couldn't build kernel source";

	status "Installing kernel modules...";
	system("make install") == 0
		or fail "Couldn't install kernel modules";
	system("depmod") == 0
		or fail "Couldn't run depmod";

	# If our working directory is inside $topdir when we exit, some
	# versions of File::Tree will fail when trying to delete $topdir
	chdir("/");
}

1;
