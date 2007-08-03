#!/usr/bin/perl

use File::Copy;
use File::Path;
use strict;
use warnings;

our $srccfg = $ARGV[0];
our $src = $ARGV[1];
our $dstcfg = $ARGV[2];
our $dst = $ARGV[3];
our $bindir = ".";
our @versions;

sub init_dest {
	print "Initializing destination directory...\n";
	die "Destination $dst already exists" if -e $dst;
	mkpath $dst;
	copy("$src/lockholder.log", "$dst/lockholder.log") or die;
	die if ! -l "$src/last";
	symlink(readlink("$src/last"), "$dst/last") or die;

	die "$srccfg does not exist" unless -e $srccfg;
	open(KR, ">$dst/keyroot") or die;
	open(PC, $srccfg) or die;
	foreach (<PC>) {
		print KR "$1\n" if /^KEYROOT=(.*)$/;
	}
	close PC;
	close KR;
}

sub prepare_version {
	my $ver = shift;

	print "Unpacking version $ver...\n";
	die unless -e "$src/$ver/cfg.tgz.enc" && -e "$src/$ver/keyring.enc";
	mkpath "$dst/$ver";
	system("openssl enc -d -bf -in '$src/$ver/cfg.tgz.enc' " .
				"-pass 'file:$dst/keyroot' -nosalt | " .
				"tar xzC '$dst/$ver'") == 0 or die;
	if (! -e "$dst/$ver/cfg/keyring.bin") {
		system("openssl enc -d -bf -in '$src/$ver/keyring.enc' " .
				"-out '$dst/$ver/keyring.old' " .
				"-pass 'file:$dst/keyroot' -nosalt") == 0
				or die;
	}
}

sub upgrade_keyring {
	my $ver = shift;

	print "Converting keyring for $ver...\n";
	if (-e "$dst/$ver/cfg/keyring.bin") {
		system("$bindir/convert-keyring -b " .
					"'$dst/$ver/cfg/keyring.bin' " .
					"'$dst/$ver/keyring'") == 0 || die;
	} elsif (-e "$dst/$ver/keyring.old") {
		system("$bindir/convert-keyring '$dst/$ver/keyring.old' " .
					"'$dst/$ver/keyring'") == 0 || die;
	} else {
		die;
	}
	unlink(glob("$dst/$ver/cfg/keyring.bin*"), "$dst/$ver/keyring.old");
}

sub update_chunks {
	my $ver = shift;
	my $chunks_per_dir = shift;

	print "Updating chunks for $ver...\n";
	mkdir("$dst/$ver/hdk") or die;
	system("$bindir/convert-chunks '$dst/mapdb' '$dst/$ver/keyring' " .
				"'$src/$ver/hdk' '$dst/$ver/hdk' " .
				"$chunks_per_dir") == 0 or die;
}

sub rewrite_keyring {
	my $ver = shift;
	my $result;

	print "Updating keyring for $ver...\n";
	# The only way to do cross-table updates in SQLite (without using
	# temporary tables or INSERT OR REPLACE) is to have multiple
	# sub-selects in the UPDATE statement, one per column, and those
	# sub-selects aren't optimized out.  We go the INSERT OR REPLACE route.
	open(RES, "-|", "$bindir/query", "$dst/$ver/keyring", "-a",
				"map:$dst/mapdb",
				"INSERT OR REPLACE INTO keys " .
				"(chunk, tag, key, compression) " .
				"SELECT keys.chunk, map.tags.new_tag, " .
				"map.tags.new_key, map.tags.new_compress " .
				"FROM keys JOIN map.tags ON " .
				"keys.tag = map.tags.old_tag") or die;
	<RES> =~ /([0-9]+) rows updated/ or die;
	close(RES);
	die if $? != 0;
	print "$1\n";
}

if ($#ARGV + 1 != 4) {
	print "Usage: $0 src-parcelcfg src-dir dst-parcelcfg dst-dir\n";
	exit 1;
}

opendir(SRC, $src) || die "Can't open directory $src";
@versions = sort grep {/[0-9]+/} readdir SRC or die;
closedir(SRC);

my $chunks_per_dir;
open(IDX, "$src/$versions[0]/hdk/index.lev1") or die;
while (<IDX>) {
	$chunks_per_dir = $1 if /^CHUNKSPERDIR= ([0-9]+)$/;
}
close(IDX);

init_dest;
foreach my $ver (@versions) {
	prepare_version $ver;
	upgrade_keyring $ver;
	update_chunks($ver, $chunks_per_dir);
}
foreach my $ver (@versions) {
	rewrite_keyring $ver;
}
# XXX should warn if anything is in the cfg directory which isn't on a
# whitelist
