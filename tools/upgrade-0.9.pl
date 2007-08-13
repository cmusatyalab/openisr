#!/usr/bin/perl

use File::Copy;
use File::Path;
use File::stat;
use strict;
use warnings;

our $srccfg = $ARGV[0];
our $src = $ARGV[1];
our $dstcfg = $ARGV[2];
our $dst = $ARGV[3];
our $bindir = ".";
our @versions;
our %parcelcfg;

sub gen_keyroot {
	my $keyroot;

	open(KR, "-|", "openssl rand -rand /dev/urandom -base64 15 2>/dev/null")
		or die;
	$keyroot = <KR>;
	close KR;
	$? == 0 or die;
	chomp $keyroot;
	$parcelcfg{"NEWKEYROOT"} = $keyroot;
}

sub process_parcel_cfg {
	my $file;
	my $key;
	my $uuid;

	print "Generating new parcel.cfg...\n";
	foreach $file ($srccfg, "$src/last/hdk/index.lev1") {
		open(IF, $file) or die "Couldn't open $file";
		foreach (<IF>) {
			/^([A-Z]+)[ =]+(.+)$/ or die;
			$parcelcfg{$1} = $2;
		}
		close IF;
	}
	$uuid = `uuidgen`;
	die if $? or !defined $uuid;
	chomp $uuid;
	die "File $dstcfg already exists" if -e $dstcfg;
	open(OF, ">$dstcfg") or die;
	print OF <<EOF;
VERSION = 3
UUID = $uuid
VMM = vmware
CRYPTO = aes-sha1
COMPRESS = zlib,lzf
EOF
	foreach $key ("PROTOCOL", "SERVER", "RPATH", "WPATH", "KEYROOT",
				"MAXKB", "CHUNKSIZE", "NUMCHUNKS",
				"CHUNKSPERDIR") {
		die unless defined $parcelcfg{$key};
		if ($key eq "KEYROOT") {
			print OF "$key = $parcelcfg{'NEWKEYROOT'}\n";
		} else {
			print OF "$key = $parcelcfg{$key}\n";
		}
	}
	close OF;
}

sub init_dest {
	print "Initializing destination directory...\n";
	die "Destination $dst already exists" if -e $dst;
	mkpath $dst;
	copy("$src/lockholder.log", "$dst/lockholder.log") or die;
	die if ! -l "$src/last";
	symlink(readlink("$src/last"), "$dst/last") or die;
}

sub prepare_version {
	my $ver = shift;
	my $keyroot = $parcelcfg{"KEYROOT"};

	print "Unpacking version $ver...\n";
	die unless -e "$src/$ver/cfg.tgz.enc" && -e "$src/$ver/keyring.enc";
	mkpath "$dst/$ver";
	system("openssl enc -d -bf -in '$src/$ver/cfg.tgz.enc' " .
				"-pass 'pass:$keyroot' -nosalt | " .
				"tar xzC '$dst/$ver'") == 0 or die;
	if (! -e "$dst/$ver/cfg/keyring.bin") {
		system("openssl enc -d -bf -in '$src/$ver/keyring.enc' " .
				"-out '$dst/$ver/keyring.old' " .
				"-pass 'pass:$keyroot' -nosalt") == 0
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

	print "Updating chunks for $ver...\n";
	mkdir("$dst/$ver/hdk") or die;
	system("$bindir/convert-chunks '$dst/mapdb' '$dst/$ver/keyring' " .
				"'$src/$ver/hdk' '$dst/$ver/hdk' " .
				$parcelcfg{"CHUNKSPERDIR"}) == 0 or die;
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
	die "Updated only $1 keys; expected $parcelcfg{'NUMCHUNKS'}"
		if $1 != $parcelcfg{"NUMCHUNKS"};

	# Vacuum can't occur within a transaction
	system("$bindir/query -t '$dst/$ver/keyring' VACUUM") == 0 or die;
	open(CHK, "-|", "$bindir/query", "$dst/$ver/keyring",
				"PRAGMA integrity_check") or die;
	<CHK> =~ /^ok\n$/ or die;
	close(CHK);
	die if $? != 0;
}

sub finish_version {
	my $ver = shift;
	my $keyroot = $parcelcfg{"NEWKEYROOT"};
	my @files;
	my $pattern;
	my $file;
	my $stat;

	print "Packing version $ver...\n";
	opendir(CFG, "$dst/$ver/cfg") or die;
	@files = readdir(CFG);
	closedir(CFG);
	foreach $pattern ("\.{1,2}", "nvram", ".*\.vmdk", ".*\.vmem",
				".*\.vmss", ".*\.vmx", ".*\.vmxf",
				"vmware[-0-9]*\.log") {
		eval "\@files = grep(!/^$pattern\$/, \@files)";
	}
	foreach $file (@files) {
		if ($file =~ /\.WRITELOCK$/) {
			print "Removing $ver/cfg/$file\n";
			unlink("$dst/$ver/cfg/$file") or die;
		} else {
			print "Unknown file in $ver/cfg: $file\n";
		}
	}
	system("tar cC '$dst/$ver' cfg | gzip -c9 | openssl enc " .
				"-aes-128-cbc -out '$dst/$ver/cfg.tgz.enc' " .
				"-pass 'pass:$keyroot' -salt") == 0 or die;
	system("openssl enc -aes-128-cbc -in '$dst/$ver/keyring' " .
			"-out '$dst/$ver/keyring.enc' " .
			"-pass 'pass:$keyroot' -salt") == 0 or die;
	unlink("$dst/$ver/keyring") or die;
	system("rm -rf '$dst/$ver/cfg'") == 0 or die;
	$stat = stat("$src/$ver/keyring.enc") or die;
	# isr_srv_ls.pl uses the keyring mtime as the checkin time, so we
	# need to carry this over
	utime(time, $stat->mtime, "$dst/$ver/keyring.enc") or die;
}

if ($#ARGV + 1 != 4) {
	print "Usage: $0 src-parcelcfg src-dir dst-parcelcfg dst-dir\n";
	exit 1;
}

opendir(SRC, $src) || die "Can't open directory $src";
@versions = sort grep {/[0-9]+/} readdir SRC or die;
closedir(SRC);

gen_keyroot;
process_parcel_cfg;
init_dest;
foreach my $ver (@versions) {
	prepare_version $ver;
	upgrade_keyring $ver;
	update_chunks $ver;
}
foreach my $ver (@versions) {
	rewrite_keyring $ver;
	finish_version $ver;
}
unlink("$dst/mapdb") == 1 or die;
print "Upgrade complete\n";
