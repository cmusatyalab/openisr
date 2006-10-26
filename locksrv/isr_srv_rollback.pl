#!/usr/bin/perl

#################################################################
# isr_srv_rollback.pl - Revert back to a previous version
#
# $Id$
#################################################################

#
#                  Internet Suspend/Resume (Release 0.5)
#           A system for capture and transport of PC state
#
#            Copyright (c) 2004, Carnegie Mellon University
#              Copyright (c) 2002-2004, Intel Corporation
#                         All Rights Reserved
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

##########
# Prologue
##########
use strict;
use Getopt::Std;
use File::stat;
use Socket;
use Sys::Hostname;
use lib "/usr/local/isr/bin";
use Server;
use sigtrap qw(die normal-signals);
$| = 1; # Autoflush output on every print statement

####################
# begin main routine
####################

#
# Variables
#
my $parcelpath;
my $hostname;
my $verbose;
my $parceldir;
my $targetver;
my $targetdir;
my $lastver;
my $lastdir;
my $cachedir;
my $hostname;
my $ipaddress;
my $parcel;
my $ipaddr;
my $chunksperdir;
my $targetkeyring;
my $lastkeyring;
my $keyroot;

# Various temporary variables
my $version;
my $this_hdkdir;
my $chunk;
my $chunkdir;
my $chunkcount;
my $i;
my $line;
my $tag;
my $key;
my $reason;
my $lock;

# Arrays and list
my @filelist = ();
my @chunkdirlist = ();
my @chunklist = ();
my @targettags = ();
my @lasttags = ();

#
# Parse the command line args
#
no strict 'vars';
getopts('hlp:v:Vk:');

if ($opt_h) {
    usage();
}

$lock = $opt_l;
$parcelpath = $opt_p;
$keyroot = $opt_k;
$targetver = $opt_v;

if (!$parcelpath) {
    usage("Missing parcel path (-p)");
}
if (!$keyroot) {
    usage("Missing keyroot (-k)");
}
if (!$targetver or $targetver < 1) {
    usage("Missing or incorrect target version number (-v)");
}
$parceldir = "$Server::CONTENT_ROOT" . "$parcelpath";
$verbose = $opt_V;
use strict 'vars';

# Assign a few variables that we will need later
$hostname = hostname();
($parcel = $parceldir) =~ s#.*/##s; # extract the parcel name from the parcel path

#
# Make sure the parcel directory exists
#
(-e $parceldir)
    or errexit("$parceldir does not exist.");

#
# Acquire the lock (if called with -l)
# 
if ($lock) {
    system("$Server::SRVBIN/isr_srv_lock.pl -p $parcelpath -n $hostname -a > $parceldir/acquire_attempt") == 0
	or system_errexit("Unable to acquire lock. See $parceldir/acquire_attempt for details.");
    print("Acquired lock.\n")
	if $verbose;
}

# 
# Make sure the target version exists
#
$targetdir = "$parceldir/" . sprintf("%06d", $targetver);
if (!-e $targetdir) {
    errexit("Error: Target version $targetver does not exist in $parceldir.");
}

#
# Determine the most recent (last) version number
# 
opendir(DIR, $parceldir)
    or errexit("Could not open directory $parceldir");
@filelist = reverse sort grep(/^\d+$/, readdir(DIR)); # numeric names only
closedir(DIR);
$lastver = int(@filelist[0]);
$lastdir = "$parceldir/" . sprintf("%06d", $lastver);

#
# Determine the number of chunks per directory
#
$chunksperdir = get_value("$lastdir/hdk/index.lev1", "CHUNKSPERDIR");

# 
# No need to do anything if target is also last
#
if ($targetver == $lastver) {
    exit 0;
}

#
# Load the keyring content tags from the target version and the last version
#
print "Decrypting and loading target and last keyrings.\n"
    if $verbose;

$targetkeyring = "$targetdir/keyring";
$lastkeyring = "$lastdir/keyring";

# Decrypt the keyrings
unlink($targetkeyring, $lastkeyring);
system("openssl enc -d -bf -in $targetkeyring.enc -out $targetkeyring -pass pass:$keyroot -nosalt") == 0
    or system_errexit("Unable to decode $targetkeyring.enc");
system("openssl enc -d -bf -in $lastkeyring.enc -out $lastkeyring -pass pass:$keyroot -nosalt") == 0
    or system_errexit("Unable to decode $lastkeyring.enc");

# Load the target keyring
open(INFILE, $targetkeyring)
    or unix_errexit("Unable to open $targetkeyring");
$i = 0;
while ($line = <INFILE>) {
    chomp($line);
    ($tag, $key) = split(" ", $line);
    $targettags[$i] = $tag;
    $i++;
}
close(INFILE)
    or unix_errexit("Unable to close $targetkeyring");

# Load the last keyring
open(INFILE, $lastkeyring)
    or unix_errexit("Unable to open $lastkeyring");
$i = 0;
while ($line = <INFILE>) {
    chomp($line);
    ($tag, $key) = split(" ", $line);
    $lasttags[$i] = $tag;
    $i++;
}
close(INFILE)
    or unix_errexit("Unable to close $lastkeyring");

#
# Create the cache directory where we'll be writing our updates
#
$cachedir = "$parceldir/cache";
system("rm -rf $cachedir") == 0
    or system_errexit("Unable to remove $cachedir");
system("mkdir $cachedir") == 0
    or system_errexit("Unable to create $cachedir");
system("mkdir $cachedir/hdk") == 0
    or system_errexit("Unable to create $cachedir/hdk");

#
# Main rollback loop nest
#
for ($version = $targetver; $version < $lastver; $version++) {
    print "\n***Version $version\n"
	if $verbose;
    
    $chunkcount = 0;
    $this_hdkdir = "$parceldir/" . sprintf("%06d", $version) . "/hdk";

    # Enumerate the chunk directories in this parcel version
    opendir(DIR, "$this_hdkdir")
	or errexit("Could not open hdk directory $this_hdkdir");
    @chunkdirlist = sort grep(/^\d+$/, readdir(DIR)); # numeric names only
    closedir(DIR);

    # Iterate over the chunk directories in this parcel version
    foreach $chunkdir (@chunkdirlist) {

	# Enumerate the chunks in this chunk directory
	opendir(DIR, "$this_hdkdir/$chunkdir")
	    or errexit("Could not open directory $this_hdkdir/$chunkdir");
	@chunklist = sort grep(/^\d+$/, readdir(DIR)); # numeric names only
	closedir(DIR);

	# Iterate over each chunk in the chunk directory
	foreach $chunk (@chunklist) {

	    # Create this chunkdir in the cache if it does not exist
	    if (!-e "$cachedir/hdk/$chunkdir") {
		system("mkdir $cachedir/hdk/$chunkdir") == 0
		    or system_errexit("Unable to create $cachedir/hdk/$chunkdir");
	    }

	    # This is tricky: Copy chunk c to the cache only if (1) a
	    # file called c does not exist in the cache AND (2) the
	    # contents of c have changed between target and
	    # last. Condition (1) is necessary for correctness, while
	    # condition (2) is necessary for space efficiency.
	    $i = get_offset($chunkdir, $chunk, $chunksperdir);
	    if (!-e "$cachedir/hdk/$chunkdir/$chunk" and ($targettags[$i] ne $lasttags[$i])) {
		$chunkcount++;
		print "Copying $chunkdir/$chunk to cache\n"
		    if $verbose;
		system("cp $this_hdkdir/$chunkdir/$chunk $cachedir/hdk/$chunkdir") == 0
		    or system_errexit("Unable to copy $this_hdkdir/$chunkdir/$chunk to cache");
	    }
	    else {
		$reason = "";
		if (-e "$cachedir/hdk/$chunkdir/$chunk") {
		    $reason = "exists";
		}
		if ($targettags[$i] eq $lasttags[$i]) {
		    $reason = $reason . "nochange";
		}
		print "Chunk $chunkdir/$chunk not copied to cache [$reason]\n"
		    if $verbose;
	    }
	}
    }
    print "Copied $chunkcount chunks for version $version.\n"
	if $verbose;
}

#
# Copy the encryption and virtualization files from the target to the cache
#
print "Copying encryption and virtualization files...\n"
    if $verbose;
system("cp $targetdir/{cfg.tgz.enc,keyring.enc} $cachedir") == 0
    or system_errexit("Unable to copy files from $targetdir to $cachedir.");
system("cp $targetdir/hdk/index.lev1 $cachedir/hdk") == 0
    or system_errexit("Unable to copy $targetdir/hdk/index.lev1 to $cachedir/hdk");

#
# Commit the updates in the cache
# 
print "Committing updates...\n"
    if $verbose;
system("$Server::SRVBIN/isr_srv_commit.pl -p $parcelpath") == 0
    or system_errexit("Unable to commit version $targetver.");

#
# Clean up and exit
#
exit 0;


##################
# end main routine
##################


#
# usage - print help message and terminate
#
sub usage
{
    my $msg = shift;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 

    if ($msg) {
        print "$progname: $msg\n";
    }

    print "Usage: $progname [-hlV] -p <path> -v <ver> -k <key>\n";
    print "Options:\n";
    print "  -h        Print this message\n";
    print "  -k <key>  Keyroot for this parcel\n";
    print "  -l        Acquire and release the parcel lock\n";
    print "  -V        Be verbose\n";
    print "  -p <path> Relative parcel path (userid/parcel)\n";
    print "  -v <ver>  Target version to revert to\n";
    print "\n";

    exit 0;
}


#############################################################
# END - This block of code executes when the program terminates 
# for any reason, either by normal exit or an uncaught signal.
#############################################################
END {

    print("Cleaning up.\n")
	if $verbose;

    #
    # Release the lock if we had already acquired it
    #
    if ($lock and $parcelpath and $hostname) { 
	if (system("$Server::SRVBIN/isr_srv_lock.pl -p $parcelpath -n $hostname -c > /dev/null") == 0) {
	    if (system("$Server::SRVBIN/isr_srv_lock.pl -p $parcelpath -n $hostname -R > $parcelpath/release_attempt") == 0) {
		print("Released the lock.\n")
		    if $verbose;
	    }
	    else {
		print ("Unable to release lock. See $parcelpath/release_attempt for details.\n");
	    }
	}
    }
}
