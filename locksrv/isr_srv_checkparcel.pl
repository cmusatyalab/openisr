#!/usr/bin/perl

###################################################################
# isr_srv_checkparcel.pl - check a parcel for consistency
###################################################################

#
#                       Internet Suspend/Resume
#           A system for capture and transport of PC state
#
#              Copyright (c) 2002-2004, Intel Corporation
#          Copyright (c) 2004-2005, Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

###################
# standard prologue
###################
use strict;
use Getopt::Std;
use POSIX;
use lib "/usr/local/isr/bin";
use Server;
use Cwd;
$| = 1; # Autoflush output on every print statement

####################
# begin main routine
####################

# 
# Declare local variables
#

# These are set by command line arguments
my $precommit;
my $contentcheck;
my $strong_contentcheck;
my $verbose;
my $username;
my $parcelname;
my $keyroot;
my $currver;

# Important variables
my $homedir;
my $parceldir;
my $lastver;
my $currdir;
my $currkeyring;
my $currkeyring_enc;
my $parcelcfg;
my $predver;
my $preddir;
my $predkeyring;
my $predkeyring_enc;
my $errors;
my $numdirs;
my $totalchunks;
my $chunksperdir;

# Various temporary variables
my $numchunks;
my $tag;
my $dirname;
my $dirpath;
my $i;
my $chunk;
my $chunkpath;
my $index;
my $dirnum;
my $filenum;
my $dir;
my $filename;

my @files;

# Arrays and list
my @tags;    # array of keyring tags
my %keydiff; # one hash key for every keyring entry that differs

#
# Parse the command line args
#
no strict 'vars';
getopts('Vhcsu:p:v:k:');

if ($opt_h) {
    usage();
}
if (!$opt_p) {
    usage("Missing parcel name (-p)");
}
if (!$opt_k) {
    usage("Missing keyroot (-k)");
}
$username = $opt_u;
$username = $ENV{"USER"} if !$username;
$parcelname = $opt_p;
$parceldir = "$Server::CONTENT_ROOT$username/$parcelname";
$currver = $opt_v;
$verbose = $opt_V;
$keyroot = $opt_k;
$contentcheck = $opt_c;
$precommit = $opt_s;

use strict 'vars';

#
# Make sure the parcel directory exists
#
(-e $parceldir)
    or errexit("$parceldir does not exist");

#
# Determine the last version that was checked in
# 
opendir(DIR, $parceldir)
    or unix_errexit("Could not open directory $parceldir");
@files = reverse sort grep(/^\d+$/, readdir(DIR));
closedir(DIR);
$lastver = int($files[0]);

#
# Make sure that there is a last link and that it points
# to the most recent version
#
chdir("$parceldir/last")
    or errexit("Parcel misconfigured: missing a last link.");
$dir = cwd();
$dir =~ /.+\/(\d+)$/; # extract the filename from the path
$filename = $1;
if ($filename ne sprintf("%06d", $lastver)) {
    errexit("Parcel misconfigured: last link does not point to last.");
}

# 
# Set the current version (default is the most recent)
#
if (!defined($currver)) {
    $currver = $lastver;
}
if ($currver < 1) {
    errexit("Current version must be greater than 0.");
}

# 
# Current version of 1 is OK only if it is also the last version
#
if ($currver == 1 and $currver != $lastver) {
    errexit("Version 1 can only be checked if it is also last");
}

#
# Set the key variables
#
$errors = 0;

# Variables for the current version
$currdir = "$parceldir/" . sprintf("%06d", $currver);
$currkeyring_enc = "$currdir/keyring.enc";
$currkeyring = "/tmp/keyring-curr.$$";
$homedir = (getpwnam($username))[7];
$parcelcfg = "$homedir/.isr/$parcelname/parcel.cfg";

# Variables for the predecessor version (if any)
if ($precommit) {
    $predver = "checkin";
    $preddir = "$parceldir/cache";
} else {
    $predver = $currver - 1; 
    $preddir = "$parceldir/" . sprintf("%06d", $predver);
}
$predkeyring_enc = "$preddir/keyring.enc";
$predkeyring = "/tmp/keyring-pred.$$";

#
# Make sure that the other files we will need are available
#
(-e $currdir)
    or errexit("$currdir does not exist.");
(-e "$currkeyring_enc")
    or errexit("$currkeyring_enc does not exist.");

if (-e $preddir) {
    (-e "$predkeyring_enc")
	or errexit("$predkeyring_enc does not exist.");
}
 
#
# Decrypt the current and predecessor keyrings
#
if (-e $preddir) {
    print "Checking versions $currver and $predver.\n"
	if $verbose;
}
else {
    print "Checking version $currver.\n"
	if $verbose;
}

system("openssl enc -d -aes-128-cbc -in $currkeyring_enc -out $currkeyring -pass pass:$keyroot") == 0
    or system_errexit("Unable to decode $currkeyring_enc");

if ($currver > 1 or $precommit) {
    system("openssl enc -d -aes-128-cbc -in $predkeyring_enc -out $predkeyring -pass pass:$keyroot") == 0
	or system_errexit("Unable to decode $predkeyring_enc");
}

#
# Check that current keyring size is consistent with parcel.cfg
#
open(TAGS, "-|", "$Server::SRVBIN/query", $currkeyring, "SELECT tag FROM keys ORDER BY chunk ASC")
    or system_errexit("Unable to read tags from $currkeyring");

@tags = ();
while ($tag = <TAGS>) {
    chomp($tag);
    push @tags, $tag;
}

close TAGS;
$? == 0
    or unix_errexit("$currkeyring query failed");

# There better be a keyring entry for each block
$totalchunks = get_value($parcelcfg, "NUMCHUNKS");
if (@tags != $totalchunks) {
    err("Version $currver keyring has " . scalar(@tags) . " chunks while the disk has $totalchunks.");
    $errors++;
}

$chunksperdir = get_value($parcelcfg, "CHUNKSPERDIR");
$numdirs = ceil($totalchunks / $chunksperdir);

#
# Check the current and predecessor keyrings for relative consistency
#
if (-e $preddir) {
    print "Comparing keyrings $currver and $predver for differences...\n"
	if $verbose;
    open(DIFFS, "-|", "$Server::SRVBIN/query", $currkeyring, "-a", "pred:$predkeyring", "SELECT main.keys.chunk FROM main.keys JOIN pred.keys ON main.keys.chunk == pred.keys.chunk WHERE main.keys.tag != pred.keys.tag")
	or system_errexit("Unable to compare $currkeyring and $predkeyring");

    while ($chunk = <DIFFS>) {
	chomp($chunk);
	$keydiff{$chunk} = 1;
    }

    close DIFFS;
    $? == 0
	or unix_errexit("Keyring comparison failed");
    
    #
    # Get rid of the unencrypted key rings, which are no longer needed
    #
    unlink($currkeyring, $predkeyring);

    # 
    # Check that the blocks in the predecessor correspond to the differing
    # entries in the keyring
    #
    print "Checking version $predver against its keyring...\n"
    	if $verbose;
    for ($i = 0; $i < $totalchunks; $i++) {
	$dirnum = floor($i / $chunksperdir);
	$filenum = $i % $chunksperdir;
	$chunk = sprintf("%04d/%04d", $dirnum, $filenum);
	$chunkpath = "$preddir/hdk/$chunk";
	if (-e $chunkpath && !defined($keydiff{$i})) {
	    print "Error: [$i] file $chunk exists, but entries are the same.\n";
	    $errors++;
	} elsif (! -e $chunkpath && defined($keydiff{$i})) {
	    print "Error: [$i] file $chunk does not exist, but entries differ.\n";
	    $errors++;
	}
    }
}

#
# If the current directory is also the most recent directory, then do a 
# simple consistency check to ensure that it is fully populated.
#
if ($currver == $lastver) {
    print "Scanning $numdirs version $currver dirs ($chunksperdir chunks/dir, $totalchunks chunks) for completeness...\n"
	if $verbose;
    
    # Iterate through the complete list of possible subdirectories
    for ($i = 0; $i < $numdirs; $i++) {
	$dirname = sprintf("%04d", $i);
	$dirpath = "$currdir/hdk/$dirname"; 

	# If the directory exists, then check its contents
	if (opendir(DIR, $dirpath)) {
	    @files = grep(!/^[\._]/, readdir(DIR)); # filter out "." and ".."
	    closedir(DIR);

	    # Count the number of files in the subdirectory
	    $numchunks = scalar(@files);
	    if ($numchunks != $chunksperdir) {
		print "Error: Directory $dirname has $numchunks blocks. Expected $chunksperdir.\n";
		$errors++;
	    }
	}
    }
}    

#
# If the user has asked for a content consistency check, then verify that
# each encrypted disk chunk has a valid key
# 
if ($contentcheck) {
    print "Performing content consistency check...\n"
	if $verbose;

    # Iterate through the complete list of possible subdirectories
    for ($i = 0; $i < $numdirs; $i++) {
	$dirname = sprintf("%04d", $i);
	$dirpath = "$currdir/hdk/$dirname"; 

	# If the directory exists, then check its chunks
	if (opendir(DIR, $dirpath)) {
	    print "$dirname "
		if $verbose;

	    @files = grep(!/^[\._]/, readdir(DIR)); # filter out "." and ".."
	    closedir(DIR);

	    # Check each chunk in the directory
	    foreach $chunk (sort @files) {
		$index = $i*$chunksperdir + $chunk;
		if ($index <= scalar(@tags)) {
		    # Check that the keyring entry tag is correct
		    $tag = `openssl sha1 < $dirpath/$chunk`;
		    chomp($tag);
		    if (lc($tag) ne lc($tags[$index])) {
			if ($verbose) {
			    print "Error: [$index] Computed tag (", uc($tag), ") <> keyring tag (", uc($tags[$index]), ").\n";
			}
			else {
			    print("Error: [$index] Computed tag <> keyring tag.\n");
			}
			$errors++;
		    }
		}
	    }
	}
    }
    print "\n"
	if $verbose;
}

#
# Print a final status message
#
if ($errors == 0) {
    print "Success: Parcel appears to be consistent.\n"
	if $verbose;
    exit 0;
} 
else {
    print "Error: Parcel appears to be inconsistent.\n";
    exit 1;
}

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
        print "Error: $msg\n\n";
    }

    print "Usage: $progname [-hcV] -p <parcel path> -k <key> [-v <version>]\n";
    print "Options:\n";
    print "  -c           Perform content consistency check\n";
    print "  -h           Print this message\n";
    print "  -k <key>     Keyroot for this parcel\n";
    print "  -u <user>    User for this parcel (default is $ENV{'USER'})\n";
    print "  -p <parcel>  Parcel name\n";    
    print "  -s           Run pre-commit check\n";
    print "  -v <ver>     Parcel version to check (default is last)\n";
    print "  -V           Be verbose\n";
    print "\n";
    exit 0;
}
