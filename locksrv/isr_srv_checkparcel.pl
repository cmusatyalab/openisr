#!/usr/bin/perl

###################################################################
# isr_srv_checkparcel.pl - check a parcel for consistency
###################################################################

#
#                  Internet Suspend/Resume (Release 0.5)
#           A system for capture and transport of PC state
#
#          Copyright (c) 2004-2005, Carnegie Mellon University
#              Copyright (c) 2002-2004, Intel Corporation
#                         All Rights Reserved
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

###################
# standard prologue
###################
use strict;
use Getopt::Std;
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

# Important variables
my $parceldir;
my $lastver;
my $currver;
my $currdir;
my $currkeyring;
my $currkeyring_enc;
my $currindexlev1;
my $predver;
my $preddir;
my $predkeyring;
my $predkeyring_enc;
my $keyroot;
my $num_keyring_entries;
my $errors;

# Various temporary variables
my $numdiffs;
my $line;
my $line1;
my $line2;
my $numdirs;
my $numpredchunks;
my $totalchunks;
my $chunksperdir;
my $numchunks;
my $index_numchunks;
my $tag;
my $key;
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
my @keys;    # array of keyring keys
my @keydiff; # keydiff[i] true iff ith keyring entries differ
#
# Parse the command line args
#
no strict 'vars';
getopts('Vhcsp:v:k:');

if ($opt_h) {
    usage();
}
if (!$opt_p) {
    usage("Missing parcel path (-p)");
}
if (!$opt_k) {
    usage("Missing keyroot (-k)");
}
$parceldir = "$Server::CONTENT_ROOT" . "$opt_p";
$currver = $opt_v;
$verbose = $opt_V;
$keyroot = $opt_k;
$contentcheck = $opt_c;

# special case -- checking the difference between "last" and "cache"
# before a commit -- mtoups 2005/08/19

# s is for sanity (since the other good letters were taken)
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

# this is the special cast pre-commit check
# mtoups 

if ($precommit) {
    $currdir = "$parceldir/" . sprintf("%06d", $currver);
#    $currdir = "$parceldir/last";
    $currkeyring_enc = "$currdir/keyring.enc";
    $currkeyring = "/tmp/keyring-curr.$$";
    $currindexlev1 = "$currdir/hdk/index.lev1";

#    $predver = "$parceldir/cache";
    $preddir = "$parceldir/cache";
    $predkeyring_enc = "$preddir/keyring.enc";
    $predkeyring = "/tmp/keyring-pred.$$";

}
else {

$currdir = "$parceldir/" . sprintf("%06d", $currver);
$currkeyring_enc = "$currdir/keyring.enc";
$currkeyring = "/tmp/keyring-curr.$$";
$currindexlev1 = "$currdir/hdk/index.lev1";

# Variables for the predecessor version (if any)
$predver = $currver - 1; 
$preddir = "$parceldir/" . sprintf("%06d", $predver);
$predkeyring_enc = "$preddir/keyring.enc";
$predkeyring = "/tmp/keyring-pred.$$";

}

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

system("openssl enc -d -bf -in $currkeyring_enc -out $currkeyring -pass pass:$keyroot -nosalt") == 0
    or system_errexit("Unable to decode $currkeyring_enc");

if ($currver > 1 or $precommit) {
    system("openssl enc -d -bf -in $predkeyring_enc -out $predkeyring -pass pass:$keyroot -nosalt") == 0
	or system_errexit("Unable to decode $predkeyring_enc");
}

#
# Check that current keyring size is consistent with index.lev1
#
open(INFILE, $currkeyring)
    or unix_errexit("Unable to open $currkeyring");

$num_keyring_entries = 0;
@tags = ();
@keys = ();
while ($line = <INFILE>) {
    chomp($line);
    ($tag, $key) = split(" ", $line);
    $tags[$num_keyring_entries] = $tag;
    $keys[$num_keyring_entries] = $key;
    $num_keyring_entries++;
}

close INFILE
    or unix_errexit("Unable to close $currkeyring");

# There better be a keyring entry for each block
$numchunks = get_value($currindexlev1, "NUMCHUNKS");
if ($num_keyring_entries != $numchunks) {
    err("Version $currver keyring has $num_keyring_entries while the disk has $numchunks chunks.");
    $errors++;
}

# The number of chunks should equal numdirs*chunks per dir
$numdirs = get_value("$currindexlev1", "NUMDIRS");
$chunksperdir = get_value("$currindexlev1", "CHUNKSPERDIR");
if ($numchunks != $numdirs*$chunksperdir) {
    err("Version $currver index file reports $numchunks chunks, which is not equal to $numdirs dirs * $chunksperdir chunks/dir.");
    $errors++;
}

#
# Check the current and predecessor keyrings for relative consistency
#
if (-e $preddir) {
    #
    # Compare the current and pred keyrings line-by-line for differences
    #
    $numdiffs = 0;
    print "Comparing keyrings $currver and $predver for differences...\n"
	if $verbose;
    open(INFILE1, $currkeyring)
	or unix_errexit("Unable to open $currkeyring");
    open(INFILE2, $predkeyring)
	or unix_errexit("Unable to open $predkeyring");

    $i = 0;
    while ($line1 = <INFILE1>) {
	$line2 = <INFILE2>;
	$keydiff[$i] = 0;
	if ($line1 ne $line2) {
	    $keydiff[$i] = 1;
	    $numdiffs++;
	}
	$i++;
    }

    close INFILE1
	or unix_errexit("Unable to close $currkeyring");
    close INFILE2
	or unix_errexit("Unable to close $predkeyring");
    
    #
    # Get rid of the unencrypted key rings, which are no longer needed
    #
    unlink($currkeyring, $predkeyring);

    # 
    # Check that the number of blocks in the predecessor is the same
    # as the number of different entries in the keyring
    #
    $numdirs = get_value("$currindexlev1", "NUMDIRS");
    $numpredchunks = 0;
    for ($i = 0; $i < $numdirs; $i++) {
	$dirname = sprintf("%04d", $i);
	$dirpath = "$preddir/hdk/$dirname"; 

	if (opendir(DIR, $dirpath)) {
	    @files = grep(!/^[\._]/, readdir(DIR)); # filter out "." and ".."
	    closedir(DIR);
	    $numchunks = scalar(@files);
	    #print "$dirname: $numchunks\n";
	    $numpredchunks += $numchunks;
	}
    }

    #
    # Report the results
    #
    if ($numpredchunks == $numdiffs) {
	print "Success: Found $numpredchunks chunks in version $predver and $numdiffs keyring differences.\n"
	    if $verbose;
    }

    # Something is wrong. Identify the specific inconsistent blocks
    else {
	print "Error: Found $numpredchunks chunks in version $predver and $numdiffs keyring differences.\n";
	$numdirs = get_value("$currindexlev1", "NUMDIRS");
	$chunksperdir = get_value("$currindexlev1", "CHUNKSPERDIR");
	$totalchunks = $numdirs * $chunksperdir;
	for ($i = 0; $i < $totalchunks; $i++) {
	    $dirnum = int($i / $chunksperdir);
	    $filenum = $i % $chunksperdir;
	    $chunk = sprintf("%04d", $dirnum) . "/" . sprintf("%04d", $filenum);
	    $chunkpath = "$preddir/hdk/$chunk";
	    if (-e $chunkpath) {
		if ($keydiff[$i] == 0) {
		    print("Error: [$i] file $chunk exists, but entries are the same.\n");
		}
	    }
	    else {
		if ($keydiff[$i] == 1) {
		    print("Error: [$i] file $chunk does not exist, but entries differ.\n");
		}
	    }
	}
	$errors++;
    }
} else {
    #
    # Get rid of the unencrypted keyring
    #
    unlink($currkeyring);
}

#
# If the current directory is also the most recent directory, then do a 
# simple consistency check to ensure that it is fully populated.
#
if ($currver == $lastver) {
    $numdirs = get_value("$currindexlev1", "NUMDIRS");
    $chunksperdir = get_value("$currindexlev1", "CHUNKSPERDIR");
    $totalchunks = $numdirs * $chunksperdir;
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

    $numdirs = get_value("$currindexlev1", "NUMDIRS");
    $chunksperdir = get_value("$currindexlev1", "CHUNKSPERDIR");
    $totalchunks = $numdirs * $chunksperdir;
    
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
	    foreach $chunk ( sort @files) {
		$index = $i*$chunksperdir + $chunk;
		if ($index <= scalar(@keys)) {

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
    print "  -c         Perform content consistency check\n";
    print "  -h         Print this message\n";
    print "  -k <key>   Keyroot for this parcel\n";
    print "  -p <path>  Relative parcel path (userid/parcel)\n";    
    print "  -v <ver>   Parcel version to check (default is last)\n";
    print "  -V         Be verbose\n";
    print "\n";
    exit 0;
}
