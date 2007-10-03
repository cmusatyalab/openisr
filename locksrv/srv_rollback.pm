#################################################################
# srv_rollback.pm - Revert back to a previous version
#################################################################

#
#                       Internet Suspend/Resume
#           A system for capture and transport of PC state
#
#              Copyright (c) 2002-2004, Intel Corporation
#            Copyright (c) 2004, Carnegie Mellon University
#
# This software is distributed under the terms of the Eclipse Public
# License, Version 1.0 which can be found in the file named LICENSE.Eclipse.
# ANY USE, REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES
# RECIPIENT'S ACCEPTANCE OF THIS AGREEMENT
#

##########
# Prologue
##########
use strict;
use File::stat;
use File::Copy;
use Socket;
use Sys::Hostname;
use sigtrap qw(die normal-signals);

####################
# begin main routine
####################

#
# Variables
#
my $username;
my $parcelpath;
my $hostname;
my $verbose;
my $parceldir;
my $targetver;
my $targetdir;
my $lastver;
my $lastdir;
my $cachedir;
my $parcel;
my $chunksperdir;
my $targetkeyring;
my $lastkeyring;
my $keyroot;
my $parcelcfg;
my $nonce;
my $lock;

# Various temporary variables
my $version;
my $this_hdkdir;
my $chunk;
my $chunkdir;
my $chunkcount;
my $i;
my $reason;
my $file;
my $rh;
my $fd;
my $umask;

# Arrays and list
my @filelist = ();
my @chunkdirlist = ();
my @chunklist = ();
my %tagdiffs;

#
# Parse the command line args
#
no strict 'vars';
getopts('hlu:p:v:V');

if ($opt_h) {
    usage();
}

$lock = $opt_l;
$username = $opt_u;
$parcel = $opt_p;
$targetver = $opt_v;

if (!$username) {
    $username = $ENV{"USER"};
}
if (!$parcel) {
    usage("Missing parcel name (-p)");
}
if (!$targetver or $targetver < 1) {
    usage("Missing or incorrect target version number (-v)");
}
$parcelpath = "$username/$parcel";
$parceldir = "$Server::CONTENT_ROOT/$parcelpath";
$verbose = $opt_V;
use strict 'vars';

# Assign a few variables that we will need later
$hostname = hostname();

#
# Make sure the parcel directory exists
#
(-e $parceldir)
    or errexit("$parceldir does not exist.");

#
# Acquire the lock (if called with -l)
# 
if ($lock) {
    $nonce = `isr_runserv lock -p $parcelpath -n $hostname -a`;
    if ($? != 0) {
	undef $nonce;
	errexit("Unable to acquire lock.");
    }
    chomp($nonce);
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
# No need to do anything if target is also last
#
if ($targetver == $lastver) {
    exit 0;
}

#
# Read config variables from parcel.cfg
#
$parcelcfg = get_parcelcfg_path($username, $parcel);
$chunksperdir = get_value($parcelcfg, "CHUNKSPERDIR");
$keyroot = get_value($parcelcfg, "KEYROOT");

#
# Load the keyring content tags from the target version and the last version
#
print "Decrypting and comparing target and last keyrings.\n"
    if $verbose;

$targetkeyring = "/tmp/keyring-target.$$";
$lastkeyring = "/tmp/keyring-last.$$";

# Decrypt the keyrings
unlink($targetkeyring, $lastkeyring);
$umask = umask(0077);
($rh, $fd) = keyroot_pipe($keyroot);
system("openssl enc -d -aes-128-cbc -in $targetdir/keyring.enc -out $targetkeyring -pass fd:$fd -salt") == 0
    or system_errexit("Unable to decode $targetdir/keyring.enc");
($rh, $fd) = keyroot_pipe($keyroot);
system("openssl enc -d -aes-128-cbc -in $lastdir/keyring.enc -out $lastkeyring -pass fd:$fd -salt") == 0
    or system_errexit("Unable to decode $lastdir/keyring.enc");
umask($umask);

# Compare the keyrings
open(IN, "-|", LIBDIR . "/query", "-a", "last:$lastkeyring", $targetkeyring, "SELECT main.keys.chunk FROM main.keys JOIN last.keys ON main.keys.chunk == last.keys.chunk WHERE main.keys.tag != last.keys.tag")
    or unix_errexit("Unable to query keyrings");
while ($chunk = <IN>) {
    chomp($chunk);
    $tagdiffs{$chunk} = 1;
}
close(IN);
$? == 0
    or unix_errexit("Keyring query failed");

# Remove the decrypted keyrings
unlink($targetkeyring, $lastkeyring);

#
# Create the cache directory where we'll be writing our updates
#
$cachedir = "$parceldir/cache";
system("rm -rf $cachedir") == 0
    or system_errexit("Unable to remove $cachedir");
mkdir($cachedir)
    or unix_errexit("Unable to create $cachedir");
mkdir("$cachedir/hdk")
    or unix_errexit("Unable to create $cachedir/hdk");

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
		mkdir("$cachedir/hdk/$chunkdir")
		    or unix_errexit("Unable to create $cachedir/hdk/$chunkdir");
	    }

	    # This is tricky: Copy chunk c to the cache only if (1) a
	    # file called c does not exist in the cache AND (2) the
	    # contents of c have changed between target and
	    # last. Condition (1) is necessary for correctness, while
	    # condition (2) is necessary for space efficiency.
	    $i = get_offset($chunkdir, $chunk, $chunksperdir);
	    if (!-e "$cachedir/hdk/$chunkdir/$chunk" and defined($tagdiffs{$i})) {
		$chunkcount++;
		print "Copying $chunkdir/$chunk to cache\n"
		    if $verbose;
		copy("$this_hdkdir/$chunkdir/$chunk", "$cachedir/hdk/$chunkdir/$chunk")
		    or unix_errexit("Unable to copy $this_hdkdir/$chunkdir/$chunk to cache");
	    } elsif ($verbose) {
		$reason = "";
		if (-e "$cachedir/hdk/$chunkdir/$chunk") {
		    $reason = "exists";
		}
		if (!defined($tagdiffs{$i})) {
		    $reason = $reason . "nochange";
		}
		print "Chunk $chunkdir/$chunk not copied to cache [$reason]\n";
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
foreach $file ("cfg.tgz.enc", "keyring.enc") {
    copy("$targetdir/$file", "$cachedir/$file")
	or unix_errexit("Unable to copy $file from $targetdir to $cachedir.");
}

#
# Commit the updates in the cache
# 
print "Committing updates...\n"
    if $verbose;
system("isr_runserv commit -u $username -p $parcel") == 0
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

    print "Usage: $progname [-hlV] [-u username] -p <parcel> -v <ver>\n";
    print "Options:\n";
    print "  -h        Print this message\n";
    print "  -l        Acquire and release the parcel lock\n";
    print "  -V        Be verbose\n";
    print "  -u <user> Username for this parcel (default is $ENV{'USER'})\n";
    print "  -p <name> Parcel name\n";
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
    if ($nonce) {
	if (system("isr_runserv lock -p $parcelpath -n $hostname -r $nonce") == 0) {
	    print("Released the lock.\n")
		if $verbose;
	} else {
	    print ("Unable to release lock.\n");
	}
    }
}
