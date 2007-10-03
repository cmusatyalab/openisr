###################################################################
# srv_lock.pm - Acquires, releases, or checks a parcel lock
###################################################################

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

###################
# Standard prologue
###################
use strict;
use Sys::Hostname;

####################
# Begin main routine
####################

# 
# Variables
#
my $parceldir;
my $parcelpath;
my $parcelname;
my $serverhostname;
my $userid;
my $clienthostname;
my $verbose;
my $lockfile;
my $logfile;
my $server_nonce;
my $noncefile;
my $datestring;
my $acquire;
my $release;
my $hard_release;
my $check;
my $line;
my $action;
my $unused;
my %config = get_config();

#
# Parse the command line args
#
no strict 'vars';
getopts('hVp:n:ar:Rc');

if ($opt_h) {
    usage();
}
if (!$opt_p) {
    usage("Missing parcel path (-p)");
}
if (!$opt_n) {
    usage("Missing client host name (-n)");
}
if (!$opt_a and !$opt_r and !$opt_R and !$opt_c) {
    usage("Must specify either -a, -r <nonce>, -R, or -c.");
}
$parcelpath = $opt_p;
$clienthostname = $opt_n;
$acquire = $opt_a;
$release = $opt_r;
$hard_release = $opt_R;
$check = $opt_c;
$verbose = $opt_V;
use strict 'vars';

#
# Make sure the parcel directory exists
#
$parceldir = "$config{content_root}/$parcelpath";
(-e $parceldir)
    or errexit("Parcel $parceldir does not exist");

#
# Set some variables that we'll need later
#
$lockfile = "$parceldir/LOCK";
$logfile = "$parceldir/lockholder.log";
$noncefile = "$parceldir/nonce";
$serverhostname = hostname();
($userid, $parcelname) = split("/", $parcelpath);

#
# If the logfile doesn't exist then create an empty one
#
if (!-e $logfile) {
    open(LOGFILE, ">$logfile")
	or errexit("Unable to open log file $logfile.");
    close(LOGFILE) 
	or errexit("Unable to close log file $logfile.");
}
    

################
# Acquire a lock
################
if ($acquire) {

    # Try to acquire the lock
    if (system("lockfile -r 0 $lockfile > /dev/null 2>&1") != 0) {

	# If we can't acquire the lock, try to print an informative
	# message that explains exactly why the request failed.
	$line = get_last_acquired_entry($logfile);
	($serverhostname, $datestring, $action, $userid, $parcelname, $clienthostname) = split('\|', $line); # NOTE: single quotes are important here
	if (-e $lockfile and $action eq "acquired") {
	    errexit("Unable to acquire lock for $parcelname because lock is currently held by $userid on $clienthostname since $datestring.");
	}
	else {
	    errexit("Unable to lock $parcelpath (reason unknown).");
	}
    }

    # Create a nonce [1..MAXNONCE] that can be used to validate releases
    srand();  # Generate a different seed each time
    $server_nonce = int(rand(Server::MAXNONCE)) + 1;

    # Save the nonce
    open(NONCEFILE, ">$noncefile")
	or errexit("Error: Unable to open $noncefile");
    print NONCEFILE "$server_nonce\n";
    close(NONCEFILE)
	or errexit("Error: Unable to close $noncefile");

    # Log the successful result
    open(LOGFILE, ">>$logfile")
	or errexit("Error: Unable to open $logfile");
    $datestring = localtime();
    print LOGFILE "$serverhostname|$datestring|acquired|$userid|$parcelname|$clienthostname\n";
    close(LOGFILE)
	or errexit("Error: Unable to close $logfile");

    # Return the nonce to the caller via stdout
    print "$server_nonce\n";
    exit 0;
}

################
# Release a lock
################
if ($release or $hard_release) {

    # Compare nonce stored on server with the one passed on command line
    # Don't do any checking if we are asked to do a hard release 
    if ($release) {
	open(NONCEFILE, $noncefile)
	    or errexit("Unable to open nonce file $noncefile");
	$server_nonce = <NONCEFILE>;
	chomp($server_nonce);
	close(NONCEFILE)
	    or errexit("Unable to close nonce file $noncefile");
	if ($release ne $server_nonce) {
	    errexit("Unable to release lock because the nonce passed on the command line does not match the nonce stored on the server.");
	}
    }
    unlink($noncefile);

    # Release the lock. Notice that this will succeed even if no one
    # currently holds the lock. This is a policy decision that
    # simplifies termination cleanup in other scripts.
    if (-e $lockfile) {
	unlink($lockfile)
	    or errexit("couldn't remove lockfile $lockfile: $!\n");
    }

    # Log the successful result
    open(LOGFILE, ">>$logfile")
	or errexit("Error: Unable to open $logfile");
    $datestring = localtime();
    print LOGFILE "$serverhostname|$datestring|released|$userid|$parcelname|$clienthostname\n";
    close(LOGFILE)
	or errexit("Error: Unable to close $logfile");

    # Done
    exit 0;
}

##############
# Check a lock
##############

# Returns exit code that indicates the current lock status.
# Also, return most recent acquire or release log entry via stdout
# if running in verbose mode.
#
# Note: To be consistent with the lockfile command, we return 0 if lock
# exists (success), 1 if lock does not exist (failure). 
#
$line = get_last_entry($logfile);
if ($check) {    
    if (-e $lockfile) {
	print("$line\n")
	    if $verbose;
	exit 0;
    }
    else {
	print("$line\n")
	    if $verbose;
	exit 1;
    }
}

# Control should never reach here.
exit 1;

##################
# End main routine
##################

#
# get_last_acquired_entry - Return the log entry from the last time
# the lock was acquired.
#
sub get_last_acquired_entry {
    my $logfile = shift;

    my $line;
    my $last_acquire_line = "";
    my $unused;
    my $action;

    open(INFILE, $logfile) 
	or errexit("Unable to open $logfile for reading.");
    while ($line = <INFILE>) {
	chomp($line);
	($unused, $unused, $action, $unused, $unused, $unused, $unused) 
	    = split('\|', $line); # NOTE: the single quotes are important here
	if ($action eq "acquired") {
	    $last_acquire_line = $line;
	}
    }
    close(INFILE)
	or errexit("Unable to close $logfile.");
    return $last_acquire_line;
}    

#
# get_last_entry - Return the log entry from the last time
# the lock was acquired or released. The reason we don't simply
# return the last line in the file is that we decide at some
# point to log other lock functions besides acquire and release,
# such as checking the lock, or failing to acquire or release.
#
sub get_last_entry {
    my $logfile = shift;

    my $line;
    my $last_line = "";
    my $unused;
    my $action;

    open(INFILE, $logfile) 
	or errexit("Unable to open $logfile for reading.");
    while ($line = <INFILE>) {
	chomp($line);
	($unused, $unused, $action, $unused, $unused, $unused, $unused) 
	    = split('\|', $line); # NOTE: the single quotes are important here
	if (($action eq "acquired") or ($action eq "released")) {
	    $last_line = $line;
	}
    }
    close(INFILE)
	or errexit("Unable to close $logfile.");
    return $last_line;
}    


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

    print "Usage: $progname [-hV] -p <parcel path> -n <hostname> -a|-r <nonce>|-R|-c\n";
    print "Options:\n";
    print "  -h    Print this message\n";
    print "  -V    Be verbose\n";
    print "  -p    Relative parcel path (userid/parcelname)\n";    
    print "  -n    Client host name\n";    
    print "Specify exactly one of the following commands:\n";
    print "  -a          Acquire lock and return nonce on stdout\n";
    print "  -r <nonce>  Release lock after checking <nonce>\n";
    print "  -R          Release lock without checking nonce\n";
    print "  -c          Check lock\n";
    print "\n";
    exit 0;
}


