#!/usr/bin/perl

#################################################################
# isr_srv_ls.pl - List information about a user's parcels
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
use Term::ANSIColor qw(:constants);
use Socket;
use Sys::Hostname;
use lib "/usr/local/isr/bin";
use Server;
$| = 1; # Autoflush output on every print statement

####################
# begin main routine
####################

# Constant
my $DEF_VERSIONS = 8; # default number of versions to display

# Variables
my $userdir;
my $username;
my $parcel;
my $unlocked;
my $logentry;
my $unused;
my $action;
my $client;
my $date;
my $user;
my $state;
my $longflag;
my $longvers;
my $version;
my $size;
my $line;
my $count;

my $hostname = hostname();

my @versions;

#
# Parse the command line args
#
no strict 'vars';
getopts('hu:p:L:l');

if ($opt_h) {
    usage();
}
if (!$opt_u) {
    usage("Missing user name (-u)");
}
if (!$opt_p) {
    usage("Missing parcel name (-p)");
}
$longflag = $opt_l;     # Use long format using default number of versions
$longvers = $opt_L;  # Use long format using specific number of versions
$username = $opt_u;
$parcel = $opt_p;
$userdir = "$Server::CONTENT_ROOT" . "/$username";
use strict 'vars';

#
# The -l option is subsumed by the -L option, but is kept here
# for backward compatibility. 
#
if ($longflag) {
    $longvers = $DEF_VERSIONS;
}

#
# Use only the hostname portion of this host's FQDN
#
$hostname =~ /^([^\.\s]+)\.?/; # at least 1 alphanum char followed by 0 or 1 dots
$hostname = $1;                # (i wanted '-' to match also so i changed the regexp -mtoups)

#
# Determine the last time this parcel was acquired or released
#
system("rm -f $userdir/entry");
$unlocked = system("$Server::SRVBIN/isr_srv_lock.pl -p $username/$parcel -n foo -Vc > $userdir/entry");
$logentry = `cat $userdir/entry`;
chomp($logentry);
system("rm -f $userdir/entry");

#
# Determine it's present state
# 
if ($unlocked) {
    $state = "released";
}
else {
    $state = "acquired";
}

#
# Parse the log entry
#
($unused, $date, $action, $user, $unused, $client, $unused) = 
    split('\|', $logentry);
if ($logentry and 
    (($unlocked and $action ne "released") or
    (!$unlocked and $action ne "acquired")) ) {
    errexit("System error: inconsistent log entry: unlocked=$unlocked action=$action\nlogentry=$logentry");
}

#
# We don't need the day of the week on the date
#
$date =~ s/^\w+\s//;

#
# Use only the hostname portion of the client's FQDN
#
$client =~ /^([^\.\s]+)\.?/; # at least 1 alphanum char followed by 0 or 1 dots
$client = $1;                # (i wanted '-' to match also so i changed the regexp -mtoups)

#
# Print the main output line
#
if ($logentry and $unlocked) {
    print GREEN;
    printf("%s [%s] %s by %s on %s\n", $parcel, $hostname, 
	   $state, $client, $date);
    print RESET;
}
elsif ($logentry and !$unlocked) {
    print RED;
    printf("%s [%s] %s by %s on %s\n", $parcel, $hostname, 
	   $state, $client, $date);
    print RESET;
}
else {
    print("$parcel [$hostname] has never been checked out.\n");
}

# 
# If the user wants to see the available versions of the parcel, print 
# those too.
#
if ($longvers) {
    opendir(DIR, "$userdir/$parcel")
	or unix_errexit("Could not open directory $userdir/$parcel");
    @versions = reverse sort grep(/^\d+$/, readdir(DIR)); # numbers only

    closedir(DIR);

    $count = 0;
    foreach $version (@versions) {
	$count++;
	if ($count > $longvers) {
	    last;
	}

	if (-e "$userdir/$parcel/$version/keyring.enc") {
	    $date = localtime(stat("$userdir/$parcel/$version/keyring.enc")->mtime);
	}
	else {
	    $date = "[not available]";
	}

	$line = `du -h -s $userdir/$parcel/$version`;
	($size, $unused) = split(" ", $line);
	printf("  %s %6s  %s\n", $version, $size, $date);
    }


    exit 0;
}


############################################
# usage - print help message and terminate #
############################################

sub usage
{
    my $msg = shift;
    my $progname;

    # Strip any path information from the program name
    ($progname = $0) =~ s#.*/##s; 
    
    if ($msg) {
        print "$progname: $msg\n\n";
    }
    
    print "Usage: $progname [-hl] [-L <n>] -u <username> -p <parcel>\n";
    print "Options:\n";
    print "  -h              Print this message\n";
    print "  -l              List available versions\n";  
    print "  -L <n>          List the <n> most recent versions\n";  
    print "  -p <parcel>     Parcel name\n";  
    print "  -u <username>   User name\n";  
    print "\n";
    exit 0;
}
