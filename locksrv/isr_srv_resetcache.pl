#!/usr/bin/perl

######################################################################
# isr_srv_resetcache.pl - Clears the serverside cache
######################################################################

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
# Prologue
###################
use strict;
use Getopt::Std;
use lib "/usr/local/isr/bin";
use Server;
$| = 1; # Autoflush output on every print statement

####################
# Begin main routine
####################

# 
# Local variables
#
my $username;
my $parcelname;
my $parceldir;
my $lastdir;
my $lastver;
my $numdirs;
my $rsync;
my $cachedir;
my $i;

my @files;

#
# Parse the command line args
#
no strict 'vars';
getopts('rhu:p:');

if ($opt_h) {
    usage();
}
if (!$opt_p) {
    usage("Missing parcel path (-p)");
}
$username = $opt_u;
$username = $ENV{"USER"} if !$username;
$parcelname = $opt_p;
$parceldir = "$Server::CONTENT_ROOT$username/$parcelname";
$rsync = $opt_r;
use strict 'vars';

#
# Make sure the parcel directory exists
#
(-e $parceldir)
    or errexit("$parceldir does not exist");

#
# Initialize some variables that we'll need later
#
opendir(DIR, $parceldir)
    or errexit("Could not open directory $parceldir");
@files = reverse sort grep(/^\d+$/, readdir(DIR)); 
closedir(DIR);

$lastver = int(@files[0]);
$lastdir = "$parceldir/" . sprintf("%06d", $lastver);
$numdirs = get_numdirs(get_parcelcfg_path($username, $parcelname));
$cachedir = "$parceldir/cache";

# 
# Either reset the server-side cache for a client using rsync...
#
if ($rsync) {
    if (!-e "$cachedir/hdk") {
	system("mkdir --parents $cachedir/hdk") == 0
	    or system_errexit("Unable to make $cachedir on server");
    }
}

#
# ... or reset the server-side cache for a client using scp
#
else {
    system("rm -rf $cachedir") == 0
	or system_errexit("Unable to remove $cachedir on server");
    system("mkdir $cachedir") == 0
	or system_errexit("Unable to make $cachedir on server");
    system("mkdir $cachedir/hdk") == 0
	or system_errexit("Unable to make $cachedir/hdk on server");

    for ($i = 0; $i < $numdirs; $i++) {
	my $dirname = sprintf("%04d", $i);
	system("mkdir $cachedir/hdk/$dirname") == 0
	    or system_errexit("Unable to make cachedir/hdk/$dirname on server");
    }
}

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
        print "$progname: $msg\n\n";
    }
    
    print "Usage: $progname [-hr] [-u <username>] -p <parcel>\n";
    print "Options:\n";
    print "  -h    Print this message\n";
    print "  -u    User for this parcel (default is $ENV{'USER'})\n";
    print "  -p    Parcel name\n";    
    print "  -r    Reset cache for rsync-based client (default is scp)\n";
    print "\n";
    exit 0;
}
