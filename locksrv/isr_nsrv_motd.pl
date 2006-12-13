#!/usr/bin/perl

###################################################################
# isr_nsrv_motd.pl - Return the message of the day on stdout
#
# $Id$
###################################################################

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

###################
# Standard prologue
###################
use strict;
use Getopt::Std;
use File::Basename;
use Sys::Hostname;
use lib "/usr/local/isr/bin";
use Server;
$| = 1; # Autoflush output on every print statement

####################
# Begin main routine
####################
my $parcelpath;
my $verbose;
my $parceldir;
my $parcelname;
my $username;
my $homedir;
my $motdfile;

#
# Parse the command line args
#
no strict 'vars';
getopts('hVu:p:');

if ($opt_h) {
    usage();
}

if (!$opt_p) {
    usage("Missing parcel name (-p)");
}
if (!$opt_u) {
    usage("Missing user name (-u)");
}
$parcelname = $opt_p;
$username = $opt_u;
$verbose = $opt_V;
use strict 'vars';

#
# Set some variables that we'll need later
#
$homedir = $ENV{HOME};
if ($username ne basename($homedir)) {
    errexit("The user name on the command line ($username) is inconsistent with the home directory ($homedir).");
}
$motdfile = "/usr/local/isr/motd.txt";

#
# Return the config file to the caller via stdout
#
open(INFILE, $motdfile) 
    or exit 0;
print "\nServer message:\n";
while (<INFILE>) {
    print $_;
}
close (INFILE) 
    or unix_errexit("Unable to close $motdfile.");
print "\n";

exit 0;

##################
# End main routine
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

    print "Usage: $progname [-hV] -p <parcel> -u <user>\n";
    print "Options:\n";
    print "  -h    Print this message\n";
    print "  -p    Parcel name\n";    
    print "  -u    User name\n";    
    print "  -V    Be verbose\n";
    print "\n";
    exit 0;
}


