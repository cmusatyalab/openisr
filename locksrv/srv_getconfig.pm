###################################################################
# srv_getconfig.pm - Fetch the parcel.cfg file from server
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
my $configfile;

#
# Parse the command line args
#
no strict 'vars';
getopts('hVp:');

if ($opt_h) {
    usage();
}

if (!$opt_p) {
    usage("Missing parcel name (-p)");
}
$parcelname = $opt_p;
$verbose = $opt_V;
use strict 'vars';

#
# Set some variables that we'll need later
#
$configfile = get_parcelcfg_path($ENV{"USER"}, $parcelname);

#
# Return the config file to the caller via stdout
#
open(INFILE, $configfile) 
    or unix_errexit("Unable to open $configfile.");
while (<INFILE>) {
    print $_;
}
close (INFILE) 
    or unix_errexit("Unable to close $configfile.");

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

    print "Usage: $progname [-hV] -p <parcel>\n";
    print "Options:\n";
    print "  -h    Print this message\n";
    print "  -p    Parcel name\n";    
    print "  -V    Be verbose\n";
    print "\n";
    exit 0;
}


